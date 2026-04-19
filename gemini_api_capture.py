#!/usr/bin/env python3
"""
gemini_api_capture.py  ── v1 全量 API 版
─────────────────────────────────────────
突破 Gemini 网页 DOM 10 条截断限制，直接通过 batchexecute API 抓取完整对话。

流程：
1. CDP 连接 Chrome（用已登录 profile，无需注入 Cookie）
2. 导航 Gemini，从 WIZ_global_data 提取 at/f.sid/bl 参数
3. 提取侧边栏全部对话 ID
4. 直接 HTTP POST batchexecute?rpcids=hNvQHb（pageSize=9999）
5. 解析 Google RPC 格式，提取完整消息
6. 生成本地静态网站

依赖：
  pip install requests websockets pycryptodome
"""

import asyncio
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# ── 代理绕过 ─────────────────────────────────────────────────────────────────
os.environ["no_proxy"]  = "localhost,127.0.0.1"
os.environ["NO_PROXY"]  = "localhost,127.0.0.1"

import requests
import websockets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ─── 配置 ─────────────────────────────────────────────────────────────────────
CHROME_PORT   = 9222
COOKIES_DB    = Path.home() / "Library/Application Support/Google/Chrome/Default/Cookies"
SITE_DIR      = Path.home() / "Documents" / "gemini_local_site"
DEBUG_DIR     = Path.home() / "Documents" / "gemini_api_debug"
# 要抓取的对话数：0 = 全部
CONV_LIMIT    = int(sys.argv[1]) if len(sys.argv) > 1 else 0
# ─────────────────────────────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════════════
#  Cookie 解密（用于直接 HTTP 请求）
# ═══════════════════════════════════════════════════════════════════════════════

def get_chrome_aes_key() -> bytes:
    result = subprocess.run(
        ["security", "find-generic-password", "-w",
         "-s", "Chrome Safe Storage", "-a", "Chrome"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Keychain 读取失败: {result.stderr.strip()}")
    password = result.stdout.strip().encode("utf-8")
    import hmac
    return PBKDF2(password, b"saltysalt", dkLen=16, count=1003,
                  prf=lambda p, s: hmac.new(p, s, "sha1").digest())


def decrypt_cookie_value(encrypted: bytes, key: bytes) -> str:
    if not encrypted:
        return ""
    if encrypted[:3] == b"v10":
        cipher = AES.new(key, AES.MODE_CBC, IV=b" " * 16)
        raw = cipher.decrypt(encrypted[3:])
        return raw[:-raw[-1]].decode("utf-8", errors="replace")
    return encrypted.decode("utf-8", errors="replace")


def build_requests_session() -> requests.Session:
    """创建带 Google cookie 的 requests Session，供直接调用 API 使用"""
    key = get_chrome_aes_key()
    tmp = tempfile.mktemp(suffix=".db")
    shutil.copy2(str(COOKIES_DB), tmp)
    s = requests.Session()
    s.trust_env = False
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        cur.execute(
            "SELECT host_key,name,value,encrypted_value,path "
            "FROM cookies WHERE host_key LIKE '%google%'"
        )
        for host, name, value, enc, path in cur.fetchall():
            val = decrypt_cookie_value(enc, key) if enc else value
            if not val:
                continue
            domain = host.lstrip(".")
            s.cookies.set(name, val, domain=domain, path=path or "/")
        conn.close()
        return s
    finally:
        os.unlink(tmp)


# ═══════════════════════════════════════════════════════════════════════════════
#  CDP（支持异步事件监听）
# ═══════════════════════════════════════════════════════════════════════════════

class CDP:
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self.ws     = None
        self._id    = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._evt_listeners: dict[str, list] = {}  # method → [(one_shot, fut_or_cb)]
        self._recv_task: asyncio.Task | None = None
        self._raw_events: list[dict] = []   # 存储所有事件，方便调试

    async def connect(self):
        self.ws = await websockets.connect(
            self.ws_url, max_size=200 * 1024 * 1024,
            open_timeout=15, close_timeout=5,
        )
        self._recv_task = asyncio.create_task(self._recv_loop())
        return self

    async def _recv_loop(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                elif "method" in msg:
                    method = msg["method"]
                    self._raw_events.append(msg)
                    handlers = self._evt_listeners.get(method, [])
                    dead = []
                    for h in handlers:
                        one_shot, cb_or_fut = h
                        if callable(cb_or_fut):
                            cb_or_fut(msg["params"])
                        elif not cb_or_fut.done():
                            cb_or_fut.set_result(msg["params"])
                        if one_shot:
                            dead.append(h)
                    for h in dead:
                        handlers.remove(h)
        except Exception:
            pass

    async def send(self, method: str, params: dict = None, timeout: float = 90):
        cid = self._id; self._id += 1
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[cid] = fut
        await self.ws.send(json.dumps({"id": cid, "method": method, "params": params or {}}))
        msg = await asyncio.wait_for(fut, timeout)
        if "error" in msg:
            raise RuntimeError(f"CDP [{method}]: {msg['error']}")
        return msg.get("result", {})

    def on(self, method: str, callback):
        self._evt_listeners.setdefault(method, []).append((False, callback))

    async def wait_for(self, method: str, timeout: float = 30):
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._evt_listeners.setdefault(method, []).append((True, fut))
        return await asyncio.wait_for(fut, timeout)

    async def js(self, expr: str, timeout_ms: int = 60_000):
        r = await self.send("Runtime.evaluate", {
            "expression": expr, "returnByValue": True,
            "awaitPromise": True, "timeout": timeout_ms,
        })
        exc = r.get("exceptionDetails")
        if exc:
            txt = exc.get("exception", {}).get("description", exc.get("text", str(exc)))
            raise RuntimeError(f"JS exception: {txt}")
        return r.get("result", {}).get("value")

    async def navigate(self, url: str, wait_sec: float = 6):
        await self.send("Page.navigate", {"url": url})
        await asyncio.sleep(wait_sec)

    async def wait_ready(self, extra: float = 0):
        for _ in range(40):
            if await self.js("document.readyState") == "complete":
                break
            await asyncio.sleep(0.5)
        if extra:
            await asyncio.sleep(extra)

    async def close(self):
        if self._recv_task:
            self._recv_task.cancel()
        if self.ws:
            await self.ws.close()


def open_cdp(port: int = CHROME_PORT) -> dict:
    s = requests.Session(); s.trust_env = False
    tabs = s.get(f"http://127.0.0.1:{port}/json", timeout=5).json()
    for t in tabs:
        if t.get("type") == "page":
            return t
    raise RuntimeError("No page tab found")


# ═══════════════════════════════════════════════════════════════════════════════
#  从 Gemini 页面提取会话参数
# ═══════════════════════════════════════════════════════════════════════════════

_WIZ_JS = r"""
(function(){
    // 方法1: WIZ_global_data
    const w = window.WIZ_global_data || {};
    if (w.SNlM0e) return {at: w.SNlM0e, fsid: w['f.sid']||'', bl: w.cfb2h||''};

    // 方法2: 从 HTML 正则匹配
    const html = document.documentElement.innerHTML;
    const m1 = html.match(/"SNlM0e":"([^"]+)"/);
    const m2 = html.match(/"f\.sid":"([^"]+)"/);
    const m3 = html.match(/"cfb2h":"([^"]+)"/);
    if (m1) return {at: m1[1], fsid: m2?m2[1]:'', bl: m3?m3[1]:''};

    // 方法3: 通用 at= token 搜索
    const m4 = html.match(/\\"at\\":\\"([^\\\\]+)\\"/);
    return {at: m4?m4[1]:'', fsid:'', bl:''};
})()
"""

_CONV_LIST_JS = r"""
(function(){
    const links=[], seen=new Set();
    document.querySelectorAll('a[href*="/app/"]').forEach(a=>{
        const m=a.href.match(/\/app\/([a-zA-Z0-9_-]{8,})/);
        if(!m||seen.has(m[1])) return;
        seen.add(m[1]);
        const t=(a.innerText||a.title||a.getAttribute('aria-label')||'')
                  .trim().replace(/^\n+|\n+$/g,'').split('\n')[0].trim();
        links.push({id:m[1], url:'https://gemini.google.com/app/'+m[1], title:t||m[1]});
    });
    return links;
})()
"""

# 滚动侧边栏到底部，触发加载更多对话
_SCROLL_SIDEBAR_JS = r"""
(function(){
    // Gemini 侧边栏可能是 nav 内的 infinite-scroller 或直接是 nav
    const candidates = [
        document.querySelector('nav infinite-scroller'),
        document.querySelector('infinite-scroller'),
        document.querySelector('nav'),
        ...Array.from(document.querySelectorAll('[class*="sidebar"],[class*="nav"],[class*="history"],[class*="conversation"]'))
              .filter(el => el.scrollHeight > el.clientHeight + 50),
    ].filter(Boolean);

    let scrolled = null;
    for (const el of candidates) {
        const before = el.scrollTop;
        el.scrollTop = el.scrollHeight;
        if (el.scrollTop !== before || el.scrollTop > 0) {
            scrolled = {tag: el.tagName, cls: el.className.slice(0,60),
                        scrollTop: el.scrollTop, scrollHeight: el.scrollHeight};
            break;
        }
    }
    // 也滚动 window，以防
    window.scrollTo(0, document.body.scrollHeight);
    return scrolled;
})()
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  batchexecute API 调用
# ═══════════════════════════════════════════════════════════════════════════════

GEMINI_BE_URL = "https://gemini.google.com/_/BardChatUi/data/batchexecute"

# ─── 通过浏览器 fetch 调用 batchexecute（绕过 Python 直连网络限制）─────────────
_CDP_FETCH_JS = r"""
async function cdpFetchBatchexecute(convId, at, bl, fsid, pageSize, contToken) {
    // contToken: null for first page, string for subsequent pages
    const inner = JSON.stringify(["c_" + convId, pageSize, contToken || null, 1, [1], [4], null, 1]);
    const freq  = JSON.stringify([[["hNvQHb", inner, null, "generic"]]]);
    const bodyParams = new URLSearchParams({"f.req": freq, "at": at});

    const urlParams = new URLSearchParams({
        rpcids: "hNvQHb",
        "source-path": "/app/" + convId,
        bl: bl,
        hl: "zh-CN",
        _reqid: String(Math.floor(Math.random() * 900000) + 100000),
        rt: "c",
    });
    if (fsid) urlParams.set("f.sid", fsid);

    const resp = await fetch(
        "/_/BardChatUi/data/batchexecute?" + urlParams.toString(),
        {
            method: "POST",
            headers: {
                "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
                "x-same-domain": "1",
            },
            body: bodyParams.toString(),
            credentials: "include",
        }
    );
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    return await resp.text();
}
"""


async def call_batchexecute_via_cdp(
    cdp: "CDP",
    conv_id: str,
    at: str,
    bl: str = "",
    fsid: str = "",
    page_size: int = 9999,
    cont_token: str | None = None,
) -> str:
    """
    通过 CDP 在浏览器页面上下文中执行 fetch，调用 batchexecute。
    这样可以利用浏览器已配置的代理和已有 Cookie，完全绕过 Python 直连问题。
    必须在已导航到 gemini.google.com 的 CDP 会话中调用。
    cont_token: 分页续传令牌，None 表示第一页，非空字符串表示后续页（更早的消息）。
    """
    bl_safe   = bl.replace('"', '\\"')
    fsid_safe = fsid.replace('"', '\\"')
    if cont_token:
        # JSON-escape the token so it's safe inside JS string literals
        token_js = json.dumps(cont_token)  # produces a properly escaped JSON string
        token_arg = token_js
    else:
        token_arg = "null"
    expr = (
        _CDP_FETCH_JS
        + f'\ncdpFetchBatchexecute("{conv_id}", "{at}", "{bl_safe}", "{fsid_safe}", {page_size}, {token_arg})'
    )
    # fetch 是异步的，awaitPromise=True 等待完成（最多 120 秒）
    result = await cdp.js(expr, timeout_ms=120_000)
    if result is None:
        raise RuntimeError("CDP fetch 返回 None")
    return result


def extract_continuation_token(payload: list) -> str | None:
    """
    从 hNvQHb payload 中提取分页续传令牌（payload[1]）。
    如果返回非空字符串，表示还有更早的消息可以请求。
    """
    if not isinstance(payload, list) or len(payload) < 2:
        return None
    token = payload[1]
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Google batchexecute 响应解析
# ═══════════════════════════════════════════════════════════════════════════════

def strip_be_prefix(text: str) -> str:
    """移除 )]}' 前缀及前置空行"""
    text = text.lstrip()
    if text.startswith(")]}'"):
        text = text[4:]
    return text.lstrip("\n")


def parse_be_chunks(text: str) -> list:
    """
    Google batchexecute 响应可能是多个 JSON 块（chunked），
    每块可能单独是完整 JSON 数组。尝试提取第一个有效 JSON 数组。
    """
    text = strip_be_prefix(text)
    # 尝试直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # chunked: 每块以 \n<size>\n 分隔，提取第一个合法块
    # 有时格式是: SIZE\nDATA\n
    lines = text.split("\n")
    combined = ""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # 跳过纯十六进制大小行
        if re.fullmatch(r"[0-9a-fA-F]+", stripped):
            continue
        combined += stripped
        try:
            obj = json.loads(combined)
            return obj
        except json.JSONDecodeError:
            pass

    # 最后尝试：提取第一个完整 JSON 数组
    depth, start = 0, -1
    for i, c in enumerate(text):
        if c == "[":
            if depth == 0:
                start = i
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    depth, start = 0, -1
    return []


def extract_rpc_payload(chunks: list, rpc_id: str = "hNvQHb") -> list | None:
    """
    从已解析的块数组中找到指定 rpc_id 的 payload（已二次解码 JSON 字符串）。
    实际格式（通过 CDP fetch 观察）:
      [ ["wrb.fr", "hNvQHb", "<json_string>", null, ...], ... ]
    旧格式（备用）:
      [ [["hNvQHb", "<json>", null, "generic"]], ... ]
    """
    if not isinstance(chunks, list):
        return None
    for item in chunks:
        if not isinstance(item, list):
            continue
        # 新格式: ["wrb.fr", rpc_id, "<json>", ...]
        if len(item) >= 3 and item[0] == "wrb.fr" and item[1] == rpc_id and isinstance(item[2], str):
            try:
                return json.loads(item[2])
            except json.JSONDecodeError:
                return None
        # 旧格式: [rpc_id, "<json>", ...]
        if len(item) >= 2 and item[0] == rpc_id and isinstance(item[1], str):
            try:
                return json.loads(item[1])
            except json.JSONDecodeError:
                return None
        # 嵌套格式: [[rpc_id, "<json>", ...]]
        for sub in item:
            if isinstance(sub, list) and len(sub) >= 2 and sub[0] == rpc_id and isinstance(sub[1], str):
                try:
                    return json.loads(sub[1])
                except json.JSONDecodeError:
                    pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  从 hNvQHb payload 提取消息
#  Gemini 的 hNvQHb 响应结构（实验性，通过实际数据推断）：
#  payload = [null, [[turn1], [turn2], ...], ...]
#  turn    = [null, null, null, [[response_candidate, ...]]]
#         或 [null, [user_message_text]]
# ═══════════════════════════════════════════════════════════════════════════════

def _deep_find_str(obj, min_len=20) -> list[str]:
    """递归收集所有长度 >= min_len 的字符串"""
    results = []
    if isinstance(obj, str):
        if len(obj) >= min_len:
            results.append(obj)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            results.extend(_deep_find_str(item, min_len))
    return results


def _get_str_at(obj, path: list):
    """按 path 索引深入对象，返回字符串或 None"""
    cur = obj
    for idx in path:
        if not isinstance(cur, (list, tuple)) or idx >= len(cur):
            return None
        cur = cur[idx]
    return cur if isinstance(cur, str) else None


def _extract_model_text(model_slot) -> str:
    """
    从 turn[3] 提取模型回复文本。
    结构：turn[3][0][0] = [candidate_id_str, [text_str], [part2], ...]
    文本在每个非 str 子项的 [0] 处（若为字符串）。
    """
    if not isinstance(model_slot, list) or not model_slot:
        return ""
    if not isinstance(model_slot[0], list) or not model_slot[0]:
        return ""
    parts_container = model_slot[0][0]
    if not isinstance(parts_container, list):
        return ""
    text_parts = []
    for part in parts_container:
        if isinstance(part, list) and part and isinstance(part[0], str) and len(part[0]) > 2:
            # 跳过 rc_xxx 类型的候选 ID
            if not re.fullmatch(r"rc_[a-f0-9]+", part[0]):
                text_parts.append(part[0])
        elif isinstance(part, str) and len(part) > 2 and not re.fullmatch(r"rc_[a-f0-9]+", part):
            text_parts.append(part)
    return "".join(text_parts)


def parse_gemini_turns(payload: list) -> list[dict]:
    """
    从 hNvQHb payload 解析对话轮次。

    实际观察到的 payload 结构（通过浏览器 CDP fetch）：
      payload = [[exchange0, exchange1, ...], ...]
      每个 exchange（一问一答）= [
        [conv_id, req_id],                     # [0] 请求元数据
        [conv_id, resp_id, candidate_id],      # [1] 响应元数据
        [[user_text, ...], ...],               # [2] 用户消息内容
        [[[rc_id, [model_text], ...]]],        # [3] 模型回复内容
        [...],                                 # [4] 其他元数据
      ]
    每个 exchange 包含一条用户消息 + 一条模型回复。
    """
    if not isinstance(payload, list):
        return []

    exchanges_array = None
    for item in payload:
        if isinstance(item, list) and item and isinstance(item[0], list):
            exchanges_array = item
            break

    if not exchanges_array:
        return []

    turns = []
    for exchange in exchanges_array:
        if not isinstance(exchange, list) or len(exchange) < 3:
            continue

        # ── 用户消息 ──────────────────────────────────────────────────────────
        user_content = exchange[2]
        if isinstance(user_content, list) and user_content:
            first = user_content[0]
            if isinstance(first, list) and first and isinstance(first[0], str):
                user_text = first[0].strip()
                if user_text:
                    turns.append({"role": "user", "text": user_text})

        # ── 模型回复 ──────────────────────────────────────────────────────────
        if len(exchange) > 3 and exchange[3] is not None:
            model_text = _extract_model_text(exchange[3])
            if not model_text:
                # 回退：深层搜索有意义的文本
                candidates = [
                    t for t in _deep_find_str(exchange[3], min_len=15)
                    if not t.startswith("http")
                    and not re.fullmatch(r"(rc_|r_|c_)[a-f0-9]+", t)
                    and not re.fullmatch(r"[a-z0-9_-]{8,64}", t)
                ]
                if candidates:
                    model_text = max(candidates, key=len)
            if model_text.strip():
                turns.append({"role": "model", "text": model_text.strip()})

    # ── 如果以上全失败，粗粒度回退 ────────────────────────────────────────────
    if not turns:
        all_texts = [
            t for t in _deep_find_str(payload, min_len=20)
            if not t.startswith("http")
            and not re.fullmatch(r"[a-z0-9_/+=]{20,}", t)
        ]
        for i, text in enumerate(all_texts):
            turns.append({"role": "user" if i % 2 == 0 else "model", "text": text})

    return turns


# ═══════════════════════════════════════════════════════════════════════════════
#  CDP DOM 回退提取（当 API 解析失败时）
# ═══════════════════════════════════════════════════════════════════════════════

_DOM_EXTRACT_JS = r"""
(function(){
    const strategies=[
        ['user-query-content','model-response'],
        ['user-query','model-response'],
        ['.user-query-content','.model-response'],
        ['[data-role="user"]','[data-role="model"]'],
    ];
    function clean(el){
        const c=el.cloneNode(true);
        c.querySelectorAll('button,[role="button"],mat-icon,.actions-container,.trailing-actions').forEach(n=>n.remove());
        return c;
    }
    for(const [us,ms] of strategies){
        const uEls=[...document.querySelectorAll(us)];
        const mEls=[...document.querySelectorAll(ms)];
        if(!uEls.length && !mEls.length) continue;
        const all=[
            ...uEls.map(el=>({el,role:'user'})),
            ...mEls.map(el=>({el,role:'model'}))
        ].sort((a,b)=>a.el.compareDocumentPosition(b.el)&4?-1:1);
        const turns=all.map(({el,role})=>({
            role, text:clean(el).innerText.trim(),
            html:clean(el).innerHTML,
            markdown:el.getAttribute('data-source-markdown')||''
        })).filter(t=>t.text.length>0);
        if(turns.length) return {turns, via:'dom'};
    }
    return {turns:[], via:'dom_failed'};
})()
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  完整对话捕获（API → DOM 回退）
# ═══════════════════════════════════════════════════════════════════════════════

async def capture_conversation(
    conv_id: str,
    conv_url: str,
    title: str,
    at: str,
    fsid: str,
    bl: str,
    cdp: CDP,
    debug: bool = True,
) -> dict:
    """先尝试 API 全量抓取，失败则回退 CDP DOM"""

    result = {
        "id":         conv_id,
        "url":        conv_url,
        "title":      title,
        "capturedAt": datetime.now().isoformat() + "Z",
        "turns":      [],
        "via":        "unknown",
    }

    # ── 1. 导航到对话页（需要在正确的页面上下文执行 fetch）─────────────────────
    print(f"    → 导航到 {conv_url}")
    await cdp.navigate(conv_url, wait_sec=5)
    await cdp.wait_ready(extra=2)

    # 从页面标题提取真实对话标题
    page_title = await cdp.js(
        "document.title.replace(/ - Google Gemini$/i, '').replace(/^Google Gemini$/i, '').trim()"
    )
    if page_title and page_title != title and len(page_title) > 3:
        result["title"] = page_title
        print(f"    标题: {page_title[:60]}")

    # ── 2. batchexecute API via browser fetch（含分页）────────────────────────
    try:
        if debug:
            DEBUG_DIR.mkdir(parents=True, exist_ok=True)

        all_turns: list[dict] = []
        cont_token: str | None = None
        page_num = 0
        max_pages = 20  # 防止无限循环

        while page_num < max_pages:
            page_num += 1
            if cont_token:
                print(f"    [API] 第 {page_num} 页（续传更早消息）...")
            else:
                print(f"    [API] 通过浏览器 fetch 调用 batchexecute (pageSize=9999)...")

            raw_resp = await call_batchexecute_via_cdp(
                cdp, conv_id, at, bl, fsid, page_size=9999, cont_token=cont_token
            )

            # 保存第一页原始响应供调试
            if debug and page_num == 1:
                (DEBUG_DIR / f"{conv_id}_raw.txt").write_text(raw_resp[:8000], encoding="utf-8")

            chunks  = parse_be_chunks(raw_resp)
            payload = extract_rpc_payload(chunks, "hNvQHb")

            if debug and payload and page_num == 1:
                (DEBUG_DIR / f"{conv_id}_payload.json").write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

            if not payload:
                if page_num == 1:
                    print(f"    [!] API 响应中未找到 hNvQHb payload")
                    if debug:
                        (DEBUG_DIR / f"{conv_id}_chunks.json").write_text(
                            json.dumps(chunks[:3] if isinstance(chunks, list) else str(chunks)[:2000],
                                       ensure_ascii=False, indent=2),
                            encoding="utf-8",
                        )
                break

            page_turns = parse_gemini_turns(payload)
            if not page_turns:
                if page_num == 1:
                    print(f"    [!] API 响应已解析但消息解析为空")
                    if debug:
                        (DEBUG_DIR / f"{conv_id}_payload_full.json").write_text(
                            json.dumps(payload, ensure_ascii=False, indent=2),
                            encoding="utf-8",
                        )
                break

            print(f"    ✓ 第 {page_num} 页: {len(page_turns)} 条消息")
            # 当前页是最近的消息；续传页是更早的消息，要插到前面
            if cont_token:
                all_turns = page_turns + all_turns
            else:
                all_turns = page_turns

            # 检查是否有更早的消息
            next_token = extract_continuation_token(payload)
            if not next_token:
                break  # 已是最早一页
            cont_token = next_token
            # 避免触发速率限制
            await asyncio.sleep(1.5)

        if all_turns:
            result["turns"] = all_turns
            result["turnCount"] = len(all_turns)
            result["via"] = "api"
            pages_str = f"，共 {page_num} 页" if page_num > 1 else ""
            print(f"    ✓ API 提取 {len(all_turns)} 条消息{pages_str}")
            return result

    except Exception as e:
        print(f"    [!] API 调用失败: {e}")

    # ── 3. DOM 回退 ───────────────────────────────────────────────────────────
    print(f"    [DOM] 回退到 CDP DOM 提取...")
    try:
        # 页面已导航，只需滚动加载更多内容
        scroller_js = """
        (function(dir){
            const s=document.querySelector('infinite-scroller')||document.documentElement;
            s.scrollTop = dir==='top' ? 0 : s.scrollHeight;
            return {st:s.scrollTop, sh:s.scrollHeight};
        })
        """
        await cdp.js(f"({scroller_js})('top')")
        await asyncio.sleep(2)
        await cdp.js(f"({scroller_js})('bottom')")
        await asyncio.sleep(3)

        dom_data = await cdp.js(_DOM_EXTRACT_JS, timeout_ms=60_000)
        turns    = dom_data.get("turns", []) if dom_data else []
        result["turns"]     = turns
        result["turnCount"] = len(turns)
        result["via"]       = "dom"
        print(f"    ✓ DOM 提取 {len(turns)} 条消息（DOM 截断限制内）")
    except Exception as e:
        print(f"    [错误] DOM 回退也失败: {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  网站生成（与之前版本保持一致）
# ═══════════════════════════════════════════════════════════════════════════════

CSS = """
:root{
  --bg:#0f1117;--surface:#161b27;--card:#1a2236;
  --accent:#5b9cf6;--accent2:#a78bfa;--red:#f87171;
  --user-bg:#1e2d4a;--model-bg:#111827;
  --text:#e2e8f0;--dim:#64748b;--border:#1e293b;
  --code:#0d1b2e;--radius:14px;
  --sans:-apple-system,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  --mono:"JetBrains Mono","Fira Code","SF Mono",Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.75}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{
  background:linear-gradient(135deg,#0d1b2e,#1a1f35);
  border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:14px;
  position:sticky;top:0;z-index:99;backdrop-filter:blur(12px);
}
.logo{font-size:18px;font-weight:700;
  background:linear-gradient(90deg,#5b9cf6,#a78bfa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.subtitle{color:var(--dim);font-size:13px}
.back{margin-left:auto;color:var(--dim);font-size:13px;
  padding:5px 14px;border:1px solid var(--border);border-radius:20px;transition:all .2s}
.back:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
main{max-width:860px;margin:0 auto;padding:28px 20px}
.search input{
  width:100%;background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:11px 18px;color:var(--text);font-size:14px;
  font-family:var(--sans);outline:none;margin-bottom:20px;
}
.search input:focus{border-color:var(--accent)}
.search input::placeholder{color:var(--dim)}
.grid{display:grid;gap:14px}
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:18px 22px;
  transition:border-color .2s,transform .15s;display:block;
}
.card:hover{border-color:var(--accent);transform:translateY(-2px);text-decoration:none}
.card h2{font-size:15px;font-weight:600;margin-bottom:8px;color:var(--text)}
.meta{display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--dim)}
.badge{background:var(--card);padding:2px 9px;border-radius:10px;border:1px solid var(--border)}
.preview{margin-top:9px;font-size:13px;color:var(--dim);
  overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.via-badge{font-size:11px;padding:1px 7px;border-radius:8px;margin-left:6px}
.via-api{background:#0d2b1a;color:#4ade80;border:1px solid #166534}
.via-dom{background:#1e1b0e;color:#fbbf24;border:1px solid #713f12}
.stats{
  display:flex;gap:18px;flex-wrap:wrap;
  padding:12px 18px;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:24px;font-size:13px;color:var(--dim);
}
.stats strong{color:var(--text)}
.convo{display:flex;flex-direction:column}
.turn{padding:22px 0;border-bottom:1px solid var(--border)}
.turn:last-child{border-bottom:none}
.turn-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.av{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
.av.user{background:linear-gradient(135deg,#3b82f6,#7c3aed)}
.av.model{background:linear-gradient(135deg,#10b981,#3b82f6)}
.role{font-weight:600;font-size:14px}
.role.user{color:#7dd3fc}.role.model{color:#6ee7b7}
.body{padding-left:40px;font-size:15px;line-height:1.8;color:var(--text);white-space:pre-wrap;word-break:break-word}
.body.model p{margin-bottom:12px}
.body.model ul,.body.model ol{padding-left:22px;margin-bottom:12px}
.body.model li{margin-bottom:4px}
.body.model h1,.body.model h2,.body.model h3{margin:18px 0 8px;font-weight:600}
.body.model h2{font-size:17px;color:var(--accent)}
.body.model h3{font-size:15px;color:var(--accent2)}
.body.model strong{color:#f1f5f9}
.body.model code{
  background:var(--code);padding:1px 6px;border-radius:4px;
  font-family:var(--mono);font-size:13px;color:#7dd3fc;
  border:1px solid #1e3a5f;
}
.body.model pre{
  background:var(--code);border:1px solid var(--border);
  border-radius:8px;padding:16px;overflow-x:auto;margin:12px 0;
}
.body.model pre code{background:none;border:none;padding:0;color:#cdd9e5;font-size:13px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
"""

_INDEX_TPL = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gemini 对话存档</title><link rel="stylesheet" href="style.css"></head>
<body>
<header>
  <div class="logo">✦ Gemini 存档</div>
  <div class="subtitle">{count} 个对话 · 更新于 {updated}</div>
</header>
<main>
  <div class="search">
    <input id="q" placeholder="搜索标题或内容…" oninput="filter()">
  </div>
  <div class="grid" id="G">{cards}</div>
</main>
<script>
function filter(){{
  const q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('.card').forEach(c=>{{
    c.style.display=c.innerText.toLowerCase().includes(q)?'':'none';
  }});
}}
</script></body></html>"""

_CARD_TPL = """<a class="card" href="conversations/{id}.html">
  <h2>{title}<span class="via-badge via-{via}">{via_label}</span></h2>
  <div class="meta">
    <span class="badge">💬 {turns} 条</span>
    <span class="badge">📅 {date}</span>
    <span class="badge">🔗 {short_id}</span>
  </div>
  <div class="preview">{preview}</div>
</a>"""

_CONV_TPL = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Gemini</title><link rel="stylesheet" href="../style.css"></head>
<body>
<header>
  <div class="logo">✦ Gemini 存档</div>
  <div class="subtitle">{title}</div>
  <a class="back" href="../index.html">← 返回</a>
</header>
<main>
  <div class="stats">
    <div><strong>{turns}</strong> 条消息</div>
    <div>来源 <strong>{via_label}</strong></div>
    <div>捕获 <strong>{date}</strong></div>
    <div><a href="{url}" target="_blank">在 Gemini 中打开 ↗</a></div>
  </div>
  <div class="convo">{turns_html}</div>
</main></body></html>"""

_TURN_TPL = """<div class="turn">
  <div class="turn-head">
    <div class="av {role}">{letter}</div>
    <div class="role {role}">{label}</div>
  </div>
  <div class="body {role}">{content}</div>
</div>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_turn_html(turn: dict) -> str:
    role = turn.get("role", "model")
    text = turn.get("text", "")
    # 如果有原始 HTML（DOM 提取），使用它；否则纯文本
    html = turn.get("html", "")
    if role == "user":
        content = _esc(text)
    else:
        if html:
            # 清理 Angular 属性
            _ANG = re.compile(r'\s+(?:_ng(?:content|host)-\S+|ng-version="[^"]*"'
                              r'|jsaction="[^"]*"|jsname="[^"]*")')
            html = _ANG.sub("", html)
            content = html
        else:
            content = _esc(text).replace("\n", "<br>")
    return _TURN_TPL.format(
        role=role,
        letter="你" if role == "user" else "G",
        label="你" if role == "user" else "Gemini",
        content=content,
    )


def generate_site(conversations: list[dict]) -> Path:
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    (SITE_DIR / "conversations").mkdir(exist_ok=True)
    (SITE_DIR / "data").mkdir(exist_ok=True)
    (SITE_DIR / "style.css").write_text(CSS, encoding="utf-8")

    # 保存全量 JSON（方便增量合并）
    (SITE_DIR / "data" / "_all.json").write_text(
        json.dumps(conversations, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # conversations 已按侧边栏顺序（最新在前）传入；原样输出即可
    cards = []
    for conv in conversations:
        cid   = conv.get("id") or re.search(r"/app/([a-zA-Z0-9_-]+)", conv.get("url",""), )
        if not cid:
            continue
        if not isinstance(cid, str):
            cid = cid.group(1)

        title = conv.get("title") or cid
        turns = conv.get("turns", [])
        date  = (conv.get("capturedAt") or "")[:10]
        via   = conv.get("via", "unknown")
        via_label = "完整API" if via == "api" else "DOM(部分)"

        turns_html = "\n".join(_build_turn_html(t) for t in turns)
        page = _CONV_TPL.format(
            title=_esc(title), url=conv.get("url",""),
            turns=len(turns), date=date,
            via_label=via_label,
            turns_html=turns_html,
        )
        (SITE_DIR / "conversations" / f"{cid}.html").write_text(page, encoding="utf-8")
        (SITE_DIR / "data" / f"{cid}.json").write_text(
            json.dumps(conv, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        preview = next((t["text"][:120] for t in turns if t.get("role") == "user"), "")
        cards.append(_CARD_TPL.format(
            id=cid, title=_esc(title), turns=len(turns), date=date,
            via=via, via_label=via_label,
            short_id=cid[:12] + "…", preview=_esc(preview),
        ))

    index = _INDEX_TPL.format(
        count=len(conversations),
        updated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        cards="\n".join(cards),
    )
    idx = SITE_DIR / "index.html"
    idx.write_text(index, encoding="utf-8")
    return idx


# ═══════════════════════════════════════════════════════════════════════════════
#  主流程
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    print("═" * 60)
    print("  Gemini 全量对话捕获  (API + CDP 双路)")
    print("═" * 60)

    # 1. 连接 CDP（直接用浏览器 fetch 调用 API，无需单独管理 Cookie）
    print(f"\n[1] 连接 Chrome 调试端口 {CHROME_PORT}...")
    tab = open_cdp(CHROME_PORT)
    cdp = CDP(tab["webSocketDebuggerUrl"])
    await cdp.connect()
    await cdp.send("Page.enable")
    await cdp.send("Network.enable")
    print(f"    ✓ 已连接: {tab.get('title','')[:50]}")

    # 2. 导航 Gemini，提取 WIZ 参数
    print("\n[2] 导航到 Gemini 并提取 API 参数...")
    await cdp.navigate("https://gemini.google.com/app", wait_sec=8)
    await cdp.wait_ready(extra=4)

    page_title = await cdp.js("document.title")
    print(f"    页面标题: {page_title}")

    wiz = await cdp.js(_WIZ_JS)
    at   = wiz.get("at",   "") if wiz else ""
    fsid = wiz.get("fsid", "") if wiz else ""
    bl   = wiz.get("bl",   "") if wiz else ""

    if at:
        print(f"    ✓ at={at[:20]}...  fsid={fsid[:20] if fsid else '(空)'}  bl={bl[:20] if bl else '(空)'}")
    else:
        print("    [!] 未能提取 at= token，API 模式将失败，使用 DOM 回退")

    # 3. 滚动侧边栏加载全部历史对话
    print("\n[3] 滚动侧边栏加载全部历史对话...")
    # 先返回主页，确保侧边栏可见
    await cdp.navigate("https://gemini.google.com/app", wait_sec=6)
    await cdp.wait_ready(extra=3)

    prev_count = 0
    stall_rounds = 0
    conv_list = []
    round_num = 0

    while True:
        round_num += 1
        # 滚动侧边栏
        scroll_info = await cdp.js(_SCROLL_SIDEBAR_JS)
        await asyncio.sleep(2.5)

        conv_list = await cdp.js(_CONV_LIST_JS) or []
        count = len(conv_list)

        if count > prev_count:
            print(f"    [{round_num}] 已加载 {count} 个对话（+{count - prev_count}）...")
            prev_count = count
            stall_rounds = 0
        else:
            stall_rounds += 1
            if stall_rounds >= 4:
                print(f"    连续 {stall_rounds} 轮无新对话，侧边栏已到底")
                break
            # 稍等更长时间再试一次
            await asyncio.sleep(2)

        # 防止无限循环
        if round_num >= 200:
            print(f"    已达最大轮次限制 ({round_num})")
            break

    if not conv_list:
        print("    [!] 侧边栏无对话链接，请检查登录状态")
        body_text = await cdp.js("document.body.innerText.slice(0,300)")
        print(f"    页面片段: {body_text[:200]}")
        await cdp.close()
        return

    # 重新提取 WIZ 参数（页面刷新后 token 可能变化）
    wiz2 = await cdp.js(_WIZ_JS)
    if wiz2 and wiz2.get("at"):
        at   = wiz2.get("at",   at)
        fsid = wiz2.get("fsid", fsid)
        bl   = wiz2.get("bl",   bl)

    total = len(conv_list)
    limit = CONV_LIMIT if CONV_LIMIT > 0 else total
    print(f"\n    ✓ 共发现 {total} 个对话，捕获全部 {limit} 个:")
    for i, c in enumerate(conv_list[:limit], 1):
        print(f"      {i}. {c['title'][:55]}")

    # 4. 逐个捕获
    print(f"\n[4] 开始全量捕获（共 {limit} 个对话）...（侧边栏顺序 = 最新在前）")
    conversations = []
    for i, info in enumerate(conv_list[:limit], 1):
        print(f"\n  ── [{i}/{limit}] {info['title'][:55]}")
        try:
            data = await capture_conversation(
                conv_id=info["id"],
                conv_url=info["url"],
                title=info["title"],
                at=at,
                fsid=fsid,
                bl=bl,
                cdp=cdp,
                debug=True,
            )
            conversations.append(data)
        except Exception as e:
            import traceback
            print(f"    [错误] {e}")
            traceback.print_exc()

    await cdp.close()

    if not conversations:
        print("\n[!] 没有成功捕获任何对话")
        return

    # 5. 生成网站
    print(f"\n[5] 生成本地静态网站...")
    idx = generate_site(conversations)

    api_count = sum(1 for c in conversations if c.get("via") == "api")
    dom_count = sum(1 for c in conversations if c.get("via") == "dom")
    total_turns = sum(c.get("turnCount", len(c.get("turns", []))) for c in conversations)

    print(f"\n{'═'*60}")
    print(f"  完成！捕获 {len(conversations)} 个对话，共 {total_turns} 条消息")
    print(f"  API 完整提取: {api_count} 个 | DOM 部分提取: {dom_count} 个")
    if DEBUG_DIR.exists():
        print(f"  调试文件 → {DEBUG_DIR}")
    print(f"  网站 → file://{idx}")
    print(f"{'═'*60}")
    os.system(f'open "file://{idx}"')


if __name__ == "__main__":
    asyncio.run(main())
