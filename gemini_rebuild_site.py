#!/usr/bin/env python3
"""
gemini_rebuild_site.py
─────────────────────
从 ~/Documents/gemini_api_debug/ 下的 *_payload.json 重建本地网站，
避免 iCloud Drive 写入超时问题。

为什么需要这个：
    抓取脚本 gemini_api_capture.py 在最后 generate_site() 阶段批量
    写入 ~/Documents/gemini_local_site/ 时，因 iCloud 同步阻塞触发
    Errno 60 超时崩溃。但抓取过程中已经把每个对话的原始 payload
    持久化到了 gemini_api_debug/，所以可以从这些数据重建。

输出位置：~/gemini_local_site/  (非 iCloud)
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

# 让脚本能 import 原始 capture 模块里的解析与模板
sys.path.insert(0, str(Path.home() / "bin"))

import gemini_api_capture as gac

DEBUG_DIR = Path.home() / "Documents" / "gemini_api_debug"
OLD_SITE  = Path.home() / "Documents" / "gemini_local_site"
NEW_SITE  = Path.home() / "gemini_local_site"

# 覆盖原模块的 SITE_DIR，让 generate_site 写到新位置
gac.SITE_DIR = NEW_SITE


def load_old_meta() -> dict:
    """读取上次成功的 _all.json，用于补全 title / 多页旧消息"""
    p = OLD_SITE / "data" / "_all.json"
    if not p.exists():
        return {}
    try:
        arr = json.loads(p.read_text(encoding="utf-8"))
        return {c["id"]: c for c in arr if c.get("id")}
    except Exception as e:
        print(f"[warn] 读取旧 _all.json 失败: {e}")
        return {}


def title_from_turns(turns: list) -> str:
    for t in turns:
        if t.get("role") == "user" and t.get("text"):
            return t["text"][:60].replace("\n", " ").strip()
    return ""


def main():
    print(f"[1] 扫描 debug payloads: {DEBUG_DIR}")
    payloads = sorted(
        DEBUG_DIR.glob("*_payload.json"),
        key=lambda p: p.stat().st_mtime,  # 升序：最先写入 = 侧边栏最新
    )
    print(f"    找到 {len(payloads)} 个 payload")

    print(f"[2] 加载旧 _all.json（用于 title / 旧分页消息）")
    old_meta = load_old_meta()
    print(f"    旧记录 {len(old_meta)} 个对话")

    print(f"[3] 解析 + 合并...")
    conversations = []
    fail = 0
    new_count = 0
    multi_page_recovered = 0

    for i, pp in enumerate(payloads, 1):
        cid = pp.name.replace("_payload.json", "")
        try:
            payload = json.loads(pp.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"    [{i}] {cid} 读取失败: {e}")
            fail += 1
            continue

        turns = gac.parse_gemini_turns(payload)
        old = old_meta.get(cid)

        # 如果旧版有更多 turns（说明原本是多页对话，debug 只存了第 1 页），
        # 把旧版前面那些更早的消息接到当前 turns 之前。
        if old and isinstance(old.get("turns"), list) and len(old["turns"]) > len(turns):
            old_turns = old["turns"]
            # 当前 turns 是最新一页；旧 turns 是当时全量。我们尝试用旧的更早部分。
            # 简单策略：如果当前页文字能在旧版找到尾部匹配，就用旧版的更早部分 + 当前
            try:
                first_user_in_new = next((t["text"] for t in turns if t.get("role") == "user"), None)
                if first_user_in_new:
                    # 在旧 turns 中找到 first_user 的位置，取它之前的部分
                    pos = next(
                        (idx for idx, t in enumerate(old_turns)
                         if t.get("role") == "user" and t.get("text", "").strip() == first_user_in_new.strip()),
                        None,
                    )
                    if pos is not None and pos > 0:
                        turns = old_turns[:pos] + turns
                        multi_page_recovered += 1
            except Exception:
                pass

        # 标题：优先用旧 meta，其次用首条用户消息
        title = (old or {}).get("title") or title_from_turns(turns) or cid

        # 注意：mtime 升序遍历=侧边栏顺序（最新在前），用 capture 时间近似
        captured_at = datetime.fromtimestamp(pp.stat().st_mtime).isoformat() + "Z"

        if cid not in old_meta:
            new_count += 1

        conversations.append({
            "id": cid,
            "url": f"https://gemini.google.com/app/{cid}",
            "title": title,
            "capturedAt": captured_at,
            "turns": turns,
            "turnCount": len(turns),
            "via": "api",
        })

    print(f"    解析成功 {len(conversations)} / 失败 {fail}")
    print(f"    新增对话（旧版未覆盖）: {new_count}")
    print(f"    多页对话恢复（拼接旧版更早消息）: {multi_page_recovered}")

    print(f"[4] 写入新站点: {NEW_SITE}")
    NEW_SITE.mkdir(parents=True, exist_ok=True)
    idx = gac.generate_site(conversations)
    print(f"\n✓ 完成 → file://{idx}")
    print(f"  共 {len(conversations)} 个对话，"
          f"{sum(c['turnCount'] for c in conversations)} 条消息")
    os.system(f'open "file://{idx}"')


if __name__ == "__main__":
    main()
