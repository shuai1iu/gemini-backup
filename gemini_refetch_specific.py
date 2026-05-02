#!/usr/bin/env python3
"""
gemini_refetch_specific.py
─────────────────────────
只重抓指定 ID 列表的对话，用修复后的 parse_gemini_turns（已改为 reversed）。
重抓后合并进 _all.json，重新生成对应的 HTML/JSON 单页。

用法：python3 gemini_refetch_specific.py <id1> <id2> ...
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# capture script reads sys.argv[1] as CONV_LIMIT at import time;
# stash our argv so it doesn't barf on non-int IDs
_my_argv = sys.argv[:]
sys.argv = [sys.argv[0]]

sys.path.insert(0, str(Path.home() / "bin"))
import gemini_api_capture as gac

sys.argv = _my_argv


async def main():
    if len(sys.argv) < 2:
        print("usage: gemini_refetch_specific.py <conv_id> [conv_id ...]")
        sys.exit(1)

    target_ids = sys.argv[1:]
    print(f"[1] 目标对话 {len(target_ids)} 个: {target_ids}")

    print(f"[2] 连接 Chrome 调试端口 {gac.CHROME_PORT}...")
    tab = gac.open_cdp(gac.CHROME_PORT)
    cdp = gac.CDP(tab["webSocketDebuggerUrl"])
    await cdp.connect()
    await cdp.send("Page.enable")
    await cdp.send("Network.enable")
    print(f"    ✓ 已连接")

    print(f"[3] 提取 API 参数...")
    await cdp.navigate("https://gemini.google.com/app", wait_sec=6)
    await cdp.wait_ready(extra=2)
    wiz = await cdp.js(gac._WIZ_JS)
    at   = wiz.get("at",   "") if wiz else ""
    fsid = wiz.get("fsid", "") if wiz else ""
    bl   = wiz.get("bl",   "") if wiz else ""
    if not at:
        print("[!] 无法获取 at token，登录态可能失效")
        await cdp.close()
        return
    print(f"    ✓ at={at[:18]}... bl={bl[:18]}")

    # 加载现有 _all.json，用于 merge + 取标题
    all_path = gac.SITE_DIR / "data" / "_all.json"
    all_arr  = json.loads(all_path.read_text(encoding="utf-8"))
    by_id    = {c["id"]: c for c in all_arr}

    print(f"[4] 重新抓取...")
    refreshed: dict[str, dict] = {}
    for i, cid in enumerate(target_ids, 1):
        old = by_id.get(cid, {})
        title = old.get("title") or cid
        url   = old.get("url") or f"https://gemini.google.com/app/{cid}"
        print(f"\n  ── [{i}/{len(target_ids)}] {title[:50]}  (旧 {len(old.get('turns',[]))} 条)")
        try:
            data = await gac.capture_conversation(
                conv_id=cid, conv_url=url, title=title,
                at=at, fsid=fsid, bl=bl, cdp=cdp, debug=True,
            )
            old_n = len(old.get("turns", []))
            new_n = len(data.get("turns", []))
            print(f"    ✓ 新 {new_n} 条（旧 {old_n}）")
            # 防御：如果新版显著缩水（如 API 失败回退到 DOM 截断），拒绝覆盖
            if old_n >= 30 and new_n < old_n * 0.7:
                print(f"    [!] 拒绝覆盖：新数据 ({new_n}) 比旧数据 ({old_n}) 少 ≥30%，可能是 API 失败回退 DOM")
                continue
            refreshed[cid] = data
        except Exception as e:
            import traceback
            print(f"    [错误] {e}")
            traceback.print_exc()

    await cdp.close()

    if not refreshed:
        print("\n[!] 无对话被刷新")
        return

    # 5. 合并入 _all.json
    print(f"\n[5] 合并入 _all.json 并重新生成...")
    new_all = []
    for c in all_arr:
        cid = c.get("id")
        if cid in refreshed:
            new_all.append(refreshed[cid])
        else:
            new_all.append(c)

    # 重新生成整站（generate_site 会写 _all.json + 每条 HTML/JSON）
    idx = gac.generate_site(new_all)

    print(f"\n✓ 完成")
    for cid, data in refreshed.items():
        turns = data.get("turns", [])
        first_user = next((t["text"] for t in turns if t.get("role")=="user"), "")
        last_user  = next((t["text"] for t in reversed(turns) if t.get("role")=="user"), "")
        print(f"\n  [{cid}] {data.get('title','')[:40]}  共 {len(turns)} 条")
        print(f"    最早用户消息: {first_user[:120]}")
        print(f"    最近用户消息: {last_user[:120]}")
    print(f"\n  网站 → file://{idx}")


if __name__ == "__main__":
    asyncio.run(main())
