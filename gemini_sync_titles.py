#!/usr/bin/env python3
"""
gemini_sync_titles.py
─────────────────────
扫描 Gemini 侧边栏，把每个对话的真实标题同步到 _all.json，
然后重新生成站点。不重抓对话内容，只更新标题。
"""
import asyncio, json, sys
from pathlib import Path

sys.argv_orig = sys.argv[:]
sys.argv = [sys.argv[0]]
sys.path.insert(0, str(Path.home() / "bin"))
import gemini_api_capture as gac
sys.argv = sys.argv_orig


async def main():
    print("[1] 连接 Chrome...")
    tab = gac.open_cdp(gac.CHROME_PORT)
    cdp = gac.CDP(tab["webSocketDebuggerUrl"])
    await cdp.connect()
    await cdp.send("Page.enable")
    print("    ✓")

    print("[2] 导航到 Gemini 主页...")
    await cdp.navigate("https://gemini.google.com/app", wait_sec=6)
    await cdp.wait_ready(extra=3)

    print("[3] 滚动侧边栏加载所有对话...")
    prev = 0; stall = 0; round_n = 0
    while True:
        round_n += 1
        await cdp.js(gac._SCROLL_SIDEBAR_JS)
        await asyncio.sleep(2.0)
        items = await cdp.js(gac._CONV_LIST_JS) or []
        n = len(items)
        if n > prev:
            print(f"    [{round_n}] {n} 个 (+{n-prev})")
            prev = n; stall = 0
        else:
            stall += 1
            if stall >= 4:
                print(f"    到底，共 {n} 个")
                break
        if round_n > 200:
            break

    # 注：折叠侧边栏时 innerText=""（CSS 隐藏），用 textContent 拿到 DOM 真实文本
    BETTER_SCRAPE_JS = r"""
(function(){
    const out = [];
    document.querySelectorAll('a[data-test-id="conversation"]').forEach(a => {
        const m = a.href.match(/\/app\/([a-zA-Z0-9_-]{8,})/);
        if (!m) return;
        const titleEl = a.querySelector('.conversation-title');
        let t = (titleEl ? titleEl.textContent : a.textContent || '').trim();
        // 去除多余空白和换行
        t = t.replace(/\s+/g, ' ').trim();
        out.push({id: m[1], title: t || m[1]});
    });
    return out;
})()
"""
    items = await cdp.js(BETTER_SCRAPE_JS) or []
    by_id = {it["id"]: (it.get("title") or "").strip() for it in items}
    print(f"    ✓ 抓到 {len(by_id)} 个对话标题")
    await cdp.close()

    # Filter out useless titles
    def is_useless(t, cid):
        if not t: return True
        if t == cid or t.startswith(cid[:12]): return True
        if t in ("Gemini", "Google Gemini", ""): return True
        return False

    real_titles = {cid: t for cid, t in by_id.items() if not is_useless(t, cid)}
    print(f"    真实标题: {len(real_titles)} 个 (其余可能是 Gemini 还没自动命名)")

    print("[4] 合并入 _all.json 并重新生成站点...")
    all_path = gac.SITE_DIR / "data" / "_all.json"
    arr = json.loads(all_path.read_text(encoding="utf-8"))
    updated = 0; new_titled = 0
    for c in arr:
        cid = c.get("id")
        if cid in real_titles:
            new_t = real_titles[cid]
            old_t = c.get("title", "")
            if old_t != new_t:
                if is_useless(old_t, cid):
                    new_titled += 1
                c["title"] = new_t
                updated += 1
    print(f"    ✓ 更新 {updated} 个标题（其中 {new_titled} 个从 ID 升级到真实标题）")

    idx = gac.generate_site(arr)
    print(f"\n✓ 完成 → file://{idx}")


if __name__ == "__main__":
    asyncio.run(main())
