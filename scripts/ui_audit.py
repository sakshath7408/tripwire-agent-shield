#!/usr/bin/env python3
"""Overflow audit for the Tripwire dashboard, the pitch deck and the hosted demo page.

For every visible element with text it flags:
  (a) content wider or taller than its box on a non-scrolling container,
  (b) a text node (HTML or SVG) whose rendered rect pokes outside its nearest bordered or
      backgrounded ancestor (for SVG: the <rect> drawn just before it),
  (c) siblings that overlap each other unexpectedly,
  (d) horizontal page scroll.
Intentional ellipsis (text-overflow: ellipsis plus a title) and scroll areas are ignored, and any
element with data-audit-ok is skipped.

Usage (dashboard states need a running daemon fed by demo/run_demo.py, and TRIPWIRE_HOME set to its home so
the browser can pair):
  TRIPWIRE_HOME=<home> uv run python scripts/ui_audit.py --base http://127.0.0.1:7797 --out /tmp/ui-audit
  uv run python scripts/ui_audit.py --pitch docs/pitch/index.html --out /tmp/ui-audit
  uv run python scripts/ui_audit.py --web http://127.0.0.1:7798 --out /tmp/ui-audit
Exit code 1 when anything is flagged. Screenshots of failing states land in --out.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

AUDIT_JS = r"""
(opts) => {
  const tol = 1.5;
  const issues = [];
  const vis = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden" || cs.opacity === "0") return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const path = (el) => {
    const parts = [];
    for (let e = el; e && e.nodeType === 1 && parts.length < 4; e = e.parentElement) {
      let p = e.tagName.toLowerCase();
      if (e.id) p += "#" + e.id;
      else if (e.classList.length) p += "." + [...e.classList].slice(0, 2).join(".");
      parts.unshift(p);
    }
    return parts.join(" > ");
  };
  const snippet = (t) => String(t || "").replace(/\s+/g, " ").trim().slice(0, 50);
  const hasBox = (el) => {
    const cs = getComputedStyle(el);
    const border = ["Top", "Right", "Bottom", "Left"].some((s) => parseFloat(cs[`border${s}Width`]) > 0 && cs[`border${s}Style`] !== "none");
    const bg = cs.backgroundColor !== "rgba(0, 0, 0, 0)" && cs.backgroundColor !== "transparent";
    const img = cs.backgroundImage !== "none";
    const shadow = cs.boxShadow !== "none";
    const clip = cs.overflow !== "visible" || cs.overflowX !== "visible" || cs.overflowY !== "visible";
    return border || bg || img || shadow || clip;
  };
  const skip = (el) => !!el.closest("[data-audit-ok], .sr-only, script, style");
  const inside = (inner, outer) => inner.left >= outer.left - tol && inner.right <= outer.right + tol && inner.top >= outer.top - tol && inner.bottom <= outer.bottom + tol;
  const fmt = (r) => `${Math.round(r.left)},${Math.round(r.top)} ${Math.round(r.width)}x${Math.round(r.height)}`;

  // (d) page scroll
  const de = document.documentElement;
  if (de.scrollWidth > de.clientWidth + tol) issues.push({ kind: "page-scroll-x", where: "html", detail: `scrollWidth ${de.scrollWidth} > viewport ${de.clientWidth}` });

  const all = [...document.querySelectorAll("body *")].filter((el) => !(el instanceof SVGElement) && vis(el) && !skip(el));
  for (const el of all) {
    const cs = getComputedStyle(el);
    const scrollsX = /auto|scroll/.test(cs.overflowX), scrollsY = /auto|scroll/.test(cs.overflowY);
    const ellipsis = cs.textOverflow === "ellipsis" && (el.hasAttribute("title") || el.closest("[title]"));
    // (a) overflow on a non-scrolling container
    if (!scrollsX && el.scrollWidth > el.clientWidth + tol && el.clientWidth > 0 && !ellipsis) {
      issues.push({ kind: "overflow-x", where: path(el), detail: `content ${el.scrollWidth}px in a ${el.clientWidth}px box (${cs.overflowX})`, text: snippet(el.textContent) });
    }
    if (!scrollsY && el.scrollHeight > el.clientHeight + tol && el.clientHeight > 0 && cs.overflowY !== "visible") {
      issues.push({ kind: "overflow-y", where: path(el), detail: `content ${el.scrollHeight}px tall in a ${el.clientHeight}px box (${cs.overflowY})`, text: snippet(el.textContent) });
    }
  }

  // (b) text nodes outside their nearest bordered / backgrounded ancestor
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => (n.nodeValue.trim() && n.parentElement && vis(n.parentElement) && !skip(n.parentElement) && !(n.parentElement instanceof SVGElement)) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT,
  });
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const range = document.createRange(); range.selectNodeContents(n);
    const rects = [...range.getClientRects()].filter((r) => r.width > 0 && r.height > 0);
    if (!rects.length) continue;
    const tr = { left: Math.min(...rects.map((r) => r.left)), right: Math.max(...rects.map((r) => r.right)), top: Math.min(...rects.map((r) => r.top)), bottom: Math.max(...rects.map((r) => r.bottom)) };
    let anc = n.parentElement;
    while (anc && anc !== document.body && !hasBox(anc)) anc = anc.parentElement;
    if (!anc || anc === document.body) continue;
    const acs = getComputedStyle(anc);
    if (/auto|scroll/.test(acs.overflowX) || /auto|scroll/.test(acs.overflowY)) continue; // a scroll area holds more than it shows
    if (acs.textOverflow === "ellipsis" || getComputedStyle(n.parentElement).textOverflow === "ellipsis") continue;
    const ar = anc.getBoundingClientRect();
    if (!inside(tr, ar)) issues.push({ kind: "text-outside-box", where: path(n.parentElement), detail: `text ${fmt({ left: tr.left, top: tr.top, width: tr.right - tr.left, height: tr.bottom - tr.top })} vs box ${path(anc)} ${fmt(ar)}`, text: snippet(n.nodeValue) });
  }

  // (b, SVG) <text> inside the <rect> drawn right before it, and inside its <svg>
  for (const t of document.querySelectorAll("svg text")) {
    if (!vis(t) || skip(t)) continue;
    const tr = t.getBoundingClientRect();
    const svg = t.ownerSVGElement;
    if (svg && !inside(tr, svg.getBoundingClientRect())) issues.push({ kind: "svg-text-outside-svg", where: path(t), detail: `text ${fmt(tr)} vs svg ${fmt(svg.getBoundingClientRect())}`, text: snippet(t.textContent) });
    let prev = t.previousElementSibling;
    while (prev && prev.tagName.toLowerCase() === "text") prev = prev.previousElementSibling;
    if (prev && prev.tagName.toLowerCase() === "rect") {
      const rr = prev.getBoundingClientRect();
      // only labels meant for that rect: vertically in its row and horizontally centred on it
      const cx = (tr.left + tr.right) / 2;
      const inRow = tr.top >= rr.top - rr.height && tr.bottom <= rr.bottom + rr.height && cx >= rr.left && cx <= rr.right;
      if (inRow && !inside(tr, rr)) issues.push({ kind: "svg-text-outside-rect", where: path(t), detail: `text ${fmt(tr)} vs rect ${fmt(rr)}`, text: snippet(t.textContent) });
    }
  }

  // (c) unexpected sibling overlap: in-flow block/flex/grid children of the same parent
  const inflow = (el) => { const cs = getComputedStyle(el); return !/absolute|fixed|sticky/.test(cs.position) && cs.transform === "none" && cs.float === "none" && !cs.display.startsWith("inline") && cs.display !== "contents"; };
  const negMargin = (el) => { const cs = getComputedStyle(el); return ["Top", "Right", "Bottom", "Left"].some((s) => parseFloat(cs[`margin${s}`]) < 0); };
  const parents = new Set(all.map((el) => el.parentElement).filter(Boolean));
  for (const p of parents) {
    if (p instanceof SVGElement || skip(p)) continue;
    const kids = [...p.children].filter((k) => !(k instanceof SVGElement) && vis(k) && inflow(k) && !negMargin(k) && !skip(k));
    for (let i = 0; i < kids.length; i++) for (let j = i + 1; j < kids.length; j++) {
      const a = kids[i].getBoundingClientRect(), b = kids[j].getBoundingClientRect();
      const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left), oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (ox > 2 && oy > 2) issues.push({ kind: "sibling-overlap", where: `${path(kids[i])} ~ ${path(kids[j])}`, detail: `overlap ${Math.round(ox)}x${Math.round(oy)}px` });
    }
  }
  return issues;
}
"""


class Audit:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.out.mkdir(parents=True, exist_ok=True)
        self.results: list[dict] = []

    def check(self, page: Page, name: str) -> list[dict]:
        page.wait_for_timeout(150)
        issues = page.evaluate(AUDIT_JS, {})
        # one line per (kind, where): the same wrapper repeated per row is one bug
        seen, uniq = set(), []
        for i in issues:
            k = (i["kind"], i["where"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(i)
        self.results.append({"state": name, "issues": uniq})
        if uniq:
            page.screenshot(path=str(self.out / f"FAIL-{name}.png"))
            print(f"  FAIL {name}: {len(uniq)} issue(s)")
            for i in uniq:
                print(f"       - [{i['kind']}] {i['where']}  {i['detail']}" + (f"  “{i['text']}”" if i.get("text") else ""))
        else:
            print(f"  ok   {name}")
        return uniq

    def done(self) -> int:
        (self.out / "ui_audit.json").write_text(json.dumps(self.results, indent=1))
        bad = [r for r in self.results if r["issues"]]
        print(f"\n{len(self.results)} states checked, {len(bad)} with issues. Report: {self.out / 'ui_audit.json'}")
        return 1 if bad else 0


WIDTHS = [(390, 844), (768, 1024), (1024, 768), (1280, 720), (1440, 900), (1920, 1080)]


def demo_cookie(base: str) -> str | None:
    """Pair this script's browser on a daemon started with `serve --demo-admin` (a throwaway test daemon: the
    real one has no key a script could use). Returns the dashboard cookie value, or None."""
    import json as _json
    import os as _os
    import urllib.request as _rq
    home = _os.environ.get("TRIPWIRE_HOME") or _os.path.expanduser("~/.tripwire")
    try:
        key = open(_os.path.join(home, "demo-admin.key")).read().strip()
        req = _rq.Request(f"{base}/v1/pair/new", data=b"", method="POST", headers={"X-Tripwire-Demo-Admin": key})
        code = _json.loads(_rq.urlopen(req, timeout=5).read())["code"]
        req = _rq.Request(f"{base}/v1/pair", data=_json.dumps({"code": code}).encode(), method="POST",
                          headers={"content-type": "application/json"})
        cookie = _rq.urlopen(req, timeout=5).headers.get("set-cookie") or ""
        return cookie.split("=", 1)[1].split(";", 1)[0] or None
    except Exception:  # noqa: BLE001
        return None


def pair(c, base: str) -> None:
    """Give the browser a dashboard cookie, as `tripwire open` would. Without it every dashboard state is the
    "not connected" page and the audit checks nothing real. Needs a `serve --demo-admin` daemon."""
    from tripwire import auth

    tok = demo_cookie(base)
    if not tok:
        print("  warning: could not pair; start the daemon with `serve --demo-admin` and the same TRIPWIRE_HOME")
        return
    host = base.split("//", 1)[1].split(":")[0].split("/")[0]
    c.add_cookies([{"name": auth.COOKIE, "value": tok, "domain": host, "path": "/"}])


def dashboard(a: Audit, browser, base: str, widths=WIDTHS, themes=("light", "dark"), full: bool = True) -> None:
    def ctx(w, h, seen_guide=True):
        c = browser.new_context(viewport={"width": w, "height": h})
        pair(c, base)
        if seen_guide:
            c.add_init_script("localStorage.setItem('tw-guide-seen','1')")
        return c

    def open_(p: Page, q: str) -> None:
        p.goto(base + "/" + q)
        p.wait_for_selector(".row, .empty:not([hidden]), .offline:not([hidden])", timeout=15000)
        p.wait_for_timeout(500)

    def unsheet(p: Page) -> None:
        """On a phone the detail panel is a full-screen sheet; close it before clicking behind it."""
        if p.locator(".detail.is-open").count():
            p.keyboard.press("Escape")
            p.wait_for_timeout(200)

    def session(p: Page, name: str) -> None:
        unsheet(p)
        b = p.locator("#sessions button", has_text=name).first
        if b.count():
            b.scroll_into_view_if_needed()
            b.click()
            p.wait_for_timeout(300)

    def mode(p: Page, m: str) -> None:
        p.click(f'#mode-seg [data-mode="{m}"]')
        p.wait_for_timeout(200)

    for (w, h) in widths:
        for theme in themes:
            tag = f"{w}-{theme}"
            # guide, all 5 steps, on a fresh profile
            c = ctx(w, h, seen_guide=False)
            p = c.new_page()
            open_(p, f"?theme={theme}")
            p.wait_for_selector("#tour:not([hidden])", timeout=5000)
            for i in range(5):
                p.wait_for_timeout(350)
                a.check(p, f"guide-step{i + 1}-{tag}")
                if i < 4:
                    p.click("#tour-next")
            p.click("#tour-next")
            c.close()

            c = ctx(w, h)
            p = c.new_page()
            for m in ("simple", "detailed"):
                open_(p, f"?theme={theme}")
                mode(p, m)
                session(p, "demo-beyond-permission")
                blocked = p.locator('.row[data-d="block"]').first
                if blocked.count():
                    blocked.click()
                    p.wait_for_timeout(400)
                a.check(p, f"feed-blocked-{m}-{tag}")
                session(p, "demo-subagents")
                b2 = p.locator(".row", has_text="curl").first
                if b2.count():
                    b2.click()
                    p.wait_for_timeout(400)
                a.check(p, f"feed-longcmd-{m}-{tag}")
                session(p, "demo-a-very-long")
                a.check(p, f"longsession-{m}-{tag}")
                session(p, "demo-legit")
                a.check(p, f"allclear-{m}-{tag}")
                queue = p.locator(".q-item").first
                if queue.count():
                    pass
                for sname in ("demo-injected-doc", "demo-injected-web"):
                    session(p, sname)
                    if p.locator(".q-item").count():
                        p.locator(".q-item").first.click()
                        p.wait_for_timeout(300)
                        a.check(p, f"queue-{m}-{tag}")
                        unsheet(p)
                        break
                # audit tab, list + tree
                unsheet(p)
                p.click("#tab-audit")
                p.wait_for_timeout(500)
                a.check(p, f"audit-list-{m}-{tag}")
                if m == "detailed" and not p.locator("#audit-tree-tab").is_hidden():
                    p.click("#audit-tree-tab")
                    p.wait_for_timeout(500)
                    a.check(p, f"audit-tree-{tag}")
                # toast
                p.click("#export")
                p.wait_for_timeout(250)
                a.check(p, f"toast-{m}-{tag}")
                # settings popover (only when the daemon offers it)
                if not p.locator("#settings-wrap").is_hidden():
                    p.click("#tab-live")
                    p.click("#settings-btn")
                    p.wait_for_timeout(300)
                    a.check(p, f"settings-{m}-{tag}")
                    p.keyboard.press("Escape")
            if w >= 1024:
                open_(p, f"?theme={theme}&stage=1")
                session(p, "demo-beyond-permission")
                blocked = p.locator('.row[data-d="block"]').first
                if blocked.count():
                    blocked.click()
                    p.wait_for_timeout(300)
                a.check(p, f"presenter-{tag}")
                p.goto(base + "/?theme=" + theme)
                p.evaluate("document.documentElement.classList.remove('stage'); localStorage.setItem('tw-stage','0')")
            c.close()


def dashboard_special(a: Audit, browser, base: str) -> None:
    """States the demo feed cannot produce, made by intercepting the API: empty log, daemon gone, browser not paired."""
    for theme in ("light", "dark"):
        for (w, h) in ((390, 844), (1280, 720)):
            for state in ("empty", "offline", "unpaired"):
                c = browser.new_context(viewport={"width": w, "height": h})
                c.add_init_script("localStorage.setItem('tw-guide-seen','1')")
                p = c.new_page()
                if state == "empty":
                    def empty(route):
                        u = route.request.url
                        body = {"total": 0, "allow": 0, "ask": 0, "block": 0, "pending": [], "sessions": 0} if "/v1/stats" in u else []
                        route.fulfill(json=body) if "/v1/events" not in u else route.abort()
                    p.route("**/v1/**", empty)
                elif state == "offline":
                    p.route("**/v1/**", lambda r: r.abort("connectionrefused"))
                    p.route("**/healthz", lambda r: r.abort("connectionrefused"))
                else:
                    p.route("**/v1/**", lambda r: r.fulfill(status=401, json={"detail": "not paired"}))
                p.goto(base + f"/?theme={theme}")
                p.wait_for_timeout(2500 if state == "offline" else 900)
                a.check(p, f"{state}-{w}-{theme}")
                c.close()


def pitch(a: Audit, browser, path: str) -> None:
    url = Path(path).resolve().as_uri()
    for (w, h) in ((1280, 720), (1920, 1080)):
        c = browser.new_context(viewport={"width": w, "height": h})
        p = c.new_page()
        p.goto(url)
        n = p.locator(".slide").count()
        for i in range(1, n + 1):
            p.goto("about:blank")
            p.goto(f"{url}#{i}")
            p.wait_for_timeout(300)
            a.check(p, f"pitch-slide{i}-{w}")
        c.close()


def web(a: Audit, browser, base: str, scenarios: list[str]) -> None:
    for (w, h) in ((390, 844), (1280, 720), (1920, 1080)):
        c = browser.new_context(viewport={"width": w, "height": h})
        p = c.new_page()
        p.goto(base + "/")
        p.wait_for_timeout(1200)
        if not p.locator("#tour").is_hidden():
            for i in range(5):
                a.check(p, f"web-guide-step{i + 1}-{w}")
                p.click("#tour-next")
            p.wait_for_timeout(300)
        a.check(p, f"web-idle-{w}")
        p.click("#tab-demo")
        p.wait_for_timeout(500)
        a.check(p, f"web-demo-idle-{w}")
        if w != 1280:
            c.close()
            continue
        for scn in scenarios:
            p.goto(base + f"/?scenario={scn}#demo")
            p.wait_for_timeout(800)
            for guarded, btn in ((False, "#run-off"), (True, "#run-on")):
                p.click(btn)
                p.wait_for_function("document.getElementById('run-on') && !document.getElementById('run-on').disabled", timeout=120000)
                p.wait_for_timeout(400)
                a.check(p, f"web-{scn}-{'on' if guarded else 'off'}-{w}")
        p.click("#tab-live")
        p.wait_for_timeout(400)
        a.check(p, "web-back-to-live-1280")
        c.close()
    # Try your own attack: the panel idle, after each run, and after "understood nothing", at phone and laptop width.
    for (w, h) in ((390, 844), (1280, 720)):
        c = browser.new_context(viewport={"width": w, "height": h})
        p = c.new_page()
        p.goto(base + "/?scenario=custom")
        p.wait_for_timeout(800)
        a.check(p, f"web-custom-idle-{w}")
        for place in ("repo", "inbox", "web"):
            p.click(f"[data-place={place}]")
            for btn in ("#run-off", "#run-on"):
                p.click(btn)
                p.wait_for_function("!document.getElementById('run-on').disabled", timeout=120000)
                p.wait_for_timeout(300)
                a.check(p, f"web-custom-{place}-{btn[5:]}-{w}")
        p.fill("#c-text", "The weather is nice today. " * 30)
        p.click("#run-off")
        p.wait_for_function("!document.getElementById('run-on').disabled", timeout=120000)
        a.check(p, f"web-custom-nothing-{w}")
        c.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="dashboard daemon, e.g. http://127.0.0.1:7797 (already fed by demo/run_demo.py)")
    ap.add_argument("--special", action="store_true", help="also the empty, offline and not-paired states (API intercepted; needs --base)")
    ap.add_argument("--pitch", help="docs/pitch/index.html")
    ap.add_argument("--web", help="hosted demo served locally, e.g. http://127.0.0.1:7798 (with /api/run)")
    ap.add_argument("--scenarios", default="legit,injected-doc,injected-web,sensitive-data,beyond-permission")
    ap.add_argument("--quick", action="store_true", help="dashboard at 390 and 1280 only")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    a = Audit(Path(args.out))
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        if args.base:
            print("dashboard")
            dashboard(a, browser, args.base.rstrip("/"), widths=[(390, 844), (1280, 720)] if args.quick else WIDTHS)
        if args.special and args.base:
            print("empty / offline / not paired")
            dashboard_special(a, browser, args.base.rstrip("/"))
        if args.pitch:
            print("pitch deck")
            pitch(a, browser, args.pitch)
        if args.web:
            print("hosted demo")
            web(a, browser, args.web.rstrip("/"), args.scenarios.split(","))
        browser.close()
    return a.done()


if __name__ == "__main__":
    sys.exit(main())
