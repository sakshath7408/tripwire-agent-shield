"""Record the backup demo video: the real dashboard and the real terminal, nothing faked.

    uv run --with playwright python scripts/record_demo.py      # first time: uv run --with playwright playwright install chromium

It starts its own daemon on a scratch port with a throwaway HOME (your real ~/.tripwire/audit.db is never
touched), then:
  1. runs Act 1 (injected-doc, no guard) and captures the terminal and the attacker's inbox as they happen
  2. records the dashboard in presenter mode (1280x720, balanced autonomy) while Act 2 runs for injected-doc
     (no questions: the six injected calls are blocked on their own, the typo fix and tests go through), then
     beyond-permission (the wire transfer and the command are blocked by the role; the summary save waits for a
     click on "Always allow this", which Tripwire allows once but refuses to learn because the inbox carried
     hidden instructions)
  3. replays the captured terminal output, with its real timing, in an HTML terminal page and records that
Outputs in docs/demo-video/: tripwire-demo.webm (dashboard), tripwire-terminal.webm (terminal story),
tripwire-terminal.png (still), and .mp4 + tripwire-demo.gif when an ffmpeg binary is available (imageio-ffmpeg
from PyPI works: uv run --with playwright --with imageio-ffmpeg python scripts/record_demo.py).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))
import attacker_view  # noqa: E402

OUT = ROOT / "docs" / "demo-video"
W, H = 1280, 720

# A visible pointer, so viewers see where the presenter clicks (Playwright videos have no cursor).
CURSOR_JS = """
window.addEventListener('DOMContentLoaded', () => {
  const c = document.createElement('div'); c.id = '__cursor';
  c.style.cssText = 'position:fixed;left:640px;top:360px;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;'
    + 'background:rgba(20,20,30,.35);border:2px solid #fff;box-shadow:0 0 0 1px rgba(0,0,0,.4);z-index:99999;'
    + 'pointer-events:none;transition:left .7s ease,top .7s ease,transform .15s';
  document.body.appendChild(c);
});
"""


# ---- daemon -----------------------------------------------------------------------------------------
def scratch_env(home: str) -> dict[str, str]:
    """HOME and TRIPWIRE_HOME both point into the throwaway folder, so a TRIPWIRE_HOME or TRIPWIRE_TOKEN set in
    your shell can never point the recording at your real audit log, token or learned rules."""
    env = {k: v for k, v in os.environ.items() if k not in ("TRIPWIRE_TOKEN", "TRIPWIRE_AUTONOMY")}
    return {**env, "HOME": home, "TRIPWIRE_HOME": str(Path(home) / ".tripwire")}


def start_daemon(port: int, home: str) -> subprocess.Popen:
    p = subprocess.Popen([str(ROOT / ".venv" / "bin" / "tripwire"), "serve", "--port", str(port),
                          "--autonomy", "balanced", "--demo-admin"], env=scratch_env(home),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return p
        except OSError:
            time.sleep(0.2)
    p.kill()
    raise SystemExit(f"daemon did not start on port {port}")


# ---- terminal capture -------------------------------------------------------------------------------
class Capture:
    """Runs a command in a pty (so it prints colour) and keeps (t, text) chunks plus attacker-inbox snapshots."""

    def __init__(self, t0: float) -> None:
        self.t0 = t0
        self.chunks: list[tuple[float, str]] = []
        self.inbox: list[tuple[float, str]] = []

    def run(self, cmd: list[str]) -> threading.Thread:
        def go() -> None:
            master, slave = pty.openpty()
            env = {**scratch_env(os.environ["TW_DEMO_HOME"]), "COLUMNS": "120"}
            proc = subprocess.Popen(cmd, cwd=ROOT, stdout=slave, stderr=slave, stdin=subprocess.DEVNULL, env=env)
            os.close(slave)
            last_inbox = None
            while True:
                r, _, _ = select.select([master], [], [], 0.1)
                now = time.monotonic() - self.t0
                inbox = attacker_view.render()
                if inbox != last_inbox:
                    self.inbox.append((now, inbox))
                    last_inbox = inbox
                if r:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        data = b""
                    if not data:
                        break
                    self.chunks.append((now, data.decode("utf-8", "replace").replace("\r", "")))
                elif proc.poll() is not None:
                    break
            proc.wait()
            os.close(master)
        th = threading.Thread(target=go, daemon=True)
        th.start()
        return th


def demo_cmd(*args: str) -> list[str]:
    return [str(ROOT / ".venv" / "bin" / "python"), "demo/run_demo.py", *args]


# ---- dashboard driving ------------------------------------------------------------------------------
def point_and_click(page, target, pause: float = 0.9) -> None:
    loc = (page.locator(target) if isinstance(target, str) else target).first
    box = loc.bounding_box()
    if not box:
        return
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.evaluate("([x,y]) => { const c = document.getElementById('__cursor'); if (c) { c.style.left = x+'px'; c.style.top = y+'px'; } }", [x, y])
    page.wait_for_timeout(int(pause * 1000))
    page.evaluate("() => { const c = document.getElementById('__cursor'); if (c) { c.style.transform='scale(.7)'; setTimeout(()=>c.style.transform='',160); } }")
    loc.click()


def decide(summary: str) -> tuple[str, str | None]:
    """(decision, remember). In balanced mode the only card in the recording is the summary save."""
    s = summary.lower()
    if "ssh" in s or "id_rsa" in s or ".env" in s:
        return "block", None
    return "allow", "always"  # the user's own summary file: show "Always allow this" and Tripwire's answer


def drive_dashboard(page, th: threading.Thread, log: list[str], read_pause: float) -> None:
    handled: set[str] = set()
    while th.is_alive():
        for item in page.locator(".q-item").all():
            try:
                vid = item.get_attribute("data-id", timeout=500)
                summary = item.locator(".q-sum").inner_text(timeout=500)
            except Exception:
                continue
            if not vid or vid in handled:
                continue
            handled.add(vid)
            choice, remember = decide(summary)
            log.append(f"{choice.upper():5}{' (' + remember + ')' if remember else ''} {summary}")
            page.wait_for_timeout(int(read_pause * 1000))  # let the viewer read the card
            sel = f'.q-item [data-resolve="{choice}"][data-id="{vid}"]'
            if remember and page.locator(f'{sel}[data-remember="{remember}"]').count():
                sel += f'[data-remember="{remember}"]'
            elif remember:
                log.append("  (no remember button on the card; plain Allow)")
            point_and_click(page, sel)
            if remember:
                page.wait_for_timeout(4500)  # the toast says whether Tripwire learned it
        page.wait_for_timeout(150)


# ---- terminal page ----------------------------------------------------------------------------------
ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(s: str) -> str:
    out, open_span = [], False
    pos = 0
    for m in ANSI.finditer(s):
        out.append(html.escape(s[pos:m.start()]))
        pos = m.end()
        if open_span:
            out.append("</span>")
            open_span = False
        codes = [c for c in m.group(1).split(";") if c and c != "0"]
        if codes:
            out.append(f'<span class="{" ".join("a" + c for c in codes)}">')
            open_span = True
    out.append(html.escape(s[pos:]))
    if open_span:
        out.append("</span>")
    return "".join(out)


TERM_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Tripwire terminal</title><style>
html,body{margin:0;height:100%;background:#0f1117;color:#d7dae0;font:15px/1.38 Menlo,'SF Mono',Consolas,monospace}
.wrap{display:grid;grid-template-columns:1fr 430px;height:100%}
.pane{overflow:hidden;padding:14px 16px;box-sizing:border-box;display:flex;flex-direction:column}
.pane+.pane{border-left:1px solid #2a2f3a;background:#13151c}
.bar{font:600 12px/1 -apple-system,system-ui,sans-serif;color:#8b93a3;letter-spacing:.06em;text-transform:uppercase;margin-bottom:10px}
pre{margin:0;font:inherit;white-space:pre-wrap;word-break:break-word}
.scr{flex:1;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end}
#inbox .scr{justify-content:flex-start;font-size:13px}
.cap{position:fixed;left:16px;bottom:12px;font:600 15px/1.3 -apple-system,system-ui,sans-serif;background:#ffd84d;color:#111;padding:6px 10px;border-radius:6px;opacity:0;transition:opacity .3s}
.a1{font-weight:700}.a2{opacity:.6}.a31{color:#ff5f5f}.a32{color:#4ee08a}.a33{color:#ffd84d}.a36{color:#5fd7ff}
</style></head><body><div class="wrap">
<div class="pane"><div class="bar">Terminal 3: the agent</div><div class="scr"><pre id="term"></pre></div></div>
<div class="pane" id="inbox"><div class="bar">Terminal 2: attacker's inbox</div><div class="scr"><pre id="drop"></pre></div></div>
</div><div class="cap" id="cap"></div>
<script>
const EV = __EVENTS__;
const term = document.getElementById('term'), drop = document.getElementById('drop'), cap = document.getElementById('cap');
let buf = '';
window.__done = false;
const t0 = performance.now();
EV.forEach(e => setTimeout(() => {
  if (e.k === 't') { buf += e.h; const lines = buf.split('\\n'); term.innerHTML = lines.slice(-34).join('\\n'); }
  else if (e.k === 'i') drop.innerHTML = e.h;
  else if (e.k === 'c') { cap.textContent = e.h; cap.style.opacity = e.h ? 1 : 0; }
  else if (e.k === 'clear') { buf = ''; term.innerHTML = ''; }
  else if (e.k === 'end') window.__done = true;
}, e.t * 1000));
</script></body></html>"""


def build_events(acts: list[tuple[str, Capture, float]], max_gap: float = 2.5) -> list[dict]:
    """Merge captures into one timeline. Long idle gaps (waiting on a click) are capped so the clip stays tight."""
    ev, t = [], 0.6
    for caption, cap, _ in acts:
        ev.append({"t": t, "k": "clear"})
        ev.append({"t": t, "k": "c", "h": caption})
        items = sorted([(ts, "t", ansi_to_html(x)) for ts, x in cap.chunks] +
                       [(ts, "i", ansi_to_html(x)) for ts, x in cap.inbox])
        prev = items[0][0] if items else 0
        for ts, k, h in items:
            t += min(ts - prev, max_gap)
            prev = ts
            ev.append({"t": round(t, 2), "k": k, "h": h})
        t += 3.0
        ev.append({"t": t, "k": "c", "h": ""})
    ev.append({"t": t + 0.3, "k": "end"})
    return ev


# ---- encoding ---------------------------------------------------------------------------------------
def find_ffmpeg() -> str | None:
    exe = shutil.which("ffmpeg")
    if exe:
        return exe
    try:
        import imageio_ffmpeg  # type: ignore
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None


def encode(ff: str, webm: Path) -> list[Path]:
    made = []
    small = webm.with_suffix(".vp9.webm")  # Playwright writes high-bitrate VP8; VP9 is ~5x smaller
    r = subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(webm), "-c:v", "libvpx-vp9", "-b:v", "0",
                        "-crf", "34", "-row-mt", "1", "-deadline", "good", "-cpu-used", "4", str(small)])
    if r.returncode == 0 and small.stat().st_size < webm.stat().st_size:
        small.replace(webm)
    elif small.exists():
        small.unlink()
    mp4 = webm.with_suffix(".mp4")
    r = subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(webm), "-c:v", "libx264", "-pix_fmt", "yuv420p",
                        "-crf", "26", "-preset", "slow", "-movflags", "+faststart", str(mp4)])
    if r.returncode == 0:
        made.append(mp4)
    return made


def make_gif(ff: str, webm: Path, gif: Path, limit_mb: float = 8.0) -> Path | None:
    for width, fps in ((960, 8), (800, 7), (640, 6), (560, 5)):
        vf = (f"fps={fps},scale={width}:-1:flags=lanczos,split[a][b];"
              f"[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle")
        r = subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(webm), "-vf", vf, str(gif)])
        if r.returncode == 0 and gif.stat().st_size < limit_mb * 1e6:
            return gif
    if gif.exists():
        gif.unlink()
    return None


# ---- main -------------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7792)
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between agent steps")
    ap.add_argument("--read-pause", type=float, default=2.2, help="seconds a card stays up before the click")
    a = ap.parse_args()

    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    home = tempfile.mkdtemp(prefix="tw-rec-home-")
    os.environ["TW_DEMO_HOME"] = home
    vids = Path(tempfile.mkdtemp(prefix="tw-rec-vid-"))
    url = f"http://127.0.0.1:{a.port}"
    daemon = start_daemon(a.port, home)
    decisions: list[str] = []
    try:
        # 1. Act 1, terminal only (the dashboard sees nothing without the guard)
        act1 = Capture(time.monotonic())
        act1.run(demo_cmd("--scenario", "injected-doc", "--no-guard", "--delay", str(a.delay))).join()

        with sync_playwright() as p:
            browser = p.chromium.launch()
            # 2. Dashboard video
            ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vids),
                                      record_video_size={"width": W, "height": H})
            ctx.add_init_script(CURSOR_JS)
            # Pair the recording browser with a one-time code. This throwaway daemon runs with --demo-admin (its own
            # HOME); a real daemon has no key a script could use.
            adm = (Path(home) / ".tripwire" / "demo-admin.key").read_text().strip()
            req = urllib.request.Request(f"{url}/v1/pair/new", data=b"", method="POST", headers={"X-Tripwire-Demo-Admin": adm})
            code = json.loads(urllib.request.urlopen(req, timeout=5).read())["code"]
            page = ctx.new_page()
            page.request.post(f"{url}/v1/pair", data={"code": code}, headers={"Origin": url})
            page.goto(f"{url}/?stage=1&theme=light&notour")
            page.wait_for_selector("#timeline", state="attached")
            page.wait_for_timeout(2500)
            act2 = Capture(time.monotonic())
            th = act2.run(demo_cmd("--scenario", "injected-doc", "--guard-only", "--delay", str(a.delay),
                                   "--approve", "dashboard", "--url", url))
            drive_dashboard(page, th, decisions, a.read_pause)
            page.wait_for_timeout(3500)
            # first blocked item: show its reason in the detail pane
            blocked = page.locator(".timeline li").filter(has_text=re.compile("email|send_email", re.I))
            if blocked.count():
                point_and_click(page, blocked, pause=0.8)
                page.wait_for_timeout(3500)
            point_and_click(page, "#tab-audit", pause=0.8)
            page.wait_for_timeout(3500)
            point_and_click(page, "#tab-live", pause=0.6)
            page.wait_for_timeout(1000)
            act3 = Capture(time.monotonic())
            th = act3.run(demo_cmd("--scenario", "beyond-permission", "--guard-only", "--delay", str(a.delay * 0.8),
                                   "--approve", "dashboard", "--url", url))
            drive_dashboard(page, th, decisions, a.read_pause)
            page.wait_for_timeout(1500)
            money = page.locator(".timeline li").filter(has_text="send_money")
            if money.count():  # show why the wire transfer was stopped
                point_and_click(page, money, pause=0.8)
            page.wait_for_timeout(4500)
            page.screenshot(path=str(OUT / "tripwire-dashboard.png"))
            dash_video = page.video
            ctx.close()
            dash = OUT / "tripwire-demo.webm"
            shutil.move(dash_video.path(), dash)

            # 3. Terminal story video, replayed from the real captured output
            events = build_events([
                ("Act 1: no guard. The README carries hidden instructions.", act1, 0),
                ("Act 2: same agent with Tripwire. No questions asked: every injected call blocked.", act2, 0),
                ("Beyond permission: inbox assistant told to wire $4,900. It asks once: the summary save.", act3, 0),
            ])
            page_html = Path(vids) / "terminal.html"
            page_html.write_text(TERM_PAGE.replace("__EVENTS__", json.dumps(events)))
            ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vids),
                                      record_video_size={"width": W, "height": H})
            tpage = ctx.new_page()
            tpage.goto(page_html.as_uri())
            tpage.wait_for_function("window.__done === true", timeout=600_000)
            # still of the end of Act 2 (the interesting frame): rebuild just that act and screenshot
            tvideo = tpage.video
            ctx.close()
            term = OUT / "tripwire-terminal.webm"
            shutil.move(tvideo.path(), term)
            still = browser.new_page(viewport={"width": W, "height": H})
            only2 = build_events([("Act 2: same agent with Tripwire. No questions asked: every injected call blocked.", act2, 0)], max_gap=0)
            only2 = [e for e in only2 if e["k"] != "c"]
            for e in only2:
                e["t"] = 0
            still.goto("about:blank")
            still.set_content(TERM_PAGE.replace("__EVENTS__", json.dumps(only2)))
            still.wait_for_function("window.__done === true")
            still.screenshot(path=str(OUT / "tripwire-terminal.png"))
            browser.close()
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
        shutil.rmtree(home, ignore_errors=True)

    made = [dash, term, OUT / "tripwire-dashboard.png", OUT / "tripwire-terminal.png"]
    ff = find_ffmpeg()
    if ff:
        made += encode(ff, dash) + encode(ff, term)
        gif = make_gif(ff, dash, OUT / "tripwire-demo.gif")
        if gif:
            made.append(gif)
    else:
        print("no ffmpeg found: skipped .mp4 and .gif")
    shutil.rmtree(vids, ignore_errors=True)
    print("dashboard clicks:", *decisions, sep="\n  ")
    for f in made:
        print(f"{f.relative_to(ROOT)}  {f.stat().st_size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
