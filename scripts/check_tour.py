"""Regression check for the first-open guide: keys and clicks finish it, and it stays closed.
Needs a daemon on :7777, or pass its URL: check_tour.py http://127.0.0.1:7790"""
import sys
from playwright.sync_api import sync_playwright
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:7777"
with sync_playwright() as p:
    for eng in ("chromium","webkit"):
        b = getattr(p, eng).launch(); pg = b.new_page(viewport={"width":1440,"height":900})
        pg.goto(BASE + "/"); pg.wait_for_timeout(1200)
        for i in range(7):
            if not pg.locator("#tour").is_visible(): break
            pg.keyboard.press("ArrowRight"); pg.wait_for_timeout(400)
        arrow_closed = not pg.locator("#tour").is_visible()
        pg.evaluate("localStorage.clear()"); pg.reload(); pg.wait_for_timeout(1200)
        for i in range(6):
            if not pg.locator("#tour").is_visible(): break
            pg.click("#tour-next"); pg.wait_for_timeout(300)
        click_closed = not pg.locator("#tour").is_visible()
        pg.reload(); pg.wait_for_timeout(1200)
        print(eng, "| arrow keys close it:", arrow_closed, "| clicks close it:", click_closed, "| stays closed after reload:", not pg.locator("#tour").is_visible())
        # Tips follow the first-open guide once: keys finish them, clicks finish them, Skip ends them, none after a reload.
        pg.evaluate("localStorage.clear()"); pg.reload(); pg.wait_for_timeout(1200)
        for i in range(7):
            if not pg.locator("#tour").is_visible(): break
            pg.keyboard.press("ArrowRight"); pg.wait_for_timeout(300)
        pg.wait_for_timeout(1200)
        tips_shown = pg.locator("#coach").is_visible()
        for i in range(12):
            if not pg.locator("#coach").is_visible(): break
            pg.keyboard.press("ArrowRight"); pg.wait_for_timeout(450)
        tips_keys = tips_shown and not pg.locator("#coach").is_visible()
        pg.evaluate("localStorage.clear()"); pg.reload(); pg.wait_for_timeout(1200)
        for i in range(7):
            if not pg.locator("#tour").is_visible(): break
            pg.click("#tour-next"); pg.wait_for_timeout(300)
        pg.wait_for_timeout(1200)
        for i in range(12):
            if not pg.locator("#coach").is_visible(): break
            pg.click("#coach-next"); pg.wait_for_timeout(450)
        tips_clicks = not pg.locator("#coach").is_visible()
        pg.evaluate("localStorage.removeItem('tw-tips-seen')"); pg.click("#help"); pg.click("#help-tips"); pg.wait_for_timeout(700)
        pg.click("#coach-skip"); pg.wait_for_timeout(300)
        tips_skip = not pg.locator("#coach").is_visible()
        pg.reload(); pg.wait_for_timeout(1500)
        print(eng, "| tips shown after guide:", tips_shown, "| keys finish tips:", tips_keys, "| clicks finish tips:", tips_clicks, "| Skip ends tips:", tips_skip, "| no tips after reload:", not pg.locator("#coach").is_visible())
        b.close()
