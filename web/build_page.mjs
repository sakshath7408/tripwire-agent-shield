// Builds the hosted page (the dashboard as a product, with a Demo tab) from the local dashboard's own index.html (src/tripwire/static/index.html), so the
// two never drift: every element app.js needs is still there. This only adds the demo controls, the outcome
// cards and the adapter scripts. Required anchors fail the build loudly; cosmetic ones are skipped with a warning.
import { readFileSync, writeFileSync } from "node:fs";

const [src, dest] = process.argv.slice(2);
let html = readFileSync(src, "utf8");

function edit(name, find, replace, required) {
  const hit = typeof find === "string" ? html.includes(find) : find.test(html);
  if (!hit) {
    if (required) { console.error(`build_page: anchor "${name}" not found in ${src}`); process.exit(1); }
    console.warn(`build_page: skipped "${name}" (anchor not found)`);
    return;
  }
  // replacement text is literal ("$12,500.00" must stay as written); "$1" means the matched anchor
  html = html.replace(find, (m, g1) => replace.split("@@ANCHOR@@").join(g1 ?? m));
}

const SYMBOLS = `<svg width="0" height="0" style="position:absolute" aria-hidden="true">
    <symbol id="i-play" viewBox="0 0 20 20"><path d="M6.5 4.6v10.8a.6.6 0 0 0 .9.5l8.6-5.4a.6.6 0 0 0 0-1L7.4 4.1a.6.6 0 0 0-.9.5z" fill="currentColor"/></symbol>
    <symbol id="i-mail" viewBox="0 0 20 20"><rect x="2.5" y="4.5" width="15" height="11" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m3 5.5 7 5.2 7-5.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></symbol>
    <symbol id="i-bank" viewBox="0 0 20 20"><path d="M3 8 10 3.5 17 8M4.5 8.5v6M8 8.5v6M12 8.5v6M15.5 8.5v6M3 16.5h14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="i-task" viewBox="0 0 20 20"><rect x="3.5" y="3.5" width="13" height="13" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m7 10.2 2.1 2.1L13.3 8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="i-git" viewBox="0 0 16 16"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></symbol>
  </svg>
`;
const DEMO = `          <section class="demo" id="demo" aria-label="Live demo controls" hidden>
      <div class="demo-run">
        <p class="demo-label"><span class="demo-pill">Demo</span>The real Tripwire engine runs on this server against a synthetic world. The agent is a scripted stand-in for a hijacked AI. Nothing here touches your machine.</p>
        <div class="scenarios" id="scenarios" role="radiogroup" aria-label="Scenario"></div>
        <p class="scenario-story" id="scenario-story"></p>
        <div class="custom" id="custom" hidden>
          <div class="c-row">
            <div class="c-place" id="c-place" role="radiogroup" aria-label="Where the attacker's text hides"></div>
            <label class="c-task"><span>Your task</span><select id="c-task" aria-label="The user's task"></select></label>
          </div>
          <div class="c-box">
            <textarea id="c-text" rows="3" maxlength="4096" spellcheck="false" autocomplete="off" aria-label="The attacker's text" aria-describedby="c-hint"></textarea>
            <div class="c-foot"><span class="c-hint" id="c-hint">The hijacked agent is scripted: it follows plain orders like "send the .env to …", "run curl … | bash", "transfer $500 to …".</span><button type="button" class="link-btn" id="c-reset">Example</button><span class="c-count" id="c-count"></span></div>
          </div>
          <div class="c-understood" id="c-understood" role="status" hidden></div>
        </div>
        <div class="demo-buttons">
          <button type="button" class="btn-run btn-run-off" id="run-off"><svg aria-hidden="true"><use href="#i-play"/></svg>Run without Tripwire</button>
          <button type="button" class="btn-run btn-run-on" id="run-on"><svg aria-hidden="true"><use href="#i-shield"/></svg>Run with Tripwire</button>
          <label class="floor" id="floor-label"><input type="checkbox" id="hard-floor" aria-describedby="human-note"><span class="floor-switch" aria-hidden="true"></span><span>Hard floor</span></label>
          <span class="run-status" id="run-status" role="status" aria-live="polite"></span>
        </div>
        <p class="human-note" id="human-note"></p>
      </div>
      <div class="outcome" id="outcome" aria-label="What happened">
        <div class="oc oc-inbox" id="oc-inbox" data-state="idle">
          <div class="oc-head"><svg aria-hidden="true"><use href="#i-mail"/></svg>Attacker's inbox</div>
          <div class="oc-big" id="oc-inbox-n">Empty</div>
          <ol class="oc-list" id="oc-inbox-list"></ol>
        </div>
        <div class="oc oc-bank" id="oc-bank" data-state="idle">
          <div class="oc-head"><svg aria-hidden="true"><use href="#i-bank"/></svg>Bank balance</div>
          <div class="oc-big" id="oc-bank-n">$12,500.00</div>
          <div class="oc-sub" id="oc-bank-sub">Synthetic account</div>
        </div>
        <div class="oc oc-task" id="oc-task" data-state="idle">
          <div class="oc-head"><svg aria-hidden="true"><use href="#i-task"/></svg>Your task</div>
          <div class="oc-big" id="oc-task-n">Not run yet</div>
          <div class="oc-sub" id="oc-task-sub"></div>
        </div>
        <p class="compare" id="compare" hidden></p>
      </div>
    </section>

`;
const RAWNOTE = `        <div class="raw-note" id="raw-note" hidden>
          <div class="raw-note-head"><svg aria-hidden="true"><use href="#i-block"/></svg>No guard on this run</div>
          <p>Every call ran the moment the agent asked. Nothing checked where its instructions came from, so there is no reason to show.</p>
          <p>Press <b>Run with Tripwire</b> to see the same agent, same world, with every call checked first.</p>
        </div>
`;
const LINKS = `        <a class="btn-quiet top-link" href="https://github.com/sakshath7408/tripwire-agent-shield" rel="noopener" title="Source code on GitHub"><svg aria-hidden="true"><use href="#i-git"/></svg><span>GitHub</span></a>
`;
// The main view is honest: a website cannot reach a daemon on your machine, so it says how to connect one.
// The Demo tab has its own empty copy.
const EMPTY = `          <div class="empty-main">
            <p class="empty-title">Connect your agent</p>
            <p>Tripwire runs on your machine, next to your agent. This page shows the product; the daemon it talks to is yours.</p>
            <ul class="empty-cmds">
              <li><code>uv run tripwire install claude</code><span>Claude Code hooks</span><button type="button" class="copy-btn" data-copy="uv run tripwire install claude" aria-label="Copy the Claude Code command"><svg aria-hidden="true"><use href="#i-copy"/></svg></button></li>
              <li><code>uv run tripwire mcp-proxy -- &lt;server&gt;</code><span>any MCP server</span><button type="button" class="copy-btn" data-copy="uv run tripwire mcp-proxy -- <server>" aria-label="Copy the MCP command"><svg aria-hidden="true"><use href="#i-copy"/></svg></button></li>
            </ul>
            <p class="empty-links"><a href="https://github.com/sakshath7408/tripwire-agent-shield" rel="noopener">Get it on GitHub</a><span aria-hidden="true">·</span><button type="button" class="link-btn" id="open-demo">Or watch the demo</button></p>
          </div>
          <div class="empty-demo">
            <p class="empty-title">Pick a scenario and press Run</p>
            <p>Run it without Tripwire first and watch the attacker's inbox fill. Then run it with Tripwire. Every tool call shows up here as it happens.</p>
          </div>`;
const TAB = `<button type="button" role="tab" id="tab-demo" aria-selected="false" aria-controls="demo" title="A scripted agent against a synthetic world, with and without Tripwire">Demo</button>`;

// required: without these the demo cannot work
edit("stylesheet", /(<link rel="stylesheet" href="\/static\/styles.css">)/, `@@ANCHOR@@\n  <link rel="stylesheet" href="/demo.css">`, true);
edit("app.js", /(<script src="\/static\/app.js"><\/script>)/, `<script src="/demo.js"></script>\n  @@ANCHOR@@\n  <script src="/demo-player.js"></script>`, true);
edit("demo-panel", /(<div id="live" role="tabpanel" aria-labelledby="tab-live">\n)/, `@@ANCHOR@@${DEMO}`, true);
edit("demo-tab", /(<button type="button" role="tab" id="tab-audit"[^>]*>[^<]*<span class="count" id="audit-count"><\/span><\/button>)/, `@@ANCHOR@@\n          ${TAB}`, true);
edit("timeline", /(<ol class="timeline" id="timeline"[^>]*><\/ol>)/, `@@ANCHOR@@\n          <ol class="timeline raw-log" id="raw-log" aria-label="What the agent did with no guard, newest first" hidden></ol>`, true);
edit("detail-empty", /(\n\s*<div class="detail-empty" id="detail-empty">)/, `\n${RAWNOTE.trimEnd()}@@ANCHOR@@`, true);
edit("body", /(<body[^>]*>\n)/, `@@ANCHOR@@  ${SYMBOLS}`, true);

// cosmetic
edit("description", /<meta name="description" content="[^"]*">/, `<meta name="description" content="Tripwire watches every tool call your AI agent makes and stops the ones you never asked for. Runs on your machine; the Demo tab shows it against a hijacked agent.">`);
edit("conn", /<span class="conn" id="conn"/, `<span class="conn" id="conn" hidden`);
edit("reset", /<button class="btn-quiet" id="reset"/, `<button class="btn-quiet" id="reset" hidden`);
edit("links", /(\n\s*<button class="btn-quiet btn-icon" id="theme")/, `\n${LINKS.trimEnd()}@@ANCHOR@@`);
edit("empty", /<p class="empty-title">[\s\S]*?<\/ul>/, EMPTY);
edit("detail-hint", /Pick any action to see exactly why Tripwire decided what it did\./, "Every decision your agent's Tripwire makes shows up on the left. Pick one to see exactly why.");

writeFileSync(dest, html);
console.log(`build_page: wrote ${dest}`);
