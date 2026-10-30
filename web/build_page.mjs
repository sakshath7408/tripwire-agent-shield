// Builds the hosted demo page from the local dashboard's own index.html (src/tripwire/static/index.html), so the
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
    <symbol id="i-deck" viewBox="0 0 20 20"><rect x="2.5" y="3.5" width="15" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 13.5v3M7 16.5h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></symbol>
  </svg>
`;
const DEMO = `    <section class="demo" aria-label="Live demo controls">
      <div class="demo-run">
        <p class="demo-label"><span class="demo-pill">Live demo</span>Real Tripwire engine running on this server against a synthetic world. The agent is a scripted stand-in for a hijacked AI.</p>
        <div class="scenarios" id="scenarios" role="radiogroup" aria-label="Scenario"></div>
        <p class="scenario-story" id="scenario-story"></p>
        <div class="demo-buttons">
          <button type="button" class="btn-run btn-run-off" id="run-off"><svg aria-hidden="true"><use href="#i-play"/></svg>Run without Tripwire</button>
          <button type="button" class="btn-run btn-run-on" id="run-on"><svg aria-hidden="true"><use href="#i-shield"/></svg>Run with Tripwire</button>
          <span class="run-status" id="run-status" role="status" aria-live="polite"></span>
        </div>
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
const LINKS = `        <a class="btn-quiet top-link" href="/pitch" title="The pitch deck"><svg aria-hidden="true"><use href="#i-deck"/></svg><span>Pitch</span></a>
        <a class="btn-quiet top-link" href="https://github.com/sakshath7408/tripwire-agent-shield" rel="noopener" title="Source code on GitHub"><svg aria-hidden="true"><use href="#i-git"/></svg><span>GitHub</span></a>
`;
const EMPTY = `          <p class="empty-title">Pick a scenario and press Run</p>
          <p>Run it without Tripwire first and watch the attacker's inbox fill. Then run it with Tripwire. Every tool call shows up here as it happens.</p>
          <ul class="empty-cmds">
            <li><code>uv sync</code><span>after cloning the repo</span></li>
            <li><code>uv run tripwire serve</code><span>local dashboard</span></li>
          </ul>`;

// required: without these the demo cannot work
edit("stylesheet", /(<link rel="stylesheet" href="\/static\/styles.css">)/, `@@ANCHOR@@\n  <link rel="stylesheet" href="/demo.css">`, true);
edit("app.js", /(<script src="\/static\/app.js"><\/script>)/, `<script src="/demo.js"></script>\n  @@ANCHOR@@\n  <script src="/demo-player.js"></script>`, true);
edit("brief", /(\n\s*<section class="brief")/, `\n${DEMO.trimEnd()}@@ANCHOR@@`, true);
edit("timeline", /(<ol class="timeline" id="timeline"[^>]*><\/ol>)/, `@@ANCHOR@@\n          <ol class="timeline raw-log" id="raw-log" aria-label="What the agent did with no guard, newest first" hidden></ol>`, true);
edit("detail-empty", /(\n\s*<div class="detail-empty" id="detail-empty">)/, `\n${RAWNOTE.trimEnd()}@@ANCHOR@@`, true);
edit("body", /(<body[^>]*>\n)/, `@@ANCHOR@@  ${SYMBOLS}`, true);

// cosmetic
edit("title", /<title>[^<]*<\/title>/, "<title>Tripwire live demo</title>");
edit("description", /<meta name="description" content="[^"]*">/, `<meta name="description" content="Live demo: the real Tripwire engine checks a hijacked agent's tool calls against a synthetic world. Run it without Tripwire, then with it.">`);
edit("conn", /<span class="conn" id="conn"/, `<span class="conn" id="conn" hidden`);
edit("reset", /<button class="btn-quiet" id="reset"/, `<button class="btn-quiet" id="reset" hidden`);
edit("links", /(\n\s*<button class="btn-quiet btn-icon" id="theme")/, `\n${LINKS.trimEnd()}@@ANCHOR@@`);
edit("empty", /<p class="empty-title">[\s\S]*?<\/ul>/, EMPTY);

writeFileSync(dest, html);
console.log(`build_page: wrote ${dest}`);
