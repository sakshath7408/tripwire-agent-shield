/* Tripwire dashboard. Plain JS, no build step, no network beyond this daemon. */
(() => {
  "use strict";

  // ---- state ---------------------------------------------------------------
  const S = {
    verdicts: new Map(), // id -> verdict
    order: [], // ids, newest first
    sessions: [],
    stats: null,
    session: null, // selected session id
    followSession: true, // pick newest session until the user chooses one
    selected: null, // selected verdict id
    manualPickAt: 0,
    held: new Set(), // ask ids an agent is actively waiting on
    deadlines: new Map(), // id -> epoch ms when the server auto-blocks
    injectSrc: new Map(), // session id -> tool where hidden instructions were seen
    fresh: new Set(), // ids that arrived live, for the arrival animation
    firstSeen: new Map(), // id -> epoch ms when we first saw a deadline, so the countdown bar has a start
    view: "live",
    agent: null, // agent filter (null = everyone)
    auditView: "list", // "list" | "tree"
    chain: null, // last /v1/audit/verify answer
    tree: null, // last /v1/audit?format=tree answer
    history: new Map(), // verdict id -> chained records (verdict + resolutions)
    mode: document.documentElement.dataset.mode === "detailed" ? "detailed" : "simple",
    settings: null, // {autonomy} from /v1/settings, null when the daemon has no such endpoint (hosted demo)
    rules: null, // learned rules from /v1/rules
  };
  const simple = () => S.mode === "simple";

  const $ = (id) => document.getElementById(id);
  const el = {
    task: $("task"), cwd: $("cwd"), profile: $("profile"), sessions: $("sessions"), conn: $("conn"),
    reset: $("reset"), inject: $("inject"), injectText: $("inject-text"), timeline: $("timeline"),
    empty: $("empty"), queue: $("queue"), queueList: $("queue-list"), queueTitle: $("queue-title"),
    detail: $("detail"), detailBody: $("detail-body"), detailEmpty: $("detail-empty"), toast: $("toast"),
    tabLive: $("tab-live"), tabAudit: $("tab-audit"), live: $("live"), audit: $("audit"),
    auditRows: $("audit-rows"), auditNote: $("audit-note"), exportBtn: $("export"), auditCount: $("audit-count"),
    nAllow: $("n-allow"), nAsk: $("n-ask"), nBlock: $("n-block"), msNote: $("ms-note"),
    story: $("story"), storyText: $("story-text"), offline: $("offline"), announce: $("announce"),
    theme: $("theme"), stage: $("stage"),
    chain: $("chain"), chainLive: $("chain-live"), degraded: $("degraded"), degradedText: $("degraded-text"),
    agentFilter: $("agent-filter"), agentFilterText: $("agent-filter-text"),
    auditListTab: $("audit-list-tab"), auditTreeTab: $("audit-tree-tab"), auditTree: $("audit-tree"), auditList: $("audit-list"),
    modeSeg: $("mode-seg"), help: $("help"), settingsWrap: $("settings-wrap"), settingsBtn: $("settings-btn"), settingsPop: $("settings-pop"),
    autonomySeg: $("autonomy-seg"), autonomyHint: $("autonomy-hint"), rulesList: $("rules-list"), rulesCount: $("rules-count"), rulesEmpty: $("rules-empty"),
    tour: $("tour"),
  };
  const phone = window.matchMedia("(max-width: 820px)");

  // ---- helpers -------------------------------------------------------------
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const icon = (name, cls = "") => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const WORD = { allow: "Allowed", ask: "Needs your OK", block: "Blocked" };
  const isPending = (v) => v.decision === "ask" && !v.resolved_by;
  const lvl = (n) => (n >= 80 ? "high" : n >= 50 ? "mid" : n > 0 ? "low" : "none");

  const UNPAIRED = "Not connected. Run \"tripwire open\" in your terminal to connect this browser.";
  /** One-time pairing: `tripwire serve` / `tripwire open` link here with #pair=<code>. The code is spent
      before any other /v1 call and never stays in the URL. */
  async function pairFromHash() {
    const m = location.hash.match(/(?:^#|&)pair=([^&]+)/);
    if (!m) return;
    history.replaceState(null, "", location.pathname + location.search);
    try {
      const r = await fetch("/v1/pair", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: decodeURIComponent(m[1]) }) });
      if (!r.ok) toast(r.status === 404 ? "This Tripwire does not need pairing." : "That pairing link was already used or has expired. Run \"tripwire open\" in a terminal for a fresh one.", 6000);
    } catch (_) { /* the daemon is down; the usual offline banner covers it */ }
  }
  async function api(path, opts = {}) {
    let r;
    try { r = await fetch(path, { headers: { "content-type": "application/json" }, ...opts }); } // same-origin: the pairing cookie rides along
    catch (_) { throw new Error("Tripwire is not reachable."); } // not "Failed to fetch" / "Load failed"
    if (r.status === 401) { const e = new Error(UNPAIRED); e.status = 401; throw e; }
    if (!r.ok) {
      // Show the server's own sentence ({"detail": "..."}), never a status code with raw JSON after it.
      const text = await r.text().catch(() => "");
      let msg = "";
      try { const d = JSON.parse(text).detail; msg = typeof d === "string" ? d : ""; } catch (_) { /* not JSON */ }
      const e = new Error(msg || (r.status >= 500 ? "Tripwire hit an error. Try again." : `The request was refused (${r.status}).`));
      e.status = r.status;
      throw e;
    }
    return r.json();
  }

  function fmtTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  }
  function fmtMs(ms) {
    if (ms == null) return "";
    return ms < 10 ? ms.toFixed(2) : ms < 100 ? ms.toFixed(1) : Math.round(ms).toString();
  }

  function toolParts(tool) {
    if (tool.startsWith("mcp__")) {
      const bits = tool.split("__");
      return { name: bits[bits.length - 1], server: bits.slice(1, -1).join("/") };
    }
    return { name: tool, server: "" };
  }
  const toolLabel = (tool) => {
    const t = toolParts(tool);
    return t.server ? `${t.server} ${t.name}` : t.name;
  };

  function relPath(p, cwd) {
    if (!p) return p;
    if (cwd && p === cwd) return "the project folder";
    if (cwd && p.startsWith(cwd + "/")) return p.slice(cwd.length + 1);
    return p;
  }

  const first = (args, keys) => {
    for (const k of keys) if (typeof args[k] === "string" && args[k]) return args[k];
    for (const k of keys) if (Array.isArray(args[k]) && args[k].length) return args[k].join(", ");
    return null;
  };

  /** A short human rendering of what the tool call does. */
  function renderAct(v) {
    const a = v.action.args || {};
    const cwd = v.action.cwd;
    const cmd = first(a, ["command", "cmd", "script", "code"]);
    if (cmd) return "$ " + cmd;
    const to = first(a, ["to", "recipient", "recipients", "email", "channel", "user", "iban", "account"]);
    if (to) {
      const subj = first(a, ["subject", "title"]);
      const amount = a.amount != null ? ` ${a.amount}${a.currency ? " " + a.currency : ""}` : "";
      return `To ${to}${amount}${subj ? `  "${subj}"` : ""}`;
    }
    const url = first(a, ["url", "uri", "endpoint"]);
    if (url) return url;
    const pattern = first(a, ["pattern", "query", "q"]);
    const path = first(a, ["file_path", "path", "notebook_path", "filename", "file", "target", "destination", "source"]);
    if (pattern) return `"${pattern}"${path ? " in " + (relPath(path, cwd) || ".") : ""}`;
    if (path) return relPath(path, cwd);
    const json = JSON.stringify(a);
    if (json === "{}") return NO_ARGS[String(v.action.tool || "").toLowerCase()] || humanTool(v.action.tool);
    return json.length > 160 ? json.slice(0, 157) + "..." : json;
  }

  // Tools that take no arguments read better as what they do than as "(no arguments)".
  const NO_ARGS = { read_inbox: "Read your inbox", get_inbox: "Read your inbox", list_emails: "Read your inbox",
    get_balance: "Check your balance", get_unread_emails: "Read your unread emails" };
  function humanTool(tool) {
    const n = toolParts(String(tool || "tool")).name.replace(/[_-]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").trim().toLowerCase();
    return n ? n[0].toUpperCase() + n.slice(1) : "Tool call";
  }

  const CAPWORD = { read: "file read", write: "file edit", exec: "command", fetch: "web fetch", send: "message",
    money: "payment", delete: "delete", agent: "sub-agent", unknown: "tool call" };

  /** Summary without the decision prefix (the badge already says it) or the judge's note (shown on its own). */
  function cleanSummary(v) {
    let s = v.summary || "";
    s = s.replace(/^(Blocked|Needs your OK|Allowed):\s*/, "");
    // "Blocked on its own: hidden instructions..." repeats the badge and the "Decided on its own" line next to it.
    s = s.replace(/^(?:Blocked|Allowed) on its own:\s*(\S)/, (_, c) => c.toUpperCase());
    s = s.replace(/\s*Judge:\s.*$/, "");
    const m = s.match(/^Looks like a normal (\w+) action\.(.*)$/);
    // "file read" is wrong for an inbox or a balance: say "read" when the call names no file.
    const fileless = m && m[1] === "read" && !first(v.action.args || {}, ["file_path", "path", "notebook_path", "filename", "file", "pattern"]);
    if (m) s = `Normal ${fileless ? "read" : CAPWORD[m[1]] || m[1]}, nothing risky found.${m[2]}`;
    return s;
  }

  function byText(v) {
    if (v.resolved_by === "human") return v.decision === "allow" ? "Approved by you" : "Blocked by you";
    if (v.auto || v.resolved_by === "rule" || v.rule_id) return v.rule_id ? "Learned rule" : "Decided on its own";
    if (v.resolved_by === "timeout") return "No answer in time, so blocked";
    // Answered with the install token: the terminal prompt, a script, never this page. Say so in plain words.
    if (v.resolved_by === "api-token" || v.resolved_by === "hook-token" || v.resolved_by === "admin" || v.resolved_by === "demo-admin") return v.decision === "allow" ? "Approved outside this page" : "Blocked outside this page";
    if (v.resolved_by) return (v.decision === "allow" ? "Approved by " : "Blocked by ") + v.resolved_by;
    if (judgeDecided(v)) return "Local judge agreed";
    return "";
  }
  const byHtml = (v) => {
    const t = byText(v);
    const auto = v.auto || v.resolved_by === "rule" || v.rule_id;
    return t ? `<span class="by${v.resolved_by === "human" ? " by-you" : ""}${auto ? " by-auto" : ""}" ${auto ? `title="${v.rule_id ? "Allowed by a rule you taught Tripwire" : "Within your autonomy level, so no question was asked"}"` : ""}>${auto ? icon("spark") : ""}${esc(t)}</span>` : "";
  };
  /** It was put to a person (here, in a terminal, or the hosted demo's simulated human), whatever they answered. */
  const wentToHuman = (v) => !!v.resolved_by && v.resolved_by !== "rule" && !v.auto && !v.rule_id;
  const judgeDecided = (v) => v.judge && !v.judge.error && (v.judge.decision === "allow" || v.judge.decision === "block");

  /** Short session label: "demo-injected-doc-bcc9" -> name "demo-injected-doc", hash "bcc9". */
  function sessionParts(id) {
    const m = String(id).match(/^(.*?)[-_]([0-9a-f]{4,12})$/i);
    return m && m[1] ? { name: m[1], hash: m[2] } : { name: id, hash: "" };
  }

  /** Who acted. The main agent of a session is plain; anything else gets a short label.
      Claude Code sub-agents look like "claude-code:<session>/<type>:<id>", MCP servers like "mcp:<name>". */
  function agentInfo(agent, session) {
    if (!agent || agent === session) return null;
    const a = String(agent);
    let m = a.match(/\/([^/:]+):([^/]+)$/);
    if (m) return { id: a, kind: "sub-agent", name: m[1], short: `sub-agent: ${m[1]}` };
    m = a.match(/^mcp:(.+)$/);
    if (m) return { id: a, kind: "mcp", name: m[1], short: `mcp: ${m[1]}` };
    m = a.match(/^claude-code:(.+)$/);
    if (m && m[1] === session) return null;
    const name = sessionParts(a.includes(":") ? a.slice(a.indexOf(":") + 1) : a).name;
    return { id: a, kind: "agent", name, short: `agent: ${name}` };
  }
  const agentOf = (v) => agentInfo(v.action.agent, v.action.session_id);
  const agentName = (id) => { const i = agentInfo(id, null); return i ? i.name : sessionParts(id).name; };
  function agentChip(v, extra = "") {
    const a = agentOf(v);
    if (!a) return "";
    return `<button type="button" class="agent-chip${extra}" data-agent="${esc(a.id)}" title="Only show what ${esc(a.short)} did">${icon("agent")}${esc(a.short)}</button>`;
  }

  const CAPDO = { read: "read a secret", write: "change files", exec: "run commands", fetch: "pull in outside content",
    send: "send data out", money: "move money", delete: "delete data", agent: "start another agent", credential: "change credentials", unknown: "use an unknown tool" };

  /** Did this session (or, with no session, any session) read hidden instructions? Then it is never "All clear". */
  function hiddenSeen(sess) {
    if (!sess) return !!(S.stats && S.stats.hidden_instructions_seen);
    return !!(sess.hidden_instructions_seen || sess.injection_seen > 0 || (sess.injections || []).length || S.injectSrc.has(sess.id));
  }
  function hiddenSource(sess) {
    const inj = sess && sess.injections && sess.injections.length ? sess.injections[sess.injections.length - 1] : null;
    return (inj && (inj.source || inj.tool)) || (sess && S.injectSrc.get(sess.id)) || "";
  }

  /** One sentence a stranger can read from across the room. */
  function storyFor(sess, vs) {
    if (!vs.length) return null;
    // Counts match the tally above: anything put to a person (answered, or timed out) is not "Tripwire blocked/allowed".
    const stopped = vs.filter((v) => v.decision === "block");
    const blocked = stopped.filter((v) => !wentToHuman(v));
    const pending = vs.filter(isPending);
    const allowed = vs.filter((v) => v.decision === "allow" && !wentToHuman(v));
    const askedBlocked = stopped.length - blocked.length;
    const inj0 = sess && (sess.injections || [])[0];
    const src = (inj0 && (inj0.source || inj0.tool)) || (sess && S.injectSrc.get(sess.id));
    // What the attack asked for: blocked actions, plus pending ones that carry an injection finding. A save the
    // user asked for that merely waits for an OK is not "what the hidden instructions told the agent to do".
    const fromAttack = (v) => (v.findings || []).some((f) => /inject|taint|chain\./.test(f.rule || "") || /inject/i.test(f.category || ""));
    const asked = stopped.concat(pending.filter(fromAttack));
    const tried = [...new Set(asked.slice().reverse().map((v) => CAPDO[v.capability]).filter(Boolean))].slice(0, 3);
    const list = tried.length <= 1 ? tried.join("") : tried.slice(0, -1).join(", ") + " and " + tried[tried.length - 1];
    const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
    if (!stopped.length && !pending.length && hiddenSeen(sess)) {
      // Nothing stopped yet, but the agent has read orders that weren't yours: amber, never "All clear".
      const where = hiddenSource(sess);
      return { warn: true, html: `<b>Hidden instructions found${where ? ` in <mark>${esc(where)}</mark>` : ""}.</b> Nothing blocked yet, watching closely.${allowed.length ? ` <span class="dim">${n(allowed.length, "action", "actions")} so far, all part of your task.</span>` : ""}` };
    }
    if (!stopped.length && !pending.length) {
      return { good: true, html: `<b>All clear.</b> ${n(allowed.length, "action", "actions")} so far, every one part of what you asked.` };
    }
    let html = "";
    if (src && asked.length) html += `<b>Hidden instructions in <mark>${esc(src)}</mark></b> told the agent to ${esc(list || "do things you never asked for")}. `;
    else if (src) html += `<b>Hidden instructions were found in <mark>${esc(src)}</mark>.</b> `;
    else if (!list) { /* only questions, none from an attack: the counts below say it all ("The agent tried to , which...") */ }
    else if (sess && sess.profile) html += `The agent tried to ${esc(list)}, which <b>${esc(sess.profile)}</b> may not do. `;
    else html += `The agent tried to ${esc(list)}, which you never asked for. `;
    if (blocked.length) html += `<b>Tripwire blocked ${pending.length || askedBlocked ? n(blocked.length, "action", "actions") : blocked.length === 1 ? "it" : "all " + blocked.length}.</b> `;
    if (askedBlocked) html += `<b>${blocked.length ? `${askedBlocked} more` : askedBlocked === 1 ? "It was" : `All ${askedBlocked} were`} blocked after asking you.</b> `;
    if (pending.length) html += `<b>${n(pending.length, "action is", "actions are")} waiting for you.</b> `;
    const okd = vs.filter((v) => v.decision === "allow" && wentToHuman(v)).length;
    if (allowed.length) html += `<span class="dim">Your ${n(allowed.length, "task action", "task actions")} went through${okd ? `, and ${okd} more after your OK` : ""}.</span>`;
    else if (okd) html += `<span class="dim">${n(okd, "action", "actions")} went through after your OK.</span>`;
    return { good: false, html };
  }

  function badge(d) {
    return `<span class="badge badge-${d}">${icon(d)}${WORD[d] || d}</span>`;
  }

  function riskHtml(r) {
    return `<span class="risk" data-lvl="${lvl(r)}" title="Risk score ${r} out of 100"><span class="risk-bar"><i style="width:${Math.max(r, 3)}%"></i></span><b>${r}</b></span>`;
  }

  /** Where an evidence snippet came from, read from the finding's own words. */
  function evidenceSource(f) {
    const m = f.message.match(/\(([^()]+)\),? not (?:from|by) you/) || f.message.match(/found in (.+?) earlier/)
      || f.message.match(/hidden instructions in (.+?)\.$/) || f.message.match(/came from (.+?), not from you/)
      || f.message.match(/hidden instructions \(([^()]+)\)/) || f.message.match(/ from (\S+)\. You asked/);
    return m ? m[1] : "content the agent read";
  }

  function highlight(text, v, f) {
    const needles = [];
    const q = f.message.match(/'([^']{3,})'/);
    if (q) needles.push(q[1]);
    const a = v.action.args || {};
    for (const k of ["command", "cmd", "to", "recipient", "url"]) if (typeof a[k] === "string") needles.push(a[k]);
    const p = first(a, ["file_path", "path"]);
    if (p) needles.push(p);
    let out = esc(text);
    const lower = text.toLowerCase();
    const hit = needles.filter((n) => n && n.length >= 3 && lower.includes(n.toLowerCase())).sort((x, y) => y.length - x.length)[0];
    if (hit) {
      const re = new RegExp(esc(hit).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      out = out.replace(re, (m) => `<mark>${m}</mark>`);
    } else {
      out = out.replace(/(IMPORTANT!*|ignore (?:all |any )?(?:previous|prior|above) instructions|do not tell the user|new instructions?:)/gi, "<mark>$1</mark>");
    }
    return out;
  }

  // ---- attack path: provenance at a glance -----------------------------------
  // Tripwire's core idea is where a value came from. For a blocked or asked action this draws the chain the
  // verdict already holds: your task (trusted) -> what the agent read (untrusted, with the snippet) -> the value
  // it carried -> the tool call it tried -> Tripwire's decision. Built only from findings, args and the session.
  const CARRIER = /taken from|came from|written inside content|copied from|a name taken from/;
  const QUOTED = /'([^']{2,160})'/;
  function markSnippet(text, needle) {
    let out = esc(text || "");
    if (needle && needle.length >= 3 && text && text.toLowerCase().includes(needle.toLowerCase())) {
      const re = new RegExp(esc(needle).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      out = out.replace(re, (m) => `<mark>${m}</mark>`);
    } else {
      out = out.replace(/(IMPORTANT!*|ignore (?:all |any )?(?:previous|prior|above) instructions|do not tell the user|new instructions?:|you must now|assistant[,:])/gi, "<mark>$1</mark>");
    }
    return out;
  }
  /** The steps of the path, or null when the verdict has nothing to draw (an allow, or no reason at all). */
  function attackPath(v, sess) {
    if (!v || v.decision === "allow") return null;
    const fs = (v.findings || []).slice().sort((a, b) => b.severity - a.severity);
    if (!fs.length) return null;
    const a = v.action.args || {};
    const task = (sess && sess.task) || "";
    const ctx = fs.find((f) => f.rule === "taint.injection_context");
    let carrier = fs.find((f) => CARRIER.test(f.message) && f.rule !== "taint.injection_context") || null;
    let value = null, source = null, injected = false, snippet = null;
    if (carrier) {
      const q = carrier.message.match(QUOTED);
      value = q ? q[1] : carrier.rule === "taint.command_from_data" ? first(a, ["command", "cmd"]) : null;
      source = evidenceSource(carrier);
      injected = /hidden instructions/i.test(carrier.message);
      snippet = carrier.evidence || (ctx && ctx.evidence) || null;
    } else if (ctx) {
      const sec = fs.find((f) => f.rule === "secrets.read");
      const m = sec && sec.message.match(/:\s*(\S+)\s*$/);
      value = m ? m[1] : null;
      source = evidenceSource(ctx);
      injected = true;
      snippet = ctx.evidence;
      carrier = ctx;
    }
    const trusted = !!(value && task && task.toLowerCase().includes(value.toLowerCase()));
    const steps = [];
    if (source) {
      steps.push({ k: "task", trust: "trusted", kicker: "Your task", text: task || "No task was given", empty: !task });
      steps.push({ k: "source", trust: injected ? "injected" : "untrusted", kicker: injected ? "Hidden instructions in" : "Content the agent read",
        text: source, snippet, value });
      if (value) steps.push({ k: "value", trust: trusted ? "trusted" : "carried", kicker: trusted ? "You named this" : "It carried", text: value });
    }
    steps.push({ k: "tool", trust: "tool", kicker: "The agent tried", text: toolLabel(v.action.tool), sub: renderAct(v) });
    // The decision and one short reason: the strongest finding that is not the carrier or the context line.
    const reason = fs.find((f) => f !== carrier && f.rule !== "taint.injection_context" && !/^Blocked on its own/.test(f.message))
      || carrier || fs[0];
    const pending = isPending(v);
    steps.push({ k: "verdict", trust: v.decision, kicker: "Tripwire", text: pending ? "Needs your OK" : v.decision === "ask" ? (wentToHuman(v) ? "Asked you first" : WORD[v.decision]) : WORD[v.decision],
      sub: reason ? reason.message : cleanSummary(v), rules: [...new Set(fs.map((f) => f.rule))] });
    return { steps, value, source, injected, trusted, simple: !source };
  }
  const PATH_ICON = { task: "user", source: "doc", value: "pin", tool: "agent", verdict: "shield" };
  function pathStepHtml(s, opt) {
    const cls = `path-step path-${s.k} is-${s.trust}${s.empty ? " is-empty" : ""}`;
    const text = s.k === "value" || s.k === "tool" ? `<code class="path-text" title="${esc(s.text)}">${esc(s.text)}</code>` : `<span class="path-text">${esc(s.text)}</span>`;
    const pill = s.trust === "trusted" ? `<span class="path-pill">trusted</span>` : s.trust === "injected" ? `<span class="path-pill">untrusted</span>` : s.trust === "untrusted" ? `<span class="path-pill">untrusted</span>` : "";
    const snippet = s.snippet && !opt.mini ? `<div class="path-snippet">…${markSnippet(s.snippet, s.value)}…</div>` : "";
    const sub = s.sub ? `<div class="path-sub">${esc(s.sub)}</div>` : "";
    const rules = s.rules && !opt.mini && !simple() ? `<div class="path-rules">${s.rules.map((r) => `<span class="rule">${esc(r)}</span>`).join("")}</div>` : "";
    return `<li class="${cls}"><span class="path-dot" aria-hidden="true">${icon(s.trust === "block" ? "block" : s.trust === "ask" ? "ask" : PATH_ICON[s.k])}</span>
      <div class="path-body"><div class="path-kicker">${esc(s.kicker)}${pill}</div>${text}${sub}${snippet}${rules}</div></li>`;
  }
  /** One sentence for screen readers and the audit of the eye. */
  function pathSentence(p) {
    return p.steps.map((s) => `${s.kicker}: ${s.text}${s.sub ? ` (${s.sub})` : ""}`).join(" → ");
  }
  function pathHtml(v, sess, opt = {}) {
    const p = attackPath(v, sess);
    if (!p) return "";
    const cls = `path${opt.mini ? " path-mini" : ""}${p.simple ? " path-short" : ""}${opt.fresh ? " is-live" : ""}`;
    const title = opt.mini ? "" : `<h3>${p.source ? "How it got here" : "What stopped it"}</h3>`;
    const body = `<ol class="${cls}" aria-label="${esc(pathSentence(p))}" style="--n:${p.steps.length}">${p.steps.map((s, i) => pathStepHtml({ ...s }, opt).replace('class="path-step', `style="--i:${i}" class="path-step`)).join("")}</ol>`;
    return opt.mini ? body : `<div class="d-section d-path">${title}${body}</div>`;
  }
  window.TWPath = { html: (v, sess, opt) => pathHtml(v, sess, opt), steps: attackPath };

  function countdownText(id) {
    const dl = S.deadlines.get(id);
    if (!dl) return S.held.has(id) ? "The agent is paused until you answer" : "";
    const left = Math.max(0, Math.round((dl - Date.now()) / 1000));
    return `Blocks on its own in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  }
  function setDeadline(id, epochMs) {
    S.deadlines.set(id, epochMs);
    if (!S.firstSeen.has(id)) S.firstSeen.set(id, Date.now());
  }
  /** 0..100, how much of the wait is left. */
  function timeLeftPct(id) {
    const dl = S.deadlines.get(id), t0 = S.firstSeen.get(id);
    if (!dl || !t0 || dl <= t0) return 100;
    return Math.max(0, Math.min(100, ((dl - Date.now()) / (dl - t0)) * 100));
  }
  const isUrgent = (id) => {
    const dl = S.deadlines.get(id);
    return dl && dl - Date.now() < 15000;
  };

  // ---- data in -------------------------------------------------------------
  function upsert(v, live) {
    const known = S.verdicts.has(v.id);
    S.verdicts.set(v.id, v);
    if (!known) {
      S.order.push(v.id);
      if (live) S.fresh.add(v.id);
    }
    if (v.deadline || v.expires_at) setDeadline(v.id, (v.deadline || v.expires_at) * 1000);
    for (const f of v.findings || []) {
      if (f.rule === "taint.injection_context" && !S.injectSrc.has(v.action.session_id)) {
        const m = f.message.match(/found in (.+?) earlier/);
        if (m) S.injectSrc.set(v.action.session_id, m[1]);
      }
    }
  }
  function sortOrder() {
    S.order.sort((a, b) => S.verdicts.get(b).ts - S.verdicts.get(a).ts);
  }

  function applyStats(st) {
    S.stats = st;
    S.held = new Set();
    for (const p of st.pending || []) {
      if (typeof p === "string") S.held.add(p);
      else if (p && p.id) {
        S.held.add(p.id);
        const dl = p.deadline || p.expires_at;
        if (dl) setDeadline(p.id, dl * 1000);
      }
    }
  }

  async function loadAll() {
    const [vs, st, ss] = await Promise.all([api("/v1/verdicts?limit=500"), api("/v1/stats"), api("/v1/sessions")]);
    S.verdicts.clear();
    S.order = [];
    for (const v of vs) upsert(v, false);
    sortOrder();
    applyStats(st);
    S.sessions = ss;
    pickSession();
    if (!S.selected) autoSelect();
    render();
    verifyChain(0);
    checkHealth();
    loadTree(0);
    if (S.settings === null && !loadAll.settingsTried) { loadAll.settingsTried = true; loadSettings(); }
  }

  let statsT, sessT;
  function refreshStats(delay = 250) {
    clearTimeout(statsT);
    statsT = setTimeout(async () => {
      try { applyStats(await api("/v1/stats")); render(); } catch (_) { /* connection status covers this */ }
    }, delay);
  }
  function refreshSessions(delay = 150) {
    clearTimeout(sessT);
    sessT = setTimeout(async () => {
      try { S.sessions = await api("/v1/sessions"); pickSession(); render(); } catch (_) { /* ignore */ }
    }, delay);
  }

  function pickSession() {
    const ids = S.sessions.map((s) => s.id);
    for (const id of S.order) {
      const sid = S.verdicts.get(id).action.session_id;
      if (!ids.includes(sid)) ids.push(sid);
    }
    if (S.session && !ids.includes(S.session)) { S.session = null; S.followSession = true; }
    if (S.followSession || !S.session) {
      const newest = S.order.length ? S.verdicts.get(S.order[0]).action.session_id : null;
      S.session = S._lastTaskSession && ids.includes(S._lastTaskSession) ? S._lastTaskSession : newest || ids[ids.length - 1] || null;
    }
  }

  function autoSelect() {
    if (phone.matches) return;
    const vs = viewVerdicts();
    const v = vs.find(isPending) || vs.find((x) => x.decision !== "allow");
    if (v) S.selected = v.id;
  }

  const viewVerdicts = () => S.order.map((id) => S.verdicts.get(id))
    .filter((v) => (!S.session || v.action.session_id === S.session) && (!S.agent || v.action.agent === S.agent));

  // ---- render ----------------------------------------------------------------
  function render() {
    // The detail pane always belongs to the visible session: when the session changes (a click, or
    // follow mode moving to a new one) a selection from another session is dropped and re-picked.
    if (S.selected) {
      const sel = S.verdicts.get(S.selected);
      if (!sel || (S.session && sel.action.session_id !== S.session) || (S.agent && sel.action.agent !== S.agent)) {
        S.selected = null;
        autoSelect();
      }
    }
    renderSessions();
    renderBrief();
    renderFilter();
    renderChain();
    if (S.view === "live") {
      renderQueue();
      renderTimeline();
    } else {
      renderAudit();
    }
    renderDetail();
  }

  function renderFilter() {
    el.agentFilter.hidden = !S.agent;
    if (S.agent) el.agentFilterText.textContent = agentName(S.agent);
  }

  function renderSessions() {
    const list = S.sessions.slice();
    for (const id of S.order) {
      const sid = S.verdicts.get(id).action.session_id;
      if (!list.some((s) => s.id === sid)) list.push({ id: sid });
    }
    el.sessions.hidden = list.length < 2;
    if (list.length < 2) { el.sessions.innerHTML = ""; return; }
    el.sessions.innerHTML = list.map((s) => {
      const vs = S.order.map((id) => S.verdicts.get(id)).filter((v) => v.action.session_id === s.id);
      const hidden = hiddenSeen(S.sessions.find((x) => x.id === s.id) || s);
      const hot = vs.some(isPending) ? "ask" : vs.some((v) => v.decision === "block") ? "block" : hidden ? "ask" : "";
      const p = sessionParts(s.id);
      const state = vs.some(isPending) ? "waiting for you" : hot === "block" ? "has blocked actions" : hidden ? "hidden instructions seen" : "all clear";
      return `<button type="button" data-sid="${esc(s.id)}" aria-pressed="${s.id === S.session}" title="${esc(s.id)}: ${state}" aria-label="Session ${esc(s.id)}, ${state}"><span class="dot" data-hot="${hot}" aria-hidden="true"></span>${esc(p.name)}${p.hash ? `<span class="sid-hash">${esc(p.hash)}</span>` : ""}</button>`;
    }).join("");
    revealSession();
  }
  /** Keep the chosen session's pill in view. Also after a resize or presenter mode, which change the bar's width. */
  function revealSession() {
    const on = el.sessions.querySelector('[aria-pressed="true"]');
    if (on) {
      const bar = el.sessions.getBoundingClientRect(), r = on.getBoundingClientRect(), pad = 24; // pad: the edge fade
      if (r.right > bar.right - pad) el.sessions.scrollLeft += r.right - bar.right + pad;
      else if (r.left < bar.left + pad) el.sessions.scrollLeft -= bar.left + pad - r.left;
    }
    el.sessions.classList.toggle("is-scrolled", el.sessions.scrollLeft > 4);
    requestAnimationFrame(() => el.sessions.classList.toggle("is-scrolled", el.sessions.scrollLeft > 4));
  }
  let revealT;
  window.addEventListener("resize", () => { clearTimeout(revealT); revealT = setTimeout(revealSession, 120); });
  el.sessions.addEventListener("scroll", () => el.sessions.classList.toggle("is-scrolled", el.sessions.scrollLeft > 4), { passive: true });

  function renderBrief() {
    const sess = S.sessions.find((s) => s.id === S.session);
    const task = sess && sess.task;
    el.task.textContent = task || "No task yet. When your agent starts working, what you asked it shows up here.";
    el.task.classList.toggle("is-empty", !task);
    const cwd = sess && sess.cwd ? sess.cwd : "";
    const parts = cwd.split("/").filter(Boolean);
    el.cwd.textContent = parts.length > 3 ? "…/" + parts.slice(-3).join("/") : cwd;
    el.cwd.title = cwd;
    const prof = sess && (sess.profile || sess.permission_profile);
    el.profile.hidden = !prof;
    const profName = prof ? (typeof prof === "string" ? prof : prof.name || prof.id) : "";
    el.profile.textContent = profName ? `${profName} profile` : "";
    el.profile.title = profName ? `The agent runs as "${profName}": only that role's tools are allowed` : "";

    const vs = viewVerdicts();
    const c = { allow: 0, ask: 0, block: 0 };
    let ms = 0;
    // Anything that went to a human counts as "needed your OK", even after you answered it;
    // allowed/blocked count only what Tripwire decided on its own.
    for (const v of vs) {
      const k = wentToHuman(v) ? "ask" : v.decision;
      c[k] = (c[k] || 0) + 1; ms += v.elapsed_ms || 0;
    }
    setStat(el.nAllow, c.allow);
    setStat(el.nAsk, c.ask);
    setStat(el.nBlock, c.block);
    el.msNote.textContent = vs.length ? `${fmtMs(ms / vs.length)} ms per decision` : "";

    const story = storyFor(sess, vs);
    el.story.hidden = !story;
    if (story) {
      el.story.classList.toggle("story-good", !!story.good);
      el.story.classList.toggle("story-warn", !!story.warn);
      el.story.querySelector("use").setAttribute("href", story.good ? "#i-allow" : "#i-hidden");
      if (el.storyText.innerHTML !== story.html) {
        el.storyText.innerHTML = story.html;
        el.story.classList.remove("is-update");
        void el.story.offsetWidth;
        el.story.classList.add("is-update");
      }
      celebrate(sess, story);
    }
  }
  const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  /** Numbers tick up to their new value (transform-free, just text), unless motion is reduced. */
  const counting = new WeakMap();
  function countTo(node, from, to, ms = 450) {
    cancelAnimationFrame(counting.get(node));
    if (reducedMotion() || !(to > from) || to - from > 400) { node.textContent = to; return; }
    const t0 = performance.now();
    const tick = (t) => {
      const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3);
      node.textContent = Math.round(from + (to - from) * e);
      if (k < 1) counting.set(node, requestAnimationFrame(tick));
    };
    counting.set(node, requestAnimationFrame(tick));
  }
  function setStat(node, n) {
    const was = Number(node.textContent) || 0;
    node.parentElement.classList.toggle("is-zero", !n);
    if (was !== n && was < n) {
      countTo(node, was, n);
      node.parentElement.classList.remove("is-bump");
      void node.offsetWidth;
      node.parentElement.classList.add("is-bump");
    } else {
      cancelAnimationFrame(counting.get(node));
      node.textContent = n;
    }
  }
  /** Once per session: the run ended with everything stopped and nothing waiting. The shield pulses green once. */
  const won = new Set();
  function celebrate(sess, story) {
    const key = sess ? sess.id : "all";
    if (!story || story.good || story.warn || won.has(key) || !/blocked (?:all|it)\b/.test(story.html) || /waiting for you/.test(story.html)) return;
    won.add(key);
    const mark = document.querySelector(".brand-mark");
    if (!mark) return;
    mark.classList.remove("is-win");
    void mark.offsetWidth;
    mark.classList.add("is-win");
    setTimeout(() => mark.classList.remove("is-win"), 1600);
  }

  function decideButtons(id) {
    const remember = S.settings ? `<div class="q-remember"><span>Remember:</span>
      <button type="button" class="btn-remember" data-resolve="allow" data-remember="always" data-id="${id}" title="Allow this kind of action from now on. Shows up under Learned rules.">${icon("pin")}Always allow this</button>
      <button type="button" class="btn-remember" data-resolve="allow" data-remember="session" data-id="${id}" title="Allow this kind of action until the agent's session ends">This session</button>
    </div>` : "";
    return `<div class="q-buttons">
      <button type="button" class="btn-decide btn-allow" data-resolve="allow" data-id="${id}">${icon("allow")}Allow<kbd aria-hidden="true">A</kbd></button>
      <button type="button" class="btn-decide btn-block" data-resolve="block" data-id="${id}">${icon("block")}Block<kbd aria-hidden="true">B</kbd></button>
    </div>${remember}`;
  }

  function renderQueue() {
    const pend = viewVerdicts().filter(isPending).sort((a, b) => b.risk - a.risk || a.ts - b.ts);
    el.queue.hidden = !pend.length;
    if (!pend.length) { el.queueList.innerHTML = ""; return; }
    el.queueTitle.innerHTML = `${icon("ask")}${pend.length === 1 ? "One action needs your OK" : pend.length + " actions need your OK"}`;
    el.queue.querySelector(".queue-hint").innerHTML = `<kbd>A</kbd> Allow <kbd>B</kbd> Block${pend.length > 1 ? " the first one" : ""}`;
    const prev = new Set([...el.queueList.children].map((n) => n.dataset.id));
    el.queueList.innerHTML = pend.map((v) => {
      const cd = countdownText(v.id);
      const hasDl = S.deadlines.has(v.id);
      return `<li class="q-item${prev.has(v.id) ? "" : " is-new"}${S.selected === v.id ? " is-selected" : ""}" data-id="${v.id}" tabindex="0" aria-label="Needs your OK: ${esc(cleanSummary(v))}">
        <div class="q-sum">${esc(cleanSummary(v))}</div>
        <div class="q-meta">${agentChip(v)}<span class="tool">${esc(toolLabel(v.action.tool))}</span><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span>${riskHtml(v.risk)}</div>
        ${cd ? `<div class="countdown${isUrgent(v.id) ? " is-urgent" : ""}" data-cd="${v.id}">${cd}</div>` : ""}
        <div class="q-actions">${decideButtons(v.id)}</div>
        ${hasDl ? `<div class="q-progress${isUrgent(v.id) ? " is-urgent" : ""}" data-pg="${v.id}" aria-hidden="true"><i style="width:${timeLeftPct(v.id)}%"></i></div>` : ""}
      </li>`;
    }).join("");
  }
  /** The pending item the A / B keys act on: the top of the queue. */
  function topPending() {
    return viewVerdicts().filter(isPending).sort((a, b) => b.risk - a.risk || a.ts - b.ts)[0] || null;
  }

  const rowEls = new Map();
  function rowHtml(v) {
    const pending = isPending(v);
    return `<div class="row-badge">${badge(v.decision)}${byHtml(v) || (pending ? `<span class="by">Waiting for you</span>` : "")}</div>
      <div class="row-main">
        <div class="row-sum">${esc(cleanSummary(v))}</div>
        <div class="row-act">${agentChip(v)}<span class="tool">${esc(toolLabel(v.action.tool))}</span><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span></div>
      </div>
      <div class="row-side">${riskHtml(v.risk)}<time title="Decided in ${fmtMs(v.elapsed_ms)} ms">${fmtTime(v.ts)}</time></div>`;
  }

  function renderTimeline() {
    const all = viewVerdicts();
    el.empty.hidden = all.length > 0;
    const vs = all.filter((v) => !isPending(v)); // a waiting item lives in the queue above, not twice
    const want = new Set(vs.map((v) => v.id));
    for (const [id, li] of rowEls) if (!want.has(id)) { li.remove(); rowEls.delete(id); }
    let anchor = el.timeline.firstChild;
    for (const v of vs) {
      let li = rowEls.get(v.id);
      const sig = `${v.decision}|${v.resolved_by}|${v.summary}|${S.held.has(v.id)}|${v.action.agent || ""}`;
      if (!li) {
        li = document.createElement("li");
        li.className = "row";
        li.tabIndex = 0;
        li.dataset.id = v.id;
        if (S.fresh.has(v.id)) {
          li.classList.add("is-new");
          li.addEventListener("animationend", () => li.classList.remove("is-new"), { once: true });
        }
        rowEls.set(v.id, li);
      }
      if (li.dataset.sig !== sig) {
        li.dataset.sig = sig;
        li.dataset.d = v.decision;
        li.innerHTML = rowHtml(v);
        li.setAttribute("aria-label", `${WORD[v.decision]}: ${toolLabel(v.action.tool)}, ${cleanSummary(v)}`);
      }
      li.classList.toggle("is-selected", S.selected === v.id);
      if (li !== anchor) el.timeline.insertBefore(li, anchor);
      else anchor = anchor.nextSibling;
      if (li === anchor) anchor = anchor.nextSibling;
    }
    S.fresh.clear();
  }

  function renderDetail() {
    const v = S.selected && S.verdicts.get(S.selected);
    el.detailEmpty.hidden = !!v;
    el.detailBody.hidden = !v;
    if (!v) {
      const vs = viewVerdicts();
      const clean = vs.length > 0 && vs.every((x) => x.decision === "allow") && !hiddenSeen(S.sessions.find((x) => x.id === S.session));
      el.detailEmpty.innerHTML = clean
        ? `<div class="ok">${icon("allow")}All clear</div><p style="margin:0">Every action so far matched what you asked for. Pick one to see why.</p>`
        : `<p style="margin:0">Pick any action to see exactly why Tripwire decided what it did.</p>`;
    }
    if (!v) { el.detail.classList.remove("is-open"); document.body.classList.remove("sheet-open"); return; }
    const pending = isPending(v);
    const ctx = (f) => (f.rule === "taint.injection_context" ? 1 : 0);
    const headline = cleanSummary(v);
    // The headline finding is already the title; show it again only when it carries evidence.
    const findings = (v.findings || []).filter((f) => f.message !== headline || f.evidence).sort((a, b) => ctx(a) - ctx(b) || b.severity - a.severity);
    const cd = pending ? countdownText(v.id) : "";
    const t = toolParts(v.action.tool);
    const fresh = el.detailBody.dataset.id !== v.id;
    if (fresh) { el.detail.scrollTop = 0; el.detailBody.dataset.id = v.id; el.detailBody.classList.remove("is-fresh"); void el.detailBody.offsetWidth; el.detailBody.classList.add("is-fresh"); }
    const sess = S.sessions.find((x) => x.id === v.action.session_id);
    const path = attackPath(v, sess);
    const pathSection = pathHtml(v, sess, { fresh });

    if (simple()) {
      // Simple: what happened, why, where it came from, and the buttons. No numbers, ids or hashes.
      const why = (v.findings || []).filter((f) => f.message !== headline).sort((a, b) => ctx(a) - ctx(b) || b.severity - a.severity);
      const evidence = (v.findings || []).filter((f) => f.evidence).sort((a, b) => ctx(a) - ctx(b) || b.severity - a.severity);
      const uniq = uniqEvidence();
      el.detailBody.innerHTML = `
        <div class="d-top"><div class="d-head"><div>${badge(v.decision)}${byHtml(v)}</div>
          <button type="button" class="d-close" data-close aria-label="Close details">${icon("close")}</button></div>
        <p class="d-sum">${esc(headline)}</p>
        ${pending ? `<div class="d-decide">${decideButtons(v.id)}${cd ? `<span class="countdown${isUrgent(v.id) ? " is-urgent" : ""}" data-cd="${v.id}">${cd}</span>` : ""}</div>` : ""}</div>
        ${pathSection}
        <div class="d-section"><h3>What happened</h3>
          <p class="d-plain">${agentOf(v) ? `<b>${esc(agentOf(v).short)}</b> wanted to ` : "The agent wanted to "}${esc(plainAction(v))}.</p>
          ${path ? "" : `<div class="d-act">${esc(renderAct(v))}</div>`}</div>
        ${why.length ? `<div class="d-section"><h3>Why</h3><ul class="d-why">${why.map((f) => `<li>${esc(f.message)}</li>`).join("")}</ul></div>`
          : v.decision === "allow" ? `<div class="d-section"><h3>Why</h3><p class="d-plain">${wentToHuman(v) ? "It needed an OK first, and got one." : "Nothing risky found. It fits what you asked."}</p></div>` : ""}
        ${evidence.length && !(path && path.source) ? `<div class="d-section"><h3>Where it came from</h3>${evidence.filter((f) => uniq(f.evidence)).map((f) =>
          `<div class="evidence"><div class="ev-src">${icon("doc")}From ${esc(evidenceSource(f))}, not from you</div><div class="ev-text">…${highlight(f.evidence, v, f)}…</div></div>`).join("")}</div>` : ""}
        ${v.action.parent ? `<p class="d-plain d-spawned-note">Started by <b>${esc(agentName(v.action.parent))}</b>.</p>` : ""}`;
      return;
    }

    // The same snippet often backs two findings (and the attack path above): show it once.
    const uniqD = uniqEvidence(path && path.steps ? path.steps.map((x) => x.snippet).filter(Boolean) : []);
    const showEv = new Set(findings.filter((f) => f.evidence && uniqD(f.evidence)));
    el.detailBody.innerHTML = `
      <div class="d-top"><div class="d-head"><div>${badge(v.decision)}${byHtml(v)}</div>
        <button type="button" class="d-close" data-close aria-label="Close details">${icon("close")}</button></div>
      <p class="d-sum">${esc(cleanSummary(v))}</p>
      ${pending ? `<div class="d-decide">${decideButtons(v.id)}${cd ? `<span class="countdown${isUrgent(v.id) ? " is-urgent" : ""}" data-cd="${v.id}">${cd}</span>` : ""}</div>` : ""}</div>
      <div class="d-act">${esc(renderAct(v))}</div>
      <div class="d-facts">
        <div><span>Tool</span><b title="${esc(v.action.tool)}">${esc(t.name)}${t.server ? ` <small>(${esc(t.server)})</small>` : ""}</b></div>
        <div><span>Kind</span><b title="${esc(CAPWORD[v.capability] || v.capability)}">${esc(CAPWORD[v.capability] || v.capability)}</b></div>
        <div><span>Risk</span><b>${v.risk}<small> / 100</small></b></div>
        <div><span>Decided in</span><b>${fmtMs(v.elapsed_ms)}<small> ms</small></b></div>
      </div>
      ${pathSection}
      <div class="d-section"><h3>Why${findings.length > 1 ? `<span class="n">${findings.length} findings</span>` : ""}</h3>
        ${findings.length ? `<ol class="findings">${findings.map((f) => `
          <li class="finding${f.message === cleanSummary(v) ? " is-headline" : ""}" data-lvl="${lvl(f.severity)}">
            <div class="f-msg"><span class="sev" data-lvl="${lvl(f.severity)}" title="Severity ${Math.min(100, f.severity)} of 100">${Math.min(100, f.severity)}</span><span>${esc(f.message)}</span></div>
            ${showEv.has(f) ? `<div class="evidence"><div class="ev-src">${icon("doc")}From ${esc(evidenceSource(f))}, not from you</div><div class="ev-text">…${highlight(f.evidence, v, f)}…</div></div>` : ""}
            <div class="f-tags">${f.message === cleanSummary(v) ? `<span class="sev" data-lvl="${lvl(f.severity)}" title="Severity ${Math.min(100, f.severity)} of 100">${Math.min(100, f.severity)}</span>` : ""}<span class="tag">${esc(f.category)}</span><span class="rule">${esc(f.rule)}</span></div>
          </li>`).join("")}</ol>` : `<p class="muted-p">Nothing risky found. It matches a normal ${esc(CAPWORD[v.capability] || "action")} for what you asked.</p>`}
      </div>
      ${judgeHtml(v)}
      ${agentHtml(v)}
      ${historyHtml(v)}
      <details class="d-more"><summary>Full arguments</summary><pre class="json">${esc(JSON.stringify(v.action.args, null, 2))}</pre></details>
      <div class="d-id">${fmtTime(v.ts)} · session ${esc(v.action.session_id)} · via ${esc(v.action.source)} · id ${esc(v.id)}</div>`;
    loadHistory(v);
  }

  /** A filter that passes each evidence snippet once: a snippet already shown (or contained in one) is dropped. */
  function uniqEvidence(already = []) {
    const norm = (t) => String(t || "").replace(/\s+/g, " ").trim().toLowerCase();
    const seen = already.map(norm).filter(Boolean);
    return (text) => {
      const n = norm(text);
      if (!n || seen.some((s) => s.includes(n) || n.includes(s))) return false;
      seen.push(n);
      return true;
    };
  }

  /** "read a file", "run a command"... for the Simple view's one-liner. */
  function plainAction(v) {
    const t = toolLabel(v.action.tool);
    const words = { read: "read a file", write: "change a file", exec: "run a command", fetch: "fetch a web page", send: "send a message",
      money: "move money", delete: "delete something", agent: "start another agent", credential: "change credentials" };
    // Mail and chat readers are reads too, but "read a file" would be wrong for them.
    const name = String(v.action.tool || "").toLowerCase();
    const mailish = /(inbox|email|mail|message|channel|chat|slack|dm)/.test(name);
    const word = v.capability === "read" && mailish ? "read your messages" : words[v.capability];
    return `${word || `use ${t}`}${word ? ` (${t})` : ""}`;
  }

  /** Who acted, and who started them. Only for sub-agents and MCP servers; the main agent needs no label. */
  function agentHtml(v) {
    const a = agentOf(v);
    if (!a) return "";
    const parent = v.action.parent ? agentName(v.action.parent) : "";
    return `<div class="d-section"><h3>Who acted</h3><div class="d-agent">
      ${agentChip(v, " is-big")}${parent ? `<span class="d-spawned">spawned by <b>${esc(parent)}</b></span>` : ""}
    </div></div>`;
  }

  /** The chained records for this action: the verdict and every resolution, each with its hash. */
  function historyHtml(v) {
    const recs = S.history.get(v.id);
    const items = recs ? recs.map((r) => {
      const body = r.body || {};
      let what;
      if (r.kind === "verdict") what = r.decision === "ask" ? "Asked" : WORD[r.decision] || r.decision;
      else if (body.by === "timeout") what = "No answer in time, so blocked";
      else if (body.by === "human") what = r.decision === "allow" ? "Allowed by you" : "Blocked by you";
      else what = `${WORD[r.decision] || r.decision} by ${body.by || "Tripwire"}`;
      return `<li data-k="${esc(r.kind)}" data-d="${esc(r.decision || "")}"><span class="h-what">${esc(what)}</span><time>${fmtTime(r.ts)}</time><code class="hash" title="SHA-256 ${esc(r.hash)}">#${esc(String(r.hash || "").slice(0, 7))}</code></li>`;
    }).join("") : "";
    const pendingNote = isPending(v) ? `<li class="h-wait"><span class="h-what">Waiting for your answer</span></li>` : "";
    return `<div class="d-section d-history"><h3>Record${recs && recs.length > 1 ? `<span class="n">${recs.length} entries</span>` : ""}</h3>
      ${recs === undefined ? `<p class="muted-p h-loading">Reading the audit chain…</p>` : recs === null ? `<p class="muted-p">Not in the audit chain (older record or hosted demo).</p>`
        : `<ol class="history">${items}${pendingNote}</ol>`}
      <p class="h-export">Every entry is hashed and signed. For auditors: <code>tripwire audit export</code></p>
    </div>`;
  }

  const historyT = new Map();
  /** Fetch this action's chained records once; refetch after a resolution. */
  function loadHistory(v, force = false) {
    if (!force && S.history.has(v.id)) return;
    if (historyT.has(v.id)) return;
    historyT.set(v.id, true);
    const who = v.action.agent || v.action.session_id;
    api(`/v1/audit/events?since=0&limit=2000&agent=${encodeURIComponent(who)}`).then((evs) => {
      const recs = evs.filter((r) => (r.kind === "verdict" && (r.ref === v.id || r.id === v.id)) || (r.kind === "resolution" && r.ref === v.id))
        .map((r) => { let body = {}; try { body = JSON.parse(r.json || "{}"); } catch (_) { /* keep empty */ } return { ...r, body }; });
      S.history.set(v.id, recs.length ? recs : null);
    }).catch(() => S.history.set(v.id, null)).finally(() => {
      historyT.delete(v.id);
      if (S.selected === v.id) renderDetail();
    });
  }

  /** The local judge's card: small and secondary. The rules decided first; the judge only speaks on grey-zone asks. */
  function judgeHtml(v) {
    const j = v.judge;
    if (!j) return "";
    const ms = j.ms != null ? `${fmtMs(j.ms)} ms` : "";
    const model = j.model ? `<span class="judge-model">${esc(j.model)}</span>` : "";
    if (j.error) {
      return `<div class="d-section"><h3>Local judge</h3><div class="judge">
        <div class="judge-head">${icon("judge", "badge-icon")}<b>Did not answer</b>${model}<span class="judge-meta">${ms}</span></div>
        <p class="judge-reason">${esc(j.reason || "The judge was unavailable, so the rule-based verdict stands and a human decides.")}</p></div></div>`;
    }
    const said = j.model_decision || j.decision;
    const conf = typeof j.confidence === "number" ? Math.round(j.confidence * 100) : null;
    const final = judgeDecided(v);
    const lead = final
      ? (j.decision === "block" ? "Agreed: block" : "Agreed: allow, no need to ask you")
      : `Leaned ${said === "allow" ? "allow" : said === "block" ? "block" : "unsure"}, so it stays a question for you`;
    return `<div class="d-section"><h3>Local judge</h3><div class="judge">
      <div class="judge-head">${icon("judge")}<b>${lead}</b>${model}
        <span class="judge-meta">${conf != null ? `<span class="conf" title="How sure the judge was">${conf}% sure<i><b style="width:${conf}%"></b></i></span>` : ""}${ms}${j.cached ? "<span>cached</span>" : ""}</span></div>
      ${j.reason ? `<p class="judge-reason">${esc(j.reason)}</p>` : ""}
      ${j.note ? `<p class="judge-note">${esc(j.note.charAt(0).toUpperCase() + j.note.slice(1))}. The judge never sees what the agent read, only your task and the action.</p>` : `<p class="judge-note">The judge never sees what the agent read, only your task and the action.</p>`}
    </div></div>`;
  }

  function renderAudit() {
    el.auditListTab.setAttribute("aria-selected", S.auditView === "list");
    el.auditTreeTab.setAttribute("aria-selected", S.auditView === "tree");
    el.auditList.hidden = S.auditView !== "list";
    el.auditTree.hidden = S.auditView !== "tree";
    if (S.auditView === "tree") { renderTree(); return; }
    const all = S.order.map((id) => S.verdicts.get(id)).filter((v) => !S.agent || v.action.agent === S.agent);
    el.auditNote.textContent = all.length
      ? `${all.length} ${all.length === 1 ? "decision" : "decisions"} across ${new Set(all.map((v) => v.action.session_id)).size} ${new Set(all.map((v) => v.action.session_id)).size === 1 ? "session" : "sessions"}, newest first.`
      : "No decisions yet.";
    el.auditCount.textContent = all.length || "";
    el.auditRows.innerHTML = all.map((v) => {
      const who = v.resolved_by === "human" ? `<span class="who-human">You</span>` : v.resolved_by === "timeout" ? `<span class="who-timeout">Timed out</span>` : v.resolved_by === "api-token" || v.resolved_by === "hook-token" || v.resolved_by === "admin" || v.resolved_by === "demo-admin" ? `<span title="Answered from a terminal or a script with Tripwire's key, not on this page">Terminal</span>` : v.resolved_by ? esc(v.resolved_by.charAt(0).toUpperCase() + v.resolved_by.slice(1)) : isPending(v) ? `<span class="who-wait">Waiting</span>` : judgeDecided(v) ? "Tripwire + judge" : "Tripwire";
      const ag = agentOf(v);
      return `<tr data-id="${v.id}" tabindex="0"><td>${fmtTime(v.ts)}</td><td class="sid" title="${esc(v.action.session_id)}">${esc(sessionParts(v.action.session_id).name)}</td><td class="agent-cell">${ag ? agentChip(v) : `<span class="main-agent">main</span>`}</td><td class="tool">${esc(toolLabel(v.action.tool))}</td>
        <td><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span></td><td>${badge(v.decision)}</td><td><span class="why" title="${esc(cleanSummary(v))}">${esc(cleanSummary(v))}</span></td><td>${who}</td>
        <td class="num">${v.risk}</td><td class="num">${fmtMs(v.elapsed_ms)}</td></tr>`;
    }).join("");
  }

  // ---- agents tree (Audit > Agents) --------------------------------------------
  let treeT, treeLoading = false;
  function loadTree(delay = 0) {
    clearTimeout(treeT);
    treeT = setTimeout(async () => {
      if (treeLoading) return;
      treeLoading = true;
      try {
        const t = await api("/v1/audit?format=tree&limit=30");
        S.tree = t && t.traces ? t.traces : null;
      } catch (_) { S.tree = null; }
      treeLoading = false;
      const deep = (S.tree || []).some((t) => t.agents > 1);
      el.auditTreeTab.hidden = !S.tree || !S.tree.length;
      el.auditTreeTab.title = deep ? "Who spawned whom, and what each agent did" : "One agent per session so far";
      if (S.view === "audit") renderAudit();
    }, delay);
  }
  function renderTree() {
    el.auditNote.textContent = S.tree && S.tree.length
      ? `${S.tree.length} ${S.tree.length === 1 ? "trace" : "traces"}. A trace is a main agent and everything it spawned. Click an agent to see only its actions.`
      : "No traces yet.";
    if (!S.tree) { el.auditTree.innerHTML = `<p class="muted-p" style="padding:1rem">The agent tree needs the local daemon.</p>`; return; }
    const counts = (c) => `<span class="t-counts">${c.allow ? `<span class="tc tc-allow" title="allowed">${icon("allow")}${c.allow}</span>` : ""}${c.ask ? `<span class="tc tc-ask" title="needed your OK">${icon("ask")}${c.ask}</span>` : ""}${c.block ? `<span class="tc tc-block" title="blocked">${icon("block")}${c.block}</span>` : ""}${!c.allow && !c.ask && !c.block ? `<span class="tc tc-none">no actions</span>` : ""}</span>`;
    const node = (n, depth, root) => {
      const info = agentInfo(n.agent, n.session) || (depth === 0 ? { kind: "main", name: sessionParts(n.session || n.agent).name, short: "" } : { kind: "agent", name: agentName(n.agent) });
      const kindWord = info.kind === "main" ? "main agent" : info.kind === "sub-agent" ? "sub-agent" : info.kind === "mcp" ? "MCP server" : "agent";
      const task = n.tasks && n.tasks.length ? n.tasks[n.tasks.length - 1].prompt : "";
      const spawn = n.spawned_by ? `<span class="t-spawn" title="The call that started this agent">started by ${esc(agentName(n.parent))}</span>` : (n.parent ? `<span class="t-spawn">under ${esc(agentName(n.parent))}</span>` : "");
      const inj = n.injections > 0 ? `<span class="t-inj" title="Hidden instructions were found in what this agent read">${icon("hidden")}${n.injections === 1 ? "hidden instructions seen" : `${n.injections}× hidden instructions`}</span>` : "";
      return `<li class="t-node" style="--depth:${depth}">
        <button type="button" class="t-row${S.agent === n.agent ? " is-on" : ""}" data-agent="${esc(n.agent)}" data-trace="${esc(root)}" aria-pressed="${S.agent === n.agent}">
          <span class="t-main"><span class="t-name">${esc(info.name)}</span><span class="t-kind">${kindWord}</span>${spawn}${inj}
            ${task ? `<span class="t-task" title="${esc(task)}">${esc(task)}</span>` : ""}</span>
          ${counts(n.counts)}
        </button>
        ${n.children && n.children.length ? `<ul>${n.children.map((c) => node(c, depth + 1, root)).join("")}</ul>` : ""}
      </li>`;
    };
    el.auditTree.innerHTML = S.tree.map((t) => `<section class="trace">
      <header class="trace-head"><span class="trace-title">${esc(sessionParts(t.root.session || t.trace).name)}</span>
        <span class="trace-meta">${t.agents} ${t.agents === 1 ? "agent" : "agents"} · ${t.totals.allow} allowed · ${t.totals.ask} asked · ${t.totals.block} blocked</span></header>
      <ul class="tree">${node(t.root, 0, t.trace)}</ul></section>`).join("");
  }

  // ---- audit chain: is the log intact? --------------------------------------
  let chainT;
  function verifyChain(delay = 0) {
    clearTimeout(chainT);
    chainT = setTimeout(async () => {
      try { S.chain = await api("/v1/audit/verify"); } catch (_) { S.chain = null; }
      renderChain();
    }, delay);
  }
  function renderChain() {
    const c = S.chain;
    for (const node of [el.chain, el.chainLive]) {
      node.hidden = !c;
      if (!c) continue;
      const text = node.querySelector("span"), use = node.querySelector("use");
      if (!text || !use) continue;
      node.dataset.ok = c.ok ? "1" : "0";
      if (c.ok) {
        const n = c.checked || 0;
        const quiet = node === el.chainLive;
        text.textContent = quiet ? `Log intact · ${n} signed` : `Audit log intact · ${n} ${n === 1 ? "record" : "records"} signed${c.legacy ? `, ${c.legacy} older unsigned` : ""}`;
        node.title = `Every record is hash-chained and signed. ${(c.notes || []).join(" ")}`.trim();
        use.setAttribute("href", "#i-lock");
      } else {
        text.textContent = c.problem || "Audit log failed verification";
        node.title = (c.notes || []).join(" ") || "The hash chain does not check out.";
        use.setAttribute("href", "#i-block");
      }
    }
  }
  async function checkHealth() {
    try {
      const h = await api("/healthz");
      const a = h && h.audit;
      const bad = a && a.status === "degraded";
      el.degraded.hidden = !bad;
      if (bad) el.degradedText.textContent = `${a.error ? a.error + ". " : ""}${a.queued ? `${a.queued} ${a.queued === 1 ? "record is" : "records are"} queued and will be written in order once the disk recovers.` : "Decisions still run; the trail has a gap until writes recover."}`;
    } catch (_) { el.degraded.hidden = true; }
  }
  setInterval(checkHealth, 30000);

  function tickCountdowns() {
    for (const n of document.querySelectorAll("[data-cd]")) {
      n.textContent = countdownText(n.dataset.cd);
      n.classList.toggle("is-urgent", !!isUrgent(n.dataset.cd));
    }
    for (const n of document.querySelectorAll("[data-pg]")) {
      n.firstElementChild.style.width = timeLeftPct(n.dataset.pg) + "%";
      n.classList.toggle("is-urgent", !!isUrgent(n.dataset.pg));
    }
  }
  setInterval(tickCountdowns, 1000);

  // ---- actions --------------------------------------------------------------
  let toastT;
  function toast(msg, ms = 3200) {
    el.toast.textContent = msg;
    el.toast.hidden = false;
    clearTimeout(toastT);
    toastT = setTimeout(() => (el.toast.hidden = true), ms);
  }

  async function resolve(id, decision, btn, remember) {
    const btns = document.querySelectorAll(`[data-resolve][data-id="${id}"]`);
    btns.forEach((b) => (b.disabled = true));
    try {
      const res = await api(`/v1/verdicts/${id}/resolve`, { method: "POST", body: JSON.stringify(remember ? { decision, remember } : { decision }) });
      if (remember) {
        if (res && res.remember_refused) toast(`Allowed this once. Not remembered: ${String(res.remember_refused).replace(/^\s*not remembered:\s*/i, "")}`, 5200);
        else toast(remember === "always" ? "Learned. Tripwire will allow this on its own from now on." : "Allowed for the rest of this session.");
        loadRules(400);
      }
      const v = S.verdicts.get(id);
      if (v) { v.decision = decision; v.resolved_by = "human"; S.history.delete(id); setTimeout(() => loadHistory(v, true), 400); }
      refreshStats(0);
      verifyChain(1200);
      if (phone.matches && el.detail.classList.contains("is-open")) { closeDetail(); return; } // show the next waiting item
      render();
    } catch (e) {
      btns.forEach((b) => (b.disabled = false));
      toast(e.status === 404 ? "That action is gone. The log was probably reset." : `Couldn't send your answer. ${e.message}`, 5200);
    }
  }

  function select(id, manual) {
    S.selected = id;
    if (manual) S.manualPickAt = Date.now();
    render();
    if (phone.matches && id) {
      el.detail.classList.add("is-open");
      document.body.classList.add("sheet-open");
      el.detail.scrollTop = 0;
    }
  }
  function closeDetail() {
    el.detail.classList.remove("is-open");
    document.body.classList.remove("sheet-open");
    if (phone.matches) S.selected = null;
    render();
  }

  async function filterAgent(agent) {
    S.agent = S.agent === agent ? null : agent;
    S.selected = null;
    if (S.agent) {
      // pull in anything older than the live window for this agent
      try { for (const v of await api(`/v1/verdicts?limit=500&agent=${encodeURIComponent(S.agent)}`)) upsert(v, false); sortOrder(); } catch (_) { /* live data is enough */ }
      const first = S.order.map((id) => S.verdicts.get(id)).find((v) => v.action.agent === S.agent);
      if (first) { S.session = first.action.session_id; S.followSession = false; }
    }
    autoSelect();
    render();
  }
  el.agentFilter.addEventListener("click", () => filterAgent(S.agent));
  el.auditListTab.addEventListener("click", () => { S.auditView = "list"; render(); });
  el.auditTreeTab.addEventListener("click", () => { S.auditView = "tree"; loadTree(0); render(); });

  document.addEventListener("click", (e) => {
    const r = e.target.closest("[data-resolve]");
    if (r) { e.stopPropagation(); resolve(r.dataset.id, r.dataset.resolve, r, r.dataset.remember); return; }
    const ac = e.target.closest(".agent-chip, .t-row");
    if (ac) {
      e.stopPropagation();
      const wasTree = !!ac.closest(".t-row");
      filterAgent(ac.dataset.agent).then(() => { if (wasTree && S.agent) setView("live"); });
      return;
    }
    if (e.target.closest("[data-close]")) { closeDetail(); return; }
    const s = e.target.closest("[data-sid]");
    if (s) { S.session = s.dataset.sid; S.followSession = false; S.selected = null; autoSelect(); render(); return; }
    const row = e.target.closest(".row, .q-item, .audit-table tbody tr");
    if (row && row.dataset.id) {
      const v = S.verdicts.get(row.dataset.id);
      if (v && S.view === "audit") {
        if (v.action.session_id !== S.session) { S.session = v.action.session_id; S.followSession = false; }
        setView("live");
      }
      select(row.dataset.id, true);
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const typing = e.target.matches("input, textarea, select, [contenteditable]");
    if (e.key === "Escape" && el.detail.classList.contains("is-open")) closeDetail();
    if ((e.key === "Enter" || e.key === " ") && e.target.matches(".row, .q-item, .audit-table tbody tr")) { e.preventDefault(); e.target.click(); return; }
    if (typing || tour.open || tips.open || !el.settingsPop.hidden) return;
    // A / B answer the first waiting item. Shown as hints on its buttons.
    if ((e.key === "a" || e.key === "A" || e.key === "b" || e.key === "B") && S.view === "live") {
      const top = topPending();
      if (!top) return;
      e.preventDefault();
      const decision = e.key.toLowerCase() === "a" ? "allow" : "block";
      const btn = document.querySelector(`.q-item [data-resolve="${decision}"][data-id="${top.id}"]`);
      if (btn) { btn.classList.add("is-pressed"); setTimeout(() => btn.classList.remove("is-pressed"), 150); }
      resolve(top.id, decision, btn);
      return;
    }
    // Up / Down move the selection through the feed.
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && S.view === "live") {
      const vs = viewVerdicts();
      if (!vs.length) return;
      e.preventDefault();
      const i = vs.findIndex((v) => v.id === S.selected);
      const next = e.key === "ArrowDown" ? Math.min(vs.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
      select(vs[next].id, true);
      const li = rowEls.get(vs[next].id);
      if (li) { li.scrollIntoView({ block: "nearest" }); li.focus({ preventScroll: true }); }
    }
  });

  // Theme and presenter mode. Both also work from the URL: ?theme=dark ?stage=1
  const root = document.documentElement;
  function paintThemeButton() {
    const dark = root.dataset.theme === "dark";
    el.theme.querySelector("use").setAttribute("href", dark ? "#i-sun" : "#i-moon");
    el.theme.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  }
  el.theme.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("tw-theme", root.dataset.theme); } catch (_) { /* private mode */ }
    paintThemeButton();
  });
  paintThemeButton();
  function paintStage() { el.stage.setAttribute("aria-pressed", root.classList.contains("stage")); }
  el.stage.addEventListener("click", () => {
    root.classList.toggle("stage");
    try { localStorage.setItem("tw-stage", root.classList.contains("stage") ? "1" : "0"); } catch (_) { /* private mode */ }
    paintStage();
    requestAnimationFrame(revealSession);
  });
  paintStage();

  /** Screen readers hear every block and every question, without the page moving focus. */
  function announce(v) {
    if (v.decision === "allow") return;
    el.announce.textContent = "";
    setTimeout(() => { el.announce.textContent = `${WORD[v.decision]}: ${cleanSummary(v)}`; }, 50);
  }

  function sayAloud(text) {
    el.announce.textContent = "";
    setTimeout(() => { el.announce.textContent = text; }, 50);
  }

  function setView(view) {
    S.view = view;
    el.tabLive.setAttribute("aria-selected", view === "live");
    el.tabAudit.setAttribute("aria-selected", view === "audit");
    const was = S.view;
    el.live.hidden = view !== "live";
    el.audit.hidden = view !== "audit";
    document.body.dataset.view = view;
    const panel = view === "live" ? el.live : el.audit;
    panel.classList.remove("is-in");
    if (was !== undefined) { void panel.offsetWidth; panel.classList.add("is-in"); }
    if (view === "audit") { el.empty.hidden = true; loadTree(0); verifyChain(0); }
    render();
  }
  el.tabLive.addEventListener("click", () => setView("live"));
  el.tabAudit.addEventListener("click", () => setView("audit"));

  el.exportBtn.addEventListener("click", async () => {
    try {
      const data = await api("/v1/verdicts?limit=100000");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      const d = new Date();
      const stamp = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}-${String(d.getHours()).padStart(2, "0")}${String(d.getMinutes()).padStart(2, "0")}`;
      a.href = URL.createObjectURL(blob);
      a.download = `tripwire-audit-${stamp}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      toast(`Exported ${data.length} decisions`);
    } catch (e) {
      toast(`Couldn't export. ${e.message}`);
    }
  });

  // Reset asks for a second click instead of a native dialog (cleaner on a projector).
  let armT;
  el.reset.addEventListener("click", async () => {
    const label = el.reset.querySelector("span");
    if (!el.reset.dataset.armed) {
      el.reset.dataset.armed = "1";
      label.textContent = "Confirm";
      el.reset.setAttribute("aria-label", "Click again to clear the live view");
      sayAloud("Click Reset again to clear the live view.");
      armT = setTimeout(() => { delete el.reset.dataset.armed; label.textContent = "Reset"; el.reset.removeAttribute("aria-label"); }, 3000);
      return;
    }
    clearTimeout(armT);
    delete el.reset.dataset.armed;
    label.textContent = "Reset";
    el.reset.removeAttribute("aria-label");
    try { await api("/v1/reset", { method: "POST" }); } catch (e) { toast(`Couldn't reset. ${e.message}`); }
  });

  // ---- Simple / Detailed ----------------------------------------------------
  function paintMode() {
    root.dataset.mode = S.mode;
    for (const b of el.modeSeg.querySelectorAll("[data-mode]")) b.setAttribute("aria-checked", b.dataset.mode === S.mode);
  }
  el.modeSeg.addEventListener("click", (e) => {
    const b = e.target.closest("[data-mode]");
    if (!b) return;
    S.mode = b.dataset.mode;
    try { localStorage.setItem("tw-mode", S.mode); } catch (_) { /* private mode */ }
    paintMode();
    render();
  });
  paintMode();

  // ---- settings: autonomy level and learned rules -----------------------------
  // Built against the engine's contract; when the endpoints are missing (hosted demo) the gear stays hidden.
  const LEVELS = {
    strict: "Asks you before anything outside your task. Nothing is decided on its own.",
    balanced: "Allows routine reads and edits inside your project on its own. Asks for everything that leaves it.",
    autonomous: "Only asks for sending data out, money and deleting. Blocks still block.",
  };
  function paintSettings() {
    const st = S.settings;
    el.settingsWrap.hidden = !st;
    if (!st) return;
    for (const b of el.autonomySeg.querySelectorAll("[data-level]")) b.setAttribute("aria-checked", b.dataset.level === st.autonomy);
    el.autonomyHint.textContent = LEVELS[st.autonomy] || "";
    const rules = S.rules || [];
    el.rulesCount.textContent = rules.length || "";
    el.rulesEmpty.hidden = rules.length > 0;
    el.rulesList.innerHTML = rules.map((r) => `<li class="rule-item">
      <span class="rule-main"><span class="badge badge-${esc(r.decision || "allow")}">${icon(r.decision || "allow")}${WORD[r.decision || "allow"]}</span>
        <span class="rule-text">${esc(r.description || `${toolLabel(r.tool || "")} ${r.target || ""}`.trim())}</span>
        <span class="rule-meta">${esc(r.scope === "session" ? "this session" : "always")}${r.created ? ` · ${esc(fmtDate(r.created))}` : ""}</span></span>
      <button type="button" class="rule-del" data-rule="${esc(r.id)}" aria-label="Forget this rule" title="Forget this rule">${icon("close")}</button></li>`).join("");
  }
  function fmtDate(x) {
    const d = typeof x === "number" ? new Date(x * 1000) : new Date(x);
    return isNaN(d) ? "" : d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
  async function loadSettings() {
    try { S.settings = await api("/v1/settings"); } catch (_) { S.settings = null; }
    paintSettings();
    if (S.settings) { loadRules(0); render(); } // approval cards gain their "remember" options
  }
  let rulesT;
  function loadRules(delay = 0) {
    if (!S.settings) return;
    clearTimeout(rulesT);
    rulesT = setTimeout(async () => {
      try { S.rules = await api("/v1/rules"); } catch (_) { S.rules = []; }
      paintSettings();
    }, delay);
  }
  el.autonomySeg.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-level]");
    if (!b || !S.settings) return;
    const prev = S.settings.autonomy;
    S.settings.autonomy = b.dataset.level;
    paintSettings();
    try { S.settings = await api("/v1/settings", { method: "PUT", body: JSON.stringify({ autonomy: b.dataset.level }) }); }
    catch (err) { S.settings.autonomy = prev; toast(`Couldn't change the level. ${err.message}`, 5200); }
    paintSettings();
  });
  el.rulesList.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-rule]");
    if (!b) return;
    b.disabled = true;
    try { await api(`/v1/rules/${encodeURIComponent(b.dataset.rule)}`, { method: "DELETE" }); toast("Forgotten."); }
    catch (err) { toast(`Couldn't forget it. ${err.message}`, 5200); }
    loadRules(0);
  });
  function openSettings(open) {
    el.settingsPop.hidden = !open;
    el.settingsBtn.setAttribute("aria-expanded", open);
    if (open) {
      loadRules(0);
      const on = el.autonomySeg.querySelector('[aria-checked="true"]') || el.autonomySeg.querySelector("button");
      if (on) on.focus({ preventScroll: true }); // keyboard users land inside the panel, not behind it
    }
  }
  el.settingsBtn.addEventListener("click", () => openSettings(el.settingsPop.hidden));
  document.addEventListener("click", (e) => { if (!el.settingsPop.hidden && !e.target.closest("#settings-wrap")) openSettings(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !el.settingsPop.hidden) { openSettings(false); el.settingsBtn.focus({ preventScroll: true }); } });

  // ---- first-open guide --------------------------------------------------------
  const TOUR_SEEN = "tw-guide-seen";
  // The commands carry this dashboard's own port when it isn't the default, or the hooks would look on 7777.
  const PORT_ARG = !window.TW && location.port && location.port !== "7777" ? ` --port ${location.port}` : "";
  const CMD_CLAUDE = `tripwire install claude${PORT_ARG}`;
  const CMD_MCP = `tripwire mcp-proxy --name myserver -- <your mcp server command>`;
  // The empty feed shows the same commands (index.html has the defaults).
  for (const li of document.querySelectorAll(".empty-cmds li")) {
    const code = li.querySelector("code"), btn = li.querySelector("[data-copy]");
    if (!code) continue;
    const cmd = /install claude/.test(code.textContent) ? CMD_CLAUDE : /mcp-proxy/.test(code.textContent) ? CMD_MCP : null;
    if (!cmd) continue;
    code.textContent = cmd;
    if (btn) btn.dataset.copy = cmd;
  }
  const T = {
    pill: (d, word) => `<span class="badge badge-${d}">${icon(d)}${word}</span>`,
    code: (cmd, label) => `<div class="tour-cmd"><code>${esc(cmd)}</code><button type="button" class="tour-copy" data-copy="${esc(cmd)}" aria-label="Copy ${esc(label)}">${icon("copy")}<span>Copy</span></button></div>`,
  };
  const STEPS = [
    { kicker: "Welcome", tone: "teal", title: "A guard between your AI agent and its tools.",
      body: `<p>Agents read files, pages and emails. Any of those can hide orders. Tripwire checks every tool call before it runs and stops the ones you never asked for.</p><p class="tour-small">${esc((window.TW && window.TW.hostedNote) || "Runs on your machine only. Nothing leaves it.")}</p>`,
      visual: `<svg viewBox="0 0 320 200" class="tv"><defs><linearGradient id="tg1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#62c9c3"/><stop offset="1" stop-color="#6c7cf0"/></linearGradient></defs>
        <rect x="8" y="72" width="104" height="56" rx="12" class="tv-box"/><text x="60" y="96" class="tv-t">AI agent</text><text x="60" y="113" class="tv-s" textLength="86" lengthAdjust="spacingAndGlyphs">reads, runs, sends</text>
        <path d="M116 100h22" class="tv-line"/><path d="M182 100h40" class="tv-line"/>
        <path d="M160 58l26 10v22c0 17-11 31-26 36-15-5-26-19-26-36V68z" fill="url(#tg1)" opacity=".95"/><path d="M149 100h22" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
        <rect x="224" y="50" width="78" height="30" rx="9" class="tv-box"/><text x="263" y="69" class="tv-t">files</text>
        <rect x="224" y="86" width="78" height="30" rx="9" class="tv-box"/><text x="263" y="105" class="tv-t">shell</text>
        <rect x="224" y="122" width="78" height="30" rx="9" class="tv-box"/><text x="263" y="141" class="tv-t">email, web</text>
        <text x="160" y="152" class="tv-s" text-anchor="middle">Tripwire</text></svg>` },
    { kicker: "Connect", tone: "indigo", title: "One line to connect it.",
      body: `<p>Claude Code: run this inside your project folder. It adds three hooks there, and every tool call in that folder is checked. Add <code>--user</code> to guard every project.</p>${T.code(CMD_CLAUDE, "the Claude Code command")}<p>Any MCP agent: put the gateway in front of a server.</p>${T.code(CMD_MCP, "the MCP command")}`,
      visual: `<svg viewBox="0 0 320 200" class="tv"><rect x="24" y="40" width="272" height="120" rx="14" class="tv-term"/><circle cx="44" cy="58" r="4" fill="#f37078"/><circle cx="58" cy="58" r="4" fill="#e8b35a"/><circle cx="72" cy="58" r="4" fill="#4fc38f"/>
        <text x="40" y="92" class="tv-code"><tspan fill="#62c9c3">$</tspan> tripwire install claude</text>
        <text x="40" y="118" class="tv-code" opacity=".75">hooks installed · 3</text><text x="40" y="140" class="tv-code" opacity=".75">dashboard  http://127.0.0.1:7777</text></svg>` },
    { kicker: "Read the feed", tone: "amber", title: "Three words you need to know.",
      body: `<ul class="tour-list"><li>${T.pill("allow", "Allowed")}<span>Part of your task. Went through.</span></li><li>${T.pill("ask", "Needs your OK")}<span>Unusual. Waits for you.</span></li><li>${T.pill("block", "Blocked")}<span>Taken from hidden instructions, or beyond the agent's permissions.</span></li></ul><p class="tour-small">Every decision has a plain-English reason and the exact text it came from.</p>`,
      visual: `<svg viewBox="0 0 320 200" class="tv">
        <rect x="24" y="30" width="272" height="40" rx="10" class="tv-row"/><circle cx="46" cy="50" r="7" fill="#1f7f5b"/><rect x="62" y="44" width="120" height="12" rx="6" class="tv-bar"/>
        <rect x="24" y="80" width="272" height="40" rx="10" class="tv-row tv-ask"/><circle cx="46" cy="100" r="7" fill="#c98a1a"/><rect x="62" y="94" width="150" height="12" rx="6" class="tv-bar"/>
        <rect x="24" y="130" width="272" height="40" rx="10" class="tv-row tv-block"/><circle cx="46" cy="150" r="7" fill="#c13a48"/><rect x="62" y="144" width="170" height="12" rx="6" class="tv-bar"/></svg>` },
    { kicker: "You decide", tone: "rose", title: "You decide, once.",
      body: `<p>When something needs your OK, press <kbd>A</kbd> to allow or <kbd>B</kbd> to block. No answer in time means blocked.</p><p>Choose <b>Always allow this</b> and Tripwire learns the rule. Forget it any time in settings.</p>`,
      visual: `<svg viewBox="0 0 320 200" class="tv"><rect x="28" y="40" width="264" height="120" rx="14" class="tv-card"/><rect x="48" y="60" width="180" height="14" rx="7" class="tv-bar"/><rect x="48" y="84" width="120" height="10" rx="5" class="tv-bar" opacity=".6"/>
        <rect x="48" y="112" width="92" height="30" rx="8" fill="#e0f3ea" stroke="#1f7f5b" stroke-opacity=".4"/><text x="94" y="131" class="tv-btn" fill="#1f7f5b">Allow  A</text>
        <rect x="150" y="112" width="92" height="30" rx="8" fill="#c13a48"/><text x="196" y="131" class="tv-btn" fill="#fff">Block  B</text></svg>` },
    { kicker: "Autonomy", tone: "teal", title: "Pick how much it decides alone.",
      body: `<ul class="tour-list tour-levels"><li><b>Strict</b><span>asks before anything outside your task.</span></li><li><b>Balanced</b><span>handles routine work in your project, asks when something leaves it.</span></li><li><b>Autonomous</b><span>only asks for sending data out, money and deleting.</span></li></ul><p class="tour-small">Blocks are blocks at every level. ${window.TW ? "On your machine, change it under the gear icon." : "Change it under the gear icon."}</p>`,
      visual: `<svg viewBox="0 0 320 200" class="tv"><rect x="40" y="88" width="240" height="10" rx="5" class="tv-bar"/><rect x="40" y="88" width="140" height="10" rx="5" fill="url(#tg2)"/><defs><linearGradient id="tg2" x1="0" x2="1"><stop offset="0" stop-color="#62c9c3"/><stop offset="1" stop-color="#6c7cf0"/></linearGradient></defs>
        <circle cx="180" cy="93" r="14" fill="#fff" stroke="#6c7cf0" stroke-width="3"/>
        <text x="40" y="130" class="tv-s">Strict</text><text x="160" y="130" class="tv-s" text-anchor="middle">Balanced</text><text x="280" y="130" class="tv-s" text-anchor="end">Autonomous</text></svg>` },
  ];
  const tour = { step: 0, open: false, restore: null };
  const tourEl = (id) => $(id);
  function tourSeen() { try { return localStorage.getItem(TOUR_SEEN) === "1"; } catch (_) { return true; } }
  function paintTour() {
    const st = STEPS[tour.step], last = STEPS.length - 1;
    el.tour.dataset.tone = st.tone;
    tourEl("tour-kicker").textContent = st.kicker;
    tourEl("tour-count").textContent = `${tour.step + 1} / ${STEPS.length}`;
    tourEl("tour-title").textContent = st.title;
    tourEl("tour-body").innerHTML = st.body;
    tourEl("tour-visual").innerHTML = st.visual;
    tourEl("tour-dots").innerHTML = STEPS.map((x, i) => `<button type="button" class="tour-dot${i === tour.step ? " on" : ""}${i < tour.step ? " done" : ""}" data-step="${i}" aria-label="Step ${i + 1}: ${esc(x.title)}" ${i === tour.step ? 'aria-current="step"' : ""}></button>`).join("");
    tourEl("tour-back").hidden = tour.step === 0;
    tourEl("tour-next").textContent = tour.step === 0 ? "Show me" : tour.step === last ? "Start" : "Next";
    for (const n of el.tour.querySelectorAll(".tour-content, .tour-visual")) { n.classList.remove("is-in"); void n.offsetWidth; n.classList.add("is-in"); }
    // The dots were just rebuilt, so a focused dot (or the Back button, now hidden on step 1) is gone.
    // Keep the keyboard inside the guide: back on the current dot, else on the dialog itself.
    const a = document.activeElement;
    if (a && a.classList && a.classList.contains("tour-dot")) return; // still attached: nothing to do
    if (!a || a === document.body || !el.tour.contains(a) || a.offsetParent === null) {
      (tour.dotFocus ? tourEl("tour-dots").querySelector(".tour-dot.on") : el.tour.querySelector(".tour-dialog")).focus({ preventScroll: true });
    }
  }
  function openTour() {
    if (tour.open) return;
    tour.step = 0; tour.open = true; tour.restore = document.activeElement; tour.dotFocus = false;
    el.tour.hidden = false;
    document.body.classList.add("tour-open");
    document.querySelector(".app").inert = true; // nothing behind the guide is reachable by Tab or a screen reader
    paintTour();
    el.tour.querySelector(".tour-dialog").focus({ preventScroll: true });
  }
  function closeTour() {
    if (!tour.open) return;
    tour.open = false;
    el.tour.hidden = true;
    document.body.classList.remove("tour-open");
    document.querySelector(".app").inert = false;
    try { if (tourEl("tour-again").checked) localStorage.setItem(TOUR_SEEN, "1"); else localStorage.removeItem(TOUR_SEEN); } catch (_) { /* private mode */ }
    if (tour.restore && tour.restore.focus) tour.restore.focus({ preventScroll: true });
    if (typeof tipsAfterGuide === "function") tipsAfterGuide();
  }
  function goTour(n) { tour.step = Math.max(0, Math.min(STEPS.length - 1, n)); paintTour(); }
  el.tour.addEventListener("click", async (e) => {
    if (e.target === el.tour) { closeTour(); return; }
    const d = e.target.closest("[data-step]");
    if (d) { tour.dotFocus = true; goTour(Number(d.dataset.step)); tour.dotFocus = false; return; }
    const c = e.target.closest("[data-copy]");
    if (c) {
      let ok = false;
      try { await navigator.clipboard.writeText(c.dataset.copy); ok = true; } catch (_) {
        const ta = document.createElement("textarea"); ta.value = c.dataset.copy; document.body.appendChild(ta); ta.select();
        try { ok = document.execCommand("copy"); } catch (_2) { /* no clipboard */ } ta.remove();
      }
      c.querySelector("span").textContent = ok ? "Copied" : "Select and copy";
      sayAloud(ok ? "Copied to the clipboard." : "Could not copy. Select the command and copy it.");
      setTimeout(() => { c.querySelector("span").textContent = "Copy"; }, 1600);
      return;
    }
    // A double click is two clicks: without this, double-clicking Next skipped a step, or closed the guide from step 4.
    if (e.detail > 1 && e.target.closest("#tour-next, #tour-back")) return;
    if (e.target.closest("#tour-skip")) closeTour();
    else if (e.target.closest("#tour-back")) goTour(tour.step - 1);
    else if (e.target.closest("#tour-next")) { if (tour.step === STEPS.length - 1) closeTour(); else goTour(tour.step + 1); }
  });
  // Keys are read on the document, not the dialog: a click on a dot used to drop focus to <body>, and from
  // there the arrows did nothing. Tab cycles by hand because Safari skips buttons on Tab and walked out of the guide.
  document.addEventListener("keydown", (e) => {
    if (!tour.open || e.metaKey || e.ctrlKey || e.altKey) return;
    const handled = ["Escape", "ArrowRight", "ArrowLeft", "Tab"].includes(e.key) || (e.key === "Enter" && !e.target.closest("button, input, a"));
    if (handled) e.stopPropagation(); // the dashboard's own keys (Escape closes a sheet, arrows move rows) stay quiet
    if (e.key === "Escape") { e.preventDefault(); closeTour(); }
    // On the last step, moving forward finishes the guide (it used to stay on step 5 forever).
    else if (e.key === "ArrowRight" || (e.key === "Enter" && !e.target.closest("button, input, a"))) {
      e.preventDefault();
      if (e.repeat) return; // a held key would race through every step and close the guide
      if (tour.step === STEPS.length - 1) closeTour(); else goTour(tour.step + 1);
    }
    else if (e.key === "ArrowLeft") { e.preventDefault(); if (!e.repeat) goTour(tour.step - 1); }
    else if (e.key === "Tab") {
      const f = [...el.tour.querySelectorAll("button, input")].filter((n) => !n.hidden && !n.disabled && n.offsetParent !== null);
      if (!f.length) return;
      e.preventDefault();
      const i = f.indexOf(document.activeElement);
      const next = i < 0 ? (e.shiftKey ? f.length - 1 : 0) : (i + (e.shiftKey ? -1 : 1) + f.length) % f.length;
      f[next].focus();
    }
  }, true);
  // The "?" menu: replay the guide, or show the tips that point at the real controls.
  const helpMenu = document.createElement("div");
  helpMenu.className = "pop pop-menu"; helpMenu.id = "help-menu"; helpMenu.hidden = true; helpMenu.setAttribute("role", "menu");
  helpMenu.innerHTML = `<button type="button" role="menuitem" id="help-guide">${icon("help")}Replay the guide<span>The five-step welcome</span></button>
    <button type="button" role="menuitem" id="help-tips">${icon("spark")}Show tips<span>Short pointers at each control</span></button>`;
  el.help.parentElement.insertBefore(helpMenu, el.help.nextSibling);
  el.help.setAttribute("aria-haspopup", "menu"); el.help.setAttribute("aria-expanded", "false"); el.help.setAttribute("aria-controls", "help-menu");
  function openHelp(open) {
    helpMenu.hidden = !open;
    el.help.setAttribute("aria-expanded", open);
    if (open) helpMenu.querySelector("button").focus({ preventScroll: true });
  }
  el.help.addEventListener("click", () => openHelp(helpMenu.hidden));
  helpMenu.addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    openHelp(false);
    if (b.id === "help-guide") openTour(); else startTips(tipsFor(), { force: true });
  });
  document.addEventListener("click", (e) => { if (!helpMenu.hidden && !e.target.closest("#help, #help-menu")) openHelp(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !helpMenu.hidden) { openHelp(false); el.help.focus({ preventScroll: true }); } });
  // First open: show the guide, unless this is the projector (?stage=1) or it was dismissed before.
  // Not on the projector, not when a deep link asks for a specific view (#demo), and not after "Don't show again".
  // The #demo check runs when the timer fires: the hosted page's ?scenario= link only switches to #demo after this file loads.
  if (!tourSeen() && !root.classList.contains("stage") && !new URLSearchParams(location.search).has("notour")) {
    setTimeout(() => { if (location.hash !== "#demo" && !tourSeen()) { tour.firstOpen = true; openTour(); } }, 400);
  }

  // ---- tips: short pointers at the real controls, once after the guide -----------------------------------
  // Each tip is one sentence anchored to an element on the page. A spotlight cutout and a small card with an
  // arrow; on a phone the card is a bottom sheet. Tips whose target is not on screen are skipped. Keys: ← → Enter
  // Esc, Tab cycles inside the card. Never auto-shown on the projector; "?" > Show tips brings them back.
  const TIPS_SEEN = "tw-tips-seen", TIPS_DEMO_SEEN = "tw-tips-demo-seen";
  const tipsSeen = (k) => { try { return localStorage.getItem(k) === "1"; } catch (_) { return true; } };
  const DASH_TIPS = [
    { sel: "#story:not([hidden])", text: "One sentence says what happened: where hidden instructions were, what was blocked, what went through." },
    { sel: "#timeline .row", text: "Every tool call lands here the moment it happens, newest first." },
    { sel: "#timeline .row .badge", text: "Allowed, Needs your OK or Blocked. Every one comes with a plain reason." },
    { sel: "#detail-body:not([hidden]) .d-path, #detail", text: "Pick a row: this shows where a value came from and why Tripwire decided the way it did." },
    { sel: "#queue-list .btn-allow", text: "Allow or Block waits for you. The A and B keys answer the first one.", alt: "#queue-list .q-item" },
    { sel: "#mode-seg", text: "Simple for plain words. Detailed adds every number, rule id and hash." },
    { sel: "#settings-btn", text: "How much Tripwire decides on its own, and the rules it learned from your answers." },
    { sel: "#tab-audit", text: "Every decision, tamper-evident and exportable." },
  ];
  const DEMO_TIPS = [
    { sel: "#scenarios", text: "Pick an attack: poisoned files, a web page, an email with hidden orders." },
    { sel: "#run-on", text: "Run it without Tripwire, then with. Hard floor makes the human allow everything, so you see what Tripwire stops alone." },
    { sel: "#scenarios [data-scn='custom']", text: "Write your own attack text and watch the engine judge it live." },
  ];
  const tipsFor = () => (document.body.contains(document.getElementById("demo-panel")) && !document.getElementById("demo-panel").hidden ? DEMO_TIPS : DASH_TIPS);
  const tips = { open: false, i: 0, list: [], el: null, hole: null, restore: null, key: TIPS_SEEN };
  function tipTarget(t) {
    for (const sel of [t.sel, t.alt].filter(Boolean)) {
      for (const n of document.querySelectorAll(sel)) {
        if (n.offsetParent === null && getComputedStyle(n).position !== "fixed") continue;
        const r = n.getBoundingClientRect();
        if (r.width > 2 && r.height > 2) return n;
      }
    }
    return null;
  }
  function buildTips() {
    if (tips.el) return;
    tips.hole = document.createElement("div"); tips.hole.className = "coach-hole"; tips.hole.setAttribute("aria-hidden", "true");
    tips.el = document.createElement("div"); tips.el.className = "coach"; tips.el.id = "coach"; tips.el.tabIndex = -1;
    tips.el.setAttribute("role", "dialog"); tips.el.setAttribute("aria-live", "polite");
    tips.el.innerHTML = `<div class="coach-arrow" aria-hidden="true"></div>
      <div class="coach-top"><span class="coach-count" id="coach-count"></span><button type="button" class="coach-skip" id="coach-skip">Skip all</button></div>
      <p class="coach-text" id="coach-text"></p>
      <div class="coach-foot"><label class="coach-again"><input type="checkbox" id="coach-again" checked> Don't show tips again</label>
        <div class="coach-actions"><button type="button" class="tour-btn tour-ghost" id="coach-back">Back</button><button type="button" class="tour-btn tour-primary" id="coach-next">Next</button></div></div>`;
    document.body.append(tips.hole, tips.el);
    tips.el.addEventListener("click", (e) => {
      if (e.detail > 1 && e.target.closest("#coach-next, #coach-back")) return;
      if (e.target.closest("#coach-skip")) endTips();
      else if (e.target.closest("#coach-back")) goTip(tips.i - 1);
      else if (e.target.closest("#coach-next")) goTip(tips.i + 1);
    });
    window.addEventListener("resize", () => tips.open && placeTip());
    window.addEventListener("scroll", () => tips.open && placeTip(), true);
  }
  function startTips(list, opt = {}) {
    if (tips.open || tour.open) return;
    tips.key = list === DEMO_TIPS ? TIPS_DEMO_SEEN : TIPS_SEEN;
    if (!opt.force && (tipsSeen(tips.key) || root.classList.contains("stage"))) return;
    tips.list = list.filter(tipTarget);
    if (!tips.list.length) return;
    buildTips();
    tips.open = true; tips.restore = document.activeElement; tips.i = -1;
    document.body.classList.add("coach-open");
    goTip(0);
  }
  function goTip(n) {
    if (n >= tips.list.length) { endTips(); return; }
    n = Math.max(0, n);
    const t = tips.list[n], target = tipTarget(t);
    if (!target) { tips.list.splice(n, 1); if (!tips.list.length) { endTips(); return; } goTip(Math.min(n, tips.list.length - 1)); return; }
    tips.i = n; tips.target = target;
    tips.el.querySelector("#coach-count").textContent = `Tip ${n + 1} of ${tips.list.length}`;
    tips.el.querySelector("#coach-text").textContent = t.text;
    tips.el.querySelector("#coach-back").disabled = n === 0;
    tips.el.querySelector("#coach-next").textContent = n === tips.list.length - 1 ? "Done" : "Next";
    tips.el.setAttribute("aria-label", `Tip ${n + 1} of ${tips.list.length}`);
    tips.el.hidden = false; tips.hole.hidden = false;
    tips.el.classList.remove("is-in"); void tips.el.offsetWidth; tips.el.classList.add("is-in");
    // "nearest": scroll only when the control is off-screen. "center" nudged the page on every first visit.
    target.scrollIntoView({ block: "nearest", inline: "nearest", behavior: reducedMotion() ? "auto" : "smooth" });
    placeTip();
    setTimeout(placeTip, 350);
    const a = document.activeElement;
    if (!a || !tips.el.contains(a)) tips.el.focus({ preventScroll: true });
  }
  function placeTip() {
    if (!tips.open || !tips.target) return;
    const r = tips.target.getBoundingClientRect(), pad = 6;
    Object.assign(tips.hole.style, { left: `${r.left - pad}px`, top: `${r.top - pad}px`, width: `${r.width + pad * 2}px`, height: `${r.height + pad * 2}px` });
    const card = tips.el, arrow = card.querySelector(".coach-arrow");
    if (phone.matches) { card.dataset.side = "sheet"; card.style.left = card.style.top = ""; return; }
    const W = card.offsetWidth, H = card.offsetHeight, vw = window.innerWidth, vh = window.innerHeight, gap = 14;
    const side = r.bottom + gap + H < vh ? "below" : r.top - gap - H > 0 ? "above"
      : r.right + gap + W < vw ? "right" : r.left - gap - W > 0 ? "left" : "over";
    let left, top;
    if (side === "below" || side === "above") {
      left = Math.min(Math.max(12, r.left + r.width / 2 - W / 2), vw - W - 12);
      top = side === "below" ? r.bottom + gap : r.top - gap - H;
      arrow.style.left = `${Math.max(16, Math.min(W - 16, r.left + r.width / 2 - left))}px`; arrow.style.top = "";
    } else if (side === "right" || side === "left") {
      left = side === "right" ? r.right + gap : r.left - gap - W;
      top = Math.min(Math.max(12, r.top + r.height / 2 - H / 2), vh - H - 12);
      arrow.style.top = `${Math.max(16, Math.min(H - 16, r.top + r.height / 2 - top))}px`; arrow.style.left = "";
    } else { // the target fills the screen (a panel): sit over its middle, no arrow
      left = Math.min(Math.max(12, r.left + r.width / 2 - W / 2), vw - W - 12);
      top = Math.min(Math.max(12, r.top + r.height / 2 - H / 2), vh - H - 12);
    }
    card.dataset.side = side;
    card.style.left = `${left}px`; card.style.top = `${top}px`;
  }
  function endTips() {
    if (!tips.open) return;
    tips.open = false;
    tips.el.hidden = true; tips.hole.hidden = true;
    document.body.classList.remove("coach-open");
    try { if (tips.el.querySelector("#coach-again").checked) localStorage.setItem(tips.key, "1"); else localStorage.removeItem(tips.key); } catch (_) { /* private mode */ }
    if (tips.restore && tips.restore.focus) tips.restore.focus({ preventScroll: true });
  }
  document.addEventListener("keydown", (e) => {
    if (!tips.open || e.metaKey || e.ctrlKey || e.altKey) return;
    const inButton = e.target.closest("button, input, a");
    const handled = ["Escape", "ArrowRight", "ArrowLeft", "Tab"].includes(e.key) || (e.key === "Enter" && !inButton);
    if (!handled) return;
    e.stopPropagation(); e.preventDefault();
    if (e.repeat) return;
    if (e.key === "Escape") endTips();
    else if (e.key === "ArrowRight" || e.key === "Enter") goTip(tips.i + 1);
    else if (e.key === "ArrowLeft") goTip(tips.i - 1);
    else if (e.key === "Tab") {
      const f = [...tips.el.querySelectorAll("button, input")].filter((n) => !n.disabled);
      const i = f.indexOf(document.activeElement);
      f[i < 0 ? (e.shiftKey ? f.length - 1 : 0) : (i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
    }
  }, true);
  // A click anywhere outside the card skips the rest (the page under a tip stays usable).
  document.addEventListener("click", (e) => { if (tips.open && !tips.el.contains(e.target)) endTips(); }, true);
  // Once after the first-open guide closes; the Demo tab gets its own three the first time it opens.
  const tipsAfterGuide = () => { if (tour.firstOpen) { tour.firstOpen = false; setTimeout(() => startTips(tipsFor()), 500); } };
  document.addEventListener("click", (e) => { if (e.target.closest("#tab-demo")) setTimeout(() => startTips(DEMO_TIPS), 600); });
  window.TWTips = { start: (which) => startTips(which === "demo" ? DEMO_TIPS : DASH_TIPS, { force: true }), end: endTips };

  // ---- live feed ------------------------------------------------------------
  function setConn(state) {
    el.conn.dataset.state = state;
    el.conn.querySelector(".conn-text").textContent = { live: "Live", connecting: "Connecting", down: "Offline", unpaired: "Not connected" }[state];
    el.offline.hidden = state !== "down" && state !== "unpaired";
    el.offline.dataset.kind = state === "unpaired" ? "unpaired" : "down";
    el.offline.querySelector("span").innerHTML = state === "unpaired"
      ? "This browser is not paired with your Tripwire yet. Run <code>tripwire open</code> in a terminal; it opens a paired tab."
      : "Agents fail closed while it is down: every tool call is denied. Retrying.";
    // Unpaired, the page sees nothing, so "Waiting for your agent" would be wrong: say what to do instead.
    const et = el.empty.querySelector(".empty-title"), ep = et && et.nextElementSibling;
    if (et && !et.dataset.orig) { et.dataset.orig = et.textContent; ep.dataset.orig = ep.textContent; }
    if (et) {
      et.textContent = state === "unpaired" ? "Connect this browser" : et.dataset.orig;
      ep.textContent = state === "unpaired" ? "Your agents' actions show up here once this browser is paired with Tripwire." : ep.dataset.orig;
    }
    el.offline.childNodes.forEach((n) => { if (n.nodeType === 3 && n.textContent.trim()) n.textContent = state === "unpaired" ? "Not connected." : "Tripwire is not reachable."; });
  }

  let es, retryT, hadError = false;
  function connect() {
    clearTimeout(retryT);
    if (es) es.close();
    setConn("connecting");
    es = new EventSource("/v1/events");
    es.onopen = () => {
      setConn("live");
      if (hadError) { hadError = false; loadAll().catch(() => {}); }
    };
    es.onerror = () => {
      hadError = true;
      setConn(es.readyState === EventSource.CLOSED ? "down" : "connecting");
      if (es.readyState === EventSource.CLOSED) retryT = setTimeout(connect, 3000);
      else setTimeout(() => { if (es.readyState !== EventSource.OPEN) setConn("down"); }, 4000);
    };
    const on = (name, fn) => es.addEventListener(name, (m) => {
      let data = {};
      try { data = JSON.parse(m.data || "{}"); } catch (_) { return; }
      fn(data);
    });
    on("verdict", (v) => {
      upsert(v, true);
      sortOrder();
      if (!S.sessions.some((s) => s.id === v.action.session_id)) refreshSessions(0);
      else {
        const s = S.sessions.find((x) => x.id === v.action.session_id);
        s.actions = (s.actions || 0) + 1;
      }
      if (S.followSession && v.action.session_id !== S.session) { S.session = v.action.session_id; S.selected = null; }
      const recentPick = Date.now() - S.manualPickAt < 20000;
      if ((v.decision !== "allow") && v.action.session_id === S.session && !recentPick && !phone.matches) S.selected = v.id;
      if (v.decision === "ask") refreshStats(300);
      announce(v);
      render();
      verifyChain(1500);
      if (S.view === "audit") loadTree(1500);
    });
    on("held", (d) => {
      if (d.id && d.deadline) { S.held.add(d.id); setDeadline(d.id, d.deadline * 1000); render(); }
    });
    on("resolved", (d) => {
      const v = S.verdicts.get(d.id);
      if (v) { v.decision = d.decision; v.resolved_by = d.by || "human"; }
      S.held.delete(d.id);
      S.deadlines.delete(d.id);
      S.firstSeen.delete(d.id);
      refreshStats();
      if (v) { S.history.delete(d.id); if (S.selected === d.id) loadHistory(v, true); }
      verifyChain(1500);
      render();
    });
    on("task", (t) => {
      S._lastTaskSession = t.session_id;
      if (S.followSession) S.session = t.session_id;
      refreshSessions(0);
    });
    on("observe", (o) => {
      if (o.injection && !S.injectSrc.has(o.session_id)) S.injectSrc.set(o.session_id, o.source || o.tool);
      refreshSessions(0);
    });
    on("reset", () => {
      S.verdicts.clear(); S.order = []; S.sessions = []; S.selected = null; S.session = null;
      S.followSession = true; S.held.clear(); S.deadlines.clear(); S.firstSeen.clear(); S.injectSrc.clear(); S._lastTaskSession = null;
      S.agent = null; S.history.clear(); S.tree = null;
      closeDetail();
      loadAll().catch(() => {});
      toast("Cleared. Ready for a fresh run.");
    });
    on("rule", () => loadRules(0));
    on("settings", (d) => { if (S.settings && d && d.autonomy) { S.settings.autonomy = d.autonomy; paintSettings(); } });
    on("ping", () => setConn("live"));
    on("pair_request", askPair);
  }

  // `tripwire open` in a terminal asks to pair a new browser. A paired dashboard can approve it, after the person
  // checks the 6 digits match the ones their own terminal shows (an agent's request shows different digits).
  const pairAsked = new Set();
  function askPair(d) {
    if (!d || !d.id || !/^\d{6}$/.test(d.digits || "") || pairAsked.has(d.id)) return;
    pairAsked.add(d.id);
    setTimeout(() => {
      const ok = window.confirm(`A terminal ran "tripwire open" and asks to connect a new browser to Tripwire.\n\n` +
        `Its code: ${d.digits.slice(0, 3)} ${d.digits.slice(3)}\n\nPress OK only if you ran it and this matches the code in your terminal. ` +
        `Otherwise press Cancel.`);
      api(`/v1/pair/requests/${encodeURIComponent(d.id)}`, { method: "POST", body: JSON.stringify({ decision: ok ? "allow" : "block" }) })
        .then(() => toast(ok ? "Approved. The new browser opens from your terminal." : "Turned down. No browser was paired."))
        .catch((e) => toast(e.message, 6000));
    }, 50);
  }
  function checkPairRequests() { api("/v1/pair/requests").then((rs) => rs.forEach(askPair)).catch(() => {}); }

  function start() {
    return pairFromHash().then(() => loadAll()).then(() => { checkPairRequests(); connect(); }).catch((e) => {
      if (e && e.status === 401) setConn("unpaired"); // no SSE retry loop: pairing needs a link from `tripwire open`
      else { setConn("down"); connect(); }
    });
  }
  // A pairing link pasted into a tab that already shows the page only changes the hash: pair then, too.
  // Paired in another tab? The cookie is shared, so coming back to this tab is enough to connect it.
  const retryPair = () => { if (el.conn.dataset.state === "unpaired" && document.visibilityState === "visible") start(); };
  window.addEventListener("focus", retryPair);
  document.addEventListener("visibilitychange", retryPair);
  window.addEventListener("hashchange", () => { if (/(?:^#|&)pair=/.test(location.hash)) { if (es) es.close(); start(); } });
  start();
})();
