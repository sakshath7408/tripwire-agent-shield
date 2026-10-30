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
  };

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
  };
  const phone = window.matchMedia("(max-width: 820px)");

  // ---- helpers -------------------------------------------------------------
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const icon = (name, cls = "") => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const WORD = { allow: "Allowed", ask: "Needs your OK", block: "Blocked" };
  const isPending = (v) => v.decision === "ask" && !v.resolved_by;
  const lvl = (n) => (n >= 80 ? "high" : n >= 50 ? "mid" : n > 0 ? "low" : "none");

  async function api(path, opts = {}) {
    const r = await fetch(path, { headers: { "content-type": "application/json" }, ...opts });
    if (!r.ok) throw new Error(`${r.status} ${await r.text().catch(() => "")}`.trim());
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
    return json === "{}" ? "(no arguments)" : json.length > 160 ? json.slice(0, 157) + "..." : json;
  }

  const CAPWORD = { read: "file read", write: "file edit", exec: "command", fetch: "web fetch", send: "message",
    money: "payment", delete: "delete", agent: "sub-agent", unknown: "tool call" };

  /** Summary without the decision prefix (the badge already says it) or the judge's note (shown on its own). */
  function cleanSummary(v) {
    let s = v.summary || "";
    s = s.replace(/^(Blocked|Needs your OK|Allowed):\s*/, "");
    s = s.replace(/\s*Judge:\s.*$/, "");
    const m = s.match(/^Looks like a normal (\w+) action\.(.*)$/);
    if (m) s = `Normal ${CAPWORD[m[1]] || m[1]}, nothing risky found.${m[2]}`;
    return s;
  }

  function byText(v) {
    if (v.resolved_by === "human") return v.decision === "allow" ? "Approved by you" : "Blocked by you";
    if (v.resolved_by === "timeout") return "No answer in time, so blocked";
    if (v.resolved_by) return "By " + v.resolved_by;
    if (judgeDecided(v)) return "Local judge agreed";
    return "";
  }
  const byHtml = (v) => {
    const t = byText(v);
    return t ? `<span class="by${v.resolved_by === "human" ? " by-you" : ""}">${esc(t)}</span>` : "";
  };
  const judgeDecided = (v) => v.judge && !v.judge.error && (v.judge.decision === "allow" || v.judge.decision === "block");

  /** Short session label: "demo-injected-doc-bcc9" -> name "demo-injected-doc", hash "bcc9". */
  function sessionParts(id) {
    const m = String(id).match(/^(.*?)[-_]([0-9a-f]{4,12})$/i);
    return m && m[1] ? { name: m[1], hash: m[2] } : { name: id, hash: "" };
  }

  const CAPDO = { read: "read a secret", write: "change files", exec: "run commands", fetch: "pull in outside content",
    send: "send data out", money: "move money", delete: "delete data", agent: "start another agent", credential: "change credentials", unknown: "use an unknown tool" };

  /** One sentence a stranger can read from across the room. */
  function storyFor(sess, vs) {
    if (!vs.length) return null;
    const blocked = vs.filter((v) => v.decision === "block");
    const pending = vs.filter(isPending);
    const allowed = vs.filter((v) => v.decision === "allow");
    const inj0 = sess && (sess.injections || [])[0];
    const src = (inj0 && (inj0.source || inj0.tool)) || (sess && S.injectSrc.get(sess.id));
    const tried = [...new Set(blocked.concat(pending).slice().reverse().map((v) => CAPDO[v.capability]).filter(Boolean))].slice(0, 3);
    const list = tried.length <= 1 ? tried.join("") : tried.slice(0, -1).join(", ") + " and " + tried[tried.length - 1];
    const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
    if (!blocked.length && !pending.length) {
      return { good: true, html: `<b>All clear.</b> ${n(allowed.length, "action", "actions")} so far, every one part of what you asked.` };
    }
    let html = "";
    if (src) html += `<b>Hidden instructions in <mark>${esc(src)}</mark></b> told the agent to ${esc(list || "do things you never asked for")}. `;
    else if (sess && sess.profile) html += `The agent tried to ${esc(list)}, which <b>${esc(sess.profile)}</b> may not do. `;
    else html += `The agent tried to ${esc(list)}, which you never asked for. `;
    if (blocked.length) html += `<b>Tripwire blocked ${pending.length ? n(blocked.length, "action", "actions") : blocked.length === 1 ? "it" : "all " + blocked.length}.</b> `;
    if (pending.length) html += `<b>${n(pending.length, "action is", "actions are")} waiting for you.</b> `;
    if (allowed.length) html += `<span class="dim">Your ${n(allowed.length, "task action", "task actions")} went through.</span>`;
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

  const viewVerdicts = () => S.order.map((id) => S.verdicts.get(id)).filter((v) => !S.session || v.action.session_id === S.session);

  // ---- render ----------------------------------------------------------------
  function render() {
    renderSessions();
    renderBrief();
    if (S.view === "live") {
      renderQueue();
      renderTimeline();
    } else {
      renderAudit();
    }
    renderDetail();
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
      const hot = vs.some(isPending) ? "ask" : vs.some((v) => v.decision === "block") ? "block" : "";
      const p = sessionParts(s.id);
      const state = hot === "ask" ? "waiting for you" : hot === "block" ? "has blocked actions" : "all clear";
      return `<button type="button" data-sid="${esc(s.id)}" aria-pressed="${s.id === S.session}" title="${esc(s.id)}: ${state}" aria-label="Session ${esc(s.id)}, ${state}"><span class="dot" data-hot="${hot}" aria-hidden="true"></span>${esc(p.name)}${p.hash ? `<span class="sid-hash">${esc(p.hash)}</span>` : ""}</button>`;
    }).join("");
    const on = el.sessions.querySelector('[aria-pressed="true"]');
    if (on && on.scrollIntoViewIfNeeded) on.scrollIntoViewIfNeeded(false);
    else if (on) on.scrollIntoView({ block: "nearest", inline: "nearest" });
    el.sessions.classList.toggle("is-scrolled", el.sessions.scrollLeft > 4);
  }
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
    for (const v of vs) { c[v.decision] = (c[v.decision] || 0) + 1; ms += v.elapsed_ms || 0; }
    setStat(el.nAllow, c.allow);
    setStat(el.nAsk, c.ask);
    setStat(el.nBlock, c.block);
    el.msNote.textContent = vs.length ? `${fmtMs(ms / vs.length)} ms per decision` : "";

    const story = storyFor(sess, vs);
    el.story.hidden = !story;
    if (story) {
      el.story.classList.toggle("story-good", story.good);
      el.story.querySelector("use").setAttribute("href", story.good ? "#i-allow" : "#i-hidden");
      el.storyText.innerHTML = story.html;
    }
  }
  function setStat(node, n) {
    const was = node.textContent;
    node.textContent = n;
    node.parentElement.classList.toggle("is-zero", !n);
    if (was !== String(n) && Number(was) < n) {
      node.parentElement.classList.remove("is-bump");
      void node.offsetWidth;
      node.parentElement.classList.add("is-bump");
    }
  }

  function decideButtons(id) {
    return `<div class="q-buttons">
      <button type="button" class="btn-decide btn-allow" data-resolve="allow" data-id="${id}">${icon("allow")}Allow<kbd aria-hidden="true">A</kbd></button>
      <button type="button" class="btn-decide btn-block" data-resolve="block" data-id="${id}">${icon("block")}Block<kbd aria-hidden="true">B</kbd></button>
    </div>`;
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
        <div class="q-meta"><span class="tool">${esc(toolLabel(v.action.tool))}</span><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span>${riskHtml(v.risk)}</div>
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
        <div class="row-act"><span class="tool">${esc(toolLabel(v.action.tool))}</span><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span></div>
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
      const sig = `${v.decision}|${v.resolved_by}|${v.summary}|${S.held.has(v.id)}`;
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
      const clean = vs.length > 0 && vs.every((x) => x.decision === "allow");
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
    if (el.detailBody.dataset.id !== v.id) { el.detail.scrollTop = 0; el.detailBody.dataset.id = v.id; }

    el.detailBody.innerHTML = `
      <div class="d-top"><div class="d-head"><div>${badge(v.decision)}${byHtml(v)}</div>
        <button type="button" class="d-close" data-close aria-label="Close details">${icon("close")}</button></div>
      <p class="d-sum">${esc(cleanSummary(v))}</p>
      ${pending ? `<div class="d-decide">${decideButtons(v.id)}${cd ? `<span class="countdown${isUrgent(v.id) ? " is-urgent" : ""}" data-cd="${v.id}">${cd}</span>` : ""}</div>` : ""}</div>
      <div class="d-act">${esc(renderAct(v))}</div>
      <div class="d-facts">
        <div><span>Tool</span><b>${esc(t.name)}${t.server ? ` <small>(${esc(t.server)})</small>` : ""}</b></div>
        <div><span>Kind</span><b>${esc(CAPWORD[v.capability] || v.capability)}</b></div>
        <div><span>Risk</span><b>${v.risk}<small> / 100</small></b></div>
        <div><span>Decided in</span><b>${fmtMs(v.elapsed_ms)}<small> ms</small></b></div>
      </div>
      <div class="d-section"><h3>Why${findings.length > 1 ? `<span class="n">${findings.length} findings</span>` : ""}</h3>
        ${findings.length ? `<ol class="findings">${findings.map((f) => `
          <li class="finding${f.message === cleanSummary(v) ? " is-headline" : ""}" data-lvl="${lvl(f.severity)}">
            <div class="f-msg"><span class="sev" data-lvl="${lvl(f.severity)}" title="Severity ${Math.min(100, f.severity)} of 100">${Math.min(100, f.severity)}</span><span>${esc(f.message)}</span></div>
            ${f.evidence ? `<div class="evidence"><div class="ev-src">${icon("doc")}From ${esc(evidenceSource(f))}, not from you</div><div class="ev-text">…${highlight(f.evidence, v, f)}…</div></div>` : ""}
            <div class="f-tags">${f.message === cleanSummary(v) ? `<span class="sev" data-lvl="${lvl(f.severity)}" title="Severity ${Math.min(100, f.severity)} of 100">${Math.min(100, f.severity)}</span>` : ""}<span class="tag">${esc(f.category)}</span><span class="rule">${esc(f.rule)}</span></div>
          </li>`).join("")}</ol>` : `<p class="muted-p">Nothing risky found. It matches a normal ${esc(CAPWORD[v.capability] || "action")} for what you asked.</p>`}
      </div>
      ${judgeHtml(v)}
      <details class="d-more"><summary>Full arguments</summary><pre class="json">${esc(JSON.stringify(v.action.args, null, 2))}</pre></details>
      <div class="d-id">${fmtTime(v.ts)} · session ${esc(v.action.session_id)} · via ${esc(v.action.source)} · id ${esc(v.id)}</div>`;
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
    const all = S.order.map((id) => S.verdicts.get(id));
    el.auditNote.textContent = all.length
      ? `${all.length} ${all.length === 1 ? "decision" : "decisions"} across ${new Set(all.map((v) => v.action.session_id)).size} ${new Set(all.map((v) => v.action.session_id)).size === 1 ? "session" : "sessions"}, newest first.`
      : "No decisions yet.";
    el.auditCount.textContent = all.length || "";
    el.auditRows.innerHTML = all.map((v) => {
      const who = v.resolved_by === "human" ? `<span class="who-human">You</span>` : v.resolved_by === "timeout" ? `<span class="who-timeout">Timed out</span>` : v.resolved_by ? esc(v.resolved_by) : isPending(v) ? `<span class="who-wait">Waiting</span>` : judgeDecided(v) ? "Tripwire + judge" : "Tripwire";
      return `<tr data-id="${v.id}" tabindex="0"><td>${fmtTime(v.ts)}</td><td class="sid" title="${esc(v.action.session_id)}">${esc(sessionParts(v.action.session_id).name)}</td><td class="tool">${esc(toolLabel(v.action.tool))}</td>
        <td><span class="act" title="${esc(renderAct(v))}">${esc(renderAct(v))}</span></td><td>${badge(v.decision)}</td><td><span class="why" title="${esc(cleanSummary(v))}">${esc(cleanSummary(v))}</span></td><td>${who}</td>
        <td class="num">${v.risk}</td><td class="num">${fmtMs(v.elapsed_ms)}</td></tr>`;
    }).join("");
  }

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
  function toast(msg) {
    el.toast.textContent = msg;
    el.toast.hidden = false;
    clearTimeout(toastT);
    toastT = setTimeout(() => (el.toast.hidden = true), 3200);
  }

  async function resolve(id, decision, btn) {
    const btns = document.querySelectorAll(`[data-resolve][data-id="${id}"]`);
    btns.forEach((b) => (b.disabled = true));
    try {
      await api(`/v1/verdicts/${id}/resolve`, { method: "POST", body: JSON.stringify({ decision }) });
      const v = S.verdicts.get(id);
      if (v) { v.decision = decision; v.resolved_by = "human"; }
      refreshStats(0);
      if (phone.matches && el.detail.classList.contains("is-open")) { closeDetail(); return; } // show the next waiting item
      render();
    } catch (e) {
      btns.forEach((b) => (b.disabled = false));
      toast(String(e.message).startsWith("404") ? "That action is gone. The log was probably reset." : `Couldn't send your answer: ${e.message}`);
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

  document.addEventListener("click", (e) => {
    const r = e.target.closest("[data-resolve]");
    if (r) { e.stopPropagation(); resolve(r.dataset.id, r.dataset.resolve, r); return; }
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
    if (typing) return;
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
  });
  paintStage();

  /** Screen readers hear every block and every question, without the page moving focus. */
  function announce(v) {
    if (v.decision === "allow") return;
    el.announce.textContent = "";
    setTimeout(() => { el.announce.textContent = `${WORD[v.decision]}: ${cleanSummary(v)}`; }, 50);
  }

  function setView(view) {
    S.view = view;
    el.tabLive.setAttribute("aria-selected", view === "live");
    el.tabAudit.setAttribute("aria-selected", view === "audit");
    el.live.hidden = view !== "live";
    el.audit.hidden = view !== "audit";
    document.body.dataset.view = view;
    if (view === "audit") el.empty.hidden = true;
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
      toast(`Couldn't export: ${e.message}`);
    }
  });

  // Reset asks for a second click instead of a native dialog (cleaner on a projector).
  let armT;
  el.reset.addEventListener("click", async () => {
    const label = el.reset.querySelector("span");
    if (!el.reset.dataset.armed) {
      el.reset.dataset.armed = "1";
      label.textContent = "Click again to clear";
      armT = setTimeout(() => { delete el.reset.dataset.armed; label.textContent = "Reset"; }, 3000);
      return;
    }
    clearTimeout(armT);
    delete el.reset.dataset.armed;
    label.textContent = "Reset";
    try { await api("/v1/reset", { method: "POST" }); } catch (e) { toast(`Couldn't reset: ${e.message}`); }
  });

  // ---- live feed ------------------------------------------------------------
  function setConn(state) {
    el.conn.dataset.state = state;
    el.conn.querySelector(".conn-text").textContent = { live: "Live", connecting: "Connecting", down: "Offline" }[state];
    el.offline.hidden = state !== "down";
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
      closeDetail();
      loadAll().catch(() => {});
      toast("Cleared. Ready for a fresh run.");
    });
    on("ping", () => setConn("live"));
  }

  loadAll().catch(() => setConn("down")).finally(connect);
})();
