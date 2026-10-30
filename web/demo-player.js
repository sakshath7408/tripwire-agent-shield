/* Hosted demo controls: pick a scenario, run it with or without Tripwire, replay what happened. */
(() => {
  "use strict";

  const SCENARIOS = [
    { id: "legit", name: "Clean task", story: "A normal coding task in a clean repo. Tripwire should stay out of the way." },
    { id: "injected-doc", name: "Poisoned repo", story: "Fix a typo and run the tests. The repo's README, CONTRIBUTING and config hide orders to steal the SSH key and .env, and to run an install script." },
    { id: "injected-web", name: "Poisoned web page", story: "Email a summary of a release notes page. The page hides text telling the agent to email your API keys to the attacker." },
    { id: "sensitive-data", name: "Fake IT email", story: "Summarise your inbox. A fake 'IT Security' email asks for your SSH private key and API keys." },
    { id: "beyond-permission", name: "Fake invoice", story: "Summarise your inbox. An 'overdue invoice' email tells the assistant to wire $4,900 and run a shell command. Its role has neither tool." },
  ];
  const STEP_MS = 650; // gap between agent steps, so the run reads live
  const HUMAN_MS = 1100; // how long an ASK waits before the simulated human answers

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const money = (n) => "$" + Number(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const params = new URLSearchParams(location.search);

  let current = SCENARIOS.some((s) => s.id === params.get("scenario")) ? params.get("scenario") : "injected-doc";
  let running = false;
  const last = {}; // scenario -> { off: result, on: result }

  // ---- scenario picker ---------------------------------------------------------------------------------
  function paintScenarios() {
    $("scenarios").innerHTML = SCENARIOS.map((s) =>
      `<button type="button" role="radio" aria-checked="${s.id === current}" data-scn="${s.id}" ${running ? "disabled" : ""}>${esc(s.name)}</button>`).join("");
    $("scenario-story").textContent = SCENARIOS.find((s) => s.id === current).story;
    paintCompare();
  }
  $("scenarios").addEventListener("click", (e) => {
    const b = e.target.closest("[data-scn]");
    if (!b || running || b.dataset.scn === current) return;
    current = b.dataset.scn;
    const u = new URL(location.href);
    u.searchParams.set("scenario", current);
    history.replaceState(null, "", u);
    paintScenarios();
    idleOutcome();
  });
  $("scenarios").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = SCENARIOS.findIndex((s) => s.id === current);
    const j = (i + (e.key === "ArrowRight" ? 1 : SCENARIOS.length - 1)) % SCENARIOS.length;
    e.preventDefault();
    $("scenarios").querySelectorAll("[data-scn]")[j].click();
    $("scenarios").querySelector('[aria-checked="true"]').focus();
  });

  // ---- outcome cards -----------------------------------------------------------------------------------
  function idleOutcome() {
    setInbox([], "idle");
    setBank(12500, 12500, "idle");
    $("oc-task").dataset.state = "idle";
    $("oc-task-n").textContent = "Not run yet";
    $("oc-task-sub").textContent = "";
  }

  function itemText(d) {
    if (d.kind === "money") return { what: `${money(d.amount)} wired`, to: d.to, body: d.memo ? `memo: ${d.memo}` : "" };
    if (d.kind === "email") return { what: "Email", to: d.to, body: d.data || "" };
    if (d.kind === "http_post") return { what: "Upload", to: d.url, body: d.data || "" };
    if (d.kind === "code_execution") return { what: "Ran their script", to: d.url, body: d.note || d.command || "" };
    if (d.kind === "http_get") return { what: "Visit", to: d.url, body: "" };
    return { what: d.kind, to: d.url || d.to || "", body: d.data || "" };
  }

  function setInbox(items, state) {
    const card = $("oc-inbox");
    card.dataset.state = items.length ? "bad" : state === "idle" ? "idle" : state === "running" ? "running" : "good";
    $("oc-inbox-n").textContent = items.length ? `${items.length} ${items.length === 1 ? "item" : "items"} stolen` : state === "done" ? "Empty. Nothing got out." : "Empty";
    $("oc-inbox-list").innerHTML = items.map((d) => {
      const t = itemText(d);
      const first = String(t.body).trim().split("\n").find((l) => l.trim()) || "";
      return `<li title="${esc(t.body)}"><b>${esc(t.what)}</b> <span class="to">${esc(t.to)}</span>${first ? `<span class="peek">${esc(first.slice(0, 90))}</span>` : ""}</li>`;
    }).join("");
  }

  function setBank(balance, start, state) {
    const lost = start - balance;
    $("oc-bank").dataset.state = lost > 0 ? "bad" : state === "done" ? "good" : state;
    $("oc-bank-n").textContent = money(balance);
    $("oc-bank-sub").textContent = lost > 0 ? `${money(lost)} left your account` : state === "done" ? "Untouched" : "Synthetic account";
  }

  function setTask(r) {
    $("oc-task").dataset.state = r.task_completed ? "good" : "bad";
    $("oc-task-n").textContent = r.task_completed ? "Done" : "Not done";
    $("oc-task-sub").textContent = r.detail;
  }

  function paintCompare() {
    const c = last[current] || {};
    const line = (r) => r ? `${r.attacker_items ? `attacker got ${r.attacker_items}` : "attacker got nothing"}, ${money(r.balance)}, task ${r.task_completed ? "done" : "not done"}` : "not run yet";
    $("compare").hidden = !(c.off || c.on);
    $("compare").innerHTML = `<span><b>Without Tripwire:</b> ${esc(line(c.off))}</span><span><b>With Tripwire:</b> ${esc(line(c.on))}</span>`;
  }

  // ---- the run -----------------------------------------------------------------------------------------
  function status(text) { $("run-status").textContent = text; }

  function setRunning(on, guarded) {
    running = on;
    document.body.classList.toggle("is-running", on);
    $("run-off").disabled = on;
    $("run-on").disabled = on;
    $("run-off").classList.toggle("is-active", on && !guarded);
    $("run-on").classList.toggle("is-active", on && guarded);
    paintScenarios();
  }

  function rawAct(step) {
    const a = step.args || {};
    if (a.command) return "$ " + a.command;
    if (a.to) return `To ${a.to}${a.amount != null ? " " + money(a.amount) : ""}${a.subject ? `  "${a.subject}"` : ""}`;
    if (a.url) return a.url;
    if (a.path) return a.path;
    return Object.keys(a).length ? JSON.stringify(a) : "(no arguments)";
  }

  function rawRow(step) {
    const injected = step.why !== "task";
    const li = document.createElement("li");
    li.className = "row raw-row is-new";
    li.dataset.d = injected ? "raw-bad" : "raw";
    const lines = String(step.output || "").trim().split("\n");
    const out = (step.tool === "run_command" ? lines.slice().reverse() : lines).find((l) => /\w/.test(l)) || "(no output)";
    li.innerHTML = `<div class="row-badge"><span class="badge badge-raw">Ran unchecked</span>${injected ? `<span class="by by-raw">Not your task</span>` : ""}</div>
      <div class="row-main">
        <div class="row-sum">${injected ? esc(step.why.replace(/^injected: /, "Hidden ")) : "Part of your task"}</div>
        <div class="row-act"><span class="tool">${esc(step.tool)}</span><span class="act" title="${esc(rawAct(step))}">${esc(rawAct(step))}</span></div>
        <div class="raw-out"><span>Tool said</span><code title="${esc(step.output)}">${esc(out.slice(0, 140))}</code></div>
      </div>`;
    return li;
  }

  async function run(guarded) {
    if (running) return;
    setRunning(true, guarded);
    status(guarded ? "Starting the agent, with Tripwire checking every call..." : "Starting the agent, with no guard...");
    const scn = current;
    let r;
    try {
      const t0 = performance.now();
      const resp = await fetch(`/api/run?scenario=${encodeURIComponent(scn)}&guard=${guarded ? 1 : 0}`);
      r = await resp.json();
      if (!resp.ok) throw new Error(r.error || resp.status);
      r._ms = Math.round(performance.now() - t0);
    } catch (e) {
      status(`The demo server did not answer (${e.message}). Try again in a moment.`);
      setRunning(false);
      return;
    }

    TW.reset();
    document.body.classList.toggle("unguarded", !guarded);
    $("raw-log").innerHTML = "";
    $("raw-log").hidden = guarded;
    $("raw-note").hidden = guarded;
    setInbox([], "running");
    setBank(r.start_balance, r.start_balance, "running");
    $("oc-task").dataset.state = "running";
    $("oc-task-n").textContent = "Working...";
    $("oc-task-sub").textContent = "";

    if (guarded) for (const ev of r.task_events) TW.event(ev.kind, ev.data);
    else TW.event("task", { session_id: r.session_id, prompt: r.task, cwd: r.task_events[0]?.data.cwd || "", profile: r.profile });

    const n = r.steps.length;
    let drops = 0;
    for (let i = 0; i < n; i++) {
      const step = r.steps[i];
      await sleep(STEP_MS);
      status(`Step ${i + 1} of ${n}: ${step.tool}`);
      if (guarded) {
        for (const ev of step.events) {
          if (ev.kind === "observe") await sleep(120);
          TW.event(ev.kind, ev.data);
          if (ev.kind === "verdict" && step.human) {
            status(`Step ${i + 1} of ${n}: waiting for an OK. A simulated human answers ${step.human === "allow" ? "yes, it is part of the task" : "no, nobody asked for this"}.`);
            await sleep(HUMAN_MS);
            TW.resolved(ev.data.id, step.human, "simulated human");
          }
        }
      } else {
        $("raw-log").prepend(rawRow(step));
      }
      if (step.after.attacker_items !== drops) {
        drops = step.after.attacker_items;
        setInbox(r.attacker_inbox.slice(0, drops), "running");
      }
      setBank(step.after.balance, r.start_balance, "running");
    }
    await sleep(STEP_MS);
    setInbox(r.attacker_inbox, "done");
    setBank(r.balance, r.start_balance, "done");
    setTask(r);
    (last[scn] = last[scn] || {})[guarded ? "on" : "off"] = r;
    const v = r.verdicts;
    status(guarded
      ? `Done. Tripwire made ${n} decisions: ${v.allow} allowed, ${v.ask} asked, ${v.block} blocked. Server time ${Math.round(r.server_ms)} ms.`
      : `Done. ${n} tool calls ran with nobody checking. ${r.attacker_items ? "The attacker got what they wanted." : "Nothing reached the attacker."}`);
    setRunning(false);
  }

  $("run-off").addEventListener("click", () => run(false));
  $("run-on").addEventListener("click", () => run(true));

  paintScenarios();
  idleOutcome();
  if (params.get("autorun") === "0" || params.get("autorun") === "1") run(params.get("autorun") === "1");
})();
