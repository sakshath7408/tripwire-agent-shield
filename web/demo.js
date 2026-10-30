/* Hosted demo adapter. Loaded before the dashboard's own app.js, which runs unchanged.

   On your machine the dashboard talks to the Tripwire daemon: GET /v1/verdicts, /v1/stats, /v1/sessions and an
   SSE stream at /v1/events. A static host has no daemon, so this file answers those same calls from memory, and
   demo-player.js fills that memory by replaying the engine events that /api/run recorded on the server. */
(() => {
  "use strict";

  const store = { verdicts: [], sessions: [] }; // verdicts newest first, like the daemon
  let stream = null;

  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  function stats() {
    const c = { allow: 0, ask: 0, block: 0 };
    for (const v of store.verdicts) c[v.decision] = (c[v.decision] || 0) + 1;
    const n = store.verdicts.length;
    return { total: n, ...c, categories: {}, sessions: store.sessions.length, pending: [], uptime_s: 0, judge: false,
      avg_ms: n ? store.verdicts.reduce((a, v) => a + (v.elapsed_ms || 0), 0) / n : 0 };
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, opts = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    const p = url.pathname;
    if (url.origin === location.origin && p === "/healthz") return json({ ok: true, demo: true });
    if (url.origin !== location.origin || !p.startsWith("/v1/")) return realFetch(input, opts);
    if (p === "/v1/verdicts") return json(store.verdicts.slice(0, Number(url.searchParams.get("limit")) || 500));
    if (p === "/v1/stats") return json(stats());
    if (p === "/v1/sessions") return json(store.sessions);
    if (p === "/v1/reset") { TW.reset(); return json({ ok: true }); }
    if (p === "/v1/pair") return json({ ok: true }); // no daemon here, nothing to pair with
    if (/^\/v1\/verdicts\/[^/]+\/resolve$/.test(p)) {
      return json({ detail: "On the hosted demo a simulated human answers. It sees only Tripwire's reason, where the call goes and your task." }, 409);
    }
    return json({ detail: "not available on the hosted demo" }, 404);
  };

  /** Stands in for the SSE connection to the daemon. */
  class DemoEventSource {
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      this.handlers = {};
      stream = this;
      setTimeout(() => { this.readyState = 1; if (this.onopen) this.onopen(); }, 0);
    }
    addEventListener(name, fn) { (this.handlers[name] = this.handlers[name] || []).push(fn); }
    close() { this.readyState = 2; if (stream === this) stream = null; }
  }
  DemoEventSource.CONNECTING = 0; DemoEventSource.OPEN = 1; DemoEventSource.CLOSED = 2;
  window.EventSource = DemoEventSource;

  function emit(kind, data) {
    if (!stream) return;
    for (const fn of stream.handlers[kind] || []) fn({ data: JSON.stringify(data) });
  }

  window.TW = {
    /** The welcome guide's "where does this run" line, worded for a hosted preview. */
    hostedNote: "Tripwire runs on your machine. This page is a hosted preview; the Demo tab runs a synthetic world on our server.",
    /** Clear everything, the same way POST /v1/reset does on the daemon. */
    reset() {
      store.verdicts = [];
      store.sessions = [];
      emit("reset", {});
      const t = document.getElementById("toast"); // the dashboard toasts "Cleared"; a new run doesn't need it
      if (t) t.hidden = true;
    },
    /** One engine event, as /api/run recorded it (task, observe or verdict). */
    event(kind, data) {
      if (kind === "task") {
        store.sessions = store.sessions.filter((s) => s.id !== data.session_id);
        store.sessions.push({ id: data.session_id, cwd: data.cwd, task: data.prompt, profile: data.profile,
          injection_seen: 0, injections: [], secrets_read: [], actions: 0 });
      }
      if (kind === "verdict") {
        store.verdicts = [data, ...store.verdicts.filter((v) => v.id !== data.id)];
        const s = store.sessions.find((x) => x.id === data.action.session_id);
        if (s) s.actions += 1;
      }
      emit(kind, data);
    },
    /** The simulated human answered an ASK. */
    resolved(id, decision, by) {
      const v = store.verdicts.find((x) => x.id === id);
      if (v) { v.decision = decision; v.resolved_by = by; }
      emit("resolved", { id, decision, by });
    },
  };
})();
