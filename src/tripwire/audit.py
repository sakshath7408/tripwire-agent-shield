"""Tamper-evident, append-only audit log with a cross-agent trail.

Every event (a verdict, a human or timeout resolution, a task, an observed tool output) is one row.
Rows are chained:

    hash = SHA-256( prev_hash + canonical JSON of the record )
    hmac = HMAC-SHA256( audit key, hash )

The record is every stored field except the three chain columns, so changing any field of any row
breaks its hash, and the next row's prev_hash. Deleting or reordering rows breaks `seq` continuity
and prev_hash. Deleting the newest rows is caught by the signed head (last seq + hash, HMAC'd), kept
in the same database and updated in the same transaction as the rows. The HMAC means someone with
write access to audit.db but not to the 0600 key cannot rebuild a consistent chain after editing.

Nothing is ever rewritten. A human Allow/Block or a timeout is a new `resolution` row that points
at the verdict (`ref`). Readers fold resolutions into the verdict they belong to.

Limits, stated plainly: a person who holds the key can rewrite the whole log, and restoring an
entire older copy of audit.db is not detectable from the file alone (keep an export elsewhere for
that). Rows written before this format (old Tripwire versions) are kept but not covered; the chain
starts with a `chain_start` row that says how many there were.

Agents: every event carries `agent` (who acted), `parent` (who spawned it, if anyone) and `trace`
(the root agent of that tree). A sub-agent's events land in its parent's trace.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Iterator

log = logging.getLogger("tripwire.audit")

GENESIS = "0" * 64
CHAIN_FIELDS = ("seq", "id", "ts", "kind", "ref", "session", "agent", "parent", "trace", "tool", "decision", "risk", "json")
LEGACY_COLS = ("id", "ts", "session", "tool", "decision", "risk", "json")
NEW_COLS = {"kind": "text", "ref": "text", "agent": "text", "parent": "text", "trace": "text",
            "seq": "integer", "prev_hash": "text", "hash": "text", "hmac": "text"}
SPAWN_TOOLS = ("task", "agent")


def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record_hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical({k: record.get(k) for k in CHAIN_FIELDS})).hexdigest()


def sign(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"tripwire-audit-key:" + key).hexdigest()[:16]


def load_key(path: Path, create: bool = True) -> bytes | None:
    """The audit key: 32 random bytes, hex, mode 0600, created once. Never overwritten."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            key = secrets.token_bytes(32)
            with os.fdopen(fd, "w") as f:
                f.write(key.hex())
            return key
    try:
        key = bytes.fromhex(path.read_text().strip())
    except FileNotFoundError:
        return None
    if len(key) < 32:
        raise ValueError(f"audit key at {path} is too short")
    return key


def default_key_path(db_path: Path) -> Path:
    """The key sits next to the database: ~/.tripwire/audit.key for ~/.tripwire/audit.db."""
    return db_path.with_name("audit.key")


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False, timeout=10)
    db.execute("pragma journal_mode=wal")
    db.execute("pragma synchronous=normal")
    return db


def migrate(db: sqlite3.Connection) -> None:
    """Old format: verdicts(id, ts, session, tool, decision, risk, json), one row per verdict,
    rewritten in place on resolve. Add the chain columns; old rows keep NULL seq and stay as they were."""
    db.execute("create table if not exists verdicts (id text primary key, ts real, session text, tool text, decision text, risk int, json text)")
    have = {r[1] for r in db.execute("pragma table_info(verdicts)")}
    for col, typ in NEW_COLS.items():
        if col not in have:
            db.execute(f"alter table verdicts add column {col} {typ}")
    db.execute("create unique index if not exists verdicts_seq on verdicts(seq) where seq is not null")
    db.execute("create index if not exists verdicts_trace on verdicts(trace)")
    db.execute("create index if not exists verdicts_agent on verdicts(agent)")
    db.execute("create index if not exists verdicts_ref on verdicts(ref)")
    db.execute("create table if not exists audit_head (id integer primary key check (id = 1), seq integer, hash text, hmac text)")
    db.commit()


class Audit:
    """Writes go through one background thread so /v1/evaluate never waits on disk.

    Failure policy (deliberate): the engine has already decided, and its decision is the safe one
    (it fails closed on its own errors). If the audit write fails (disk full, db locked, bad
    permissions) we still return that decision. Refusing every tool call because the log is broken
    would turn a disk problem into an outage for every agent, and a held ASK would leave the agent
    hanging. Instead the failure is loud: logged at ERROR on every failed attempt, /healthz reports
    audit "degraded" with the error, and unwritten events stay queued in order and are retried, so
    the chain has no holes once the disk recovers. Only if more than MAX_BACKLOG events pile up do
    we drop the oldest, and that is counted and reported too.
    """

    MAX_BACKLOG = 100_000

    def __init__(self, path: Path, key_path: Path | None = None, background: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path = key_path or default_key_path(self.path)
        self.key = load_key(self.key_path)
        self.kid = key_id(self.key)
        self.db = connect(self.path)  # writer connection (used only by the writer, or under _wlock)
        migrate(self.db)
        self._wlock = threading.Lock()
        self._cv = threading.Condition()
        self._queue: deque[dict] = deque()
        self.enqueued = self.written = self.dropped = 0
        self.error: str | None = None
        self.last_error_ts: float | None = None
        self.write_ms: deque[float] = deque(maxlen=500)
        self.agents: dict[str, dict] = {}  # agent -> {"parent", "trace"}
        self._alock = threading.Lock()
        self._rebuild_agents()
        self._ensure_chain()
        self._stop = False
        self._thread: threading.Thread | None = None
        if background:
            self._thread = threading.Thread(target=self._run, name="tripwire-audit", daemon=True)
            self._thread.start()

    # ---- agent tree ------------------------------------------------------------
    def _rebuild_agents(self) -> None:
        for agent, parent, trace in self.db.execute(
                "select agent, parent, trace from verdicts where seq is not null and agent is not null order by seq"):
            self.agents.setdefault(agent, {"parent": parent, "trace": trace or agent})

    def register(self, agent: str, parent: str | None) -> str:
        """Record who spawned whom and return the trace (root agent) this agent belongs to."""
        with self._alock:
            known = self.agents.get(agent)
            if known and (known["parent"] or not parent):
                return known["trace"]
            if parent and parent != agent:
                if parent not in self.agents:
                    self.agents[parent] = {"parent": None, "trace": parent}
                # walk up, guarding against a cycle a confused caller could create
                trace, seen, cur = parent, {agent}, parent
                while cur and cur not in seen:
                    seen.add(cur)
                    trace = cur
                    cur = self.agents.get(cur, {}).get("parent")
                self.agents[agent] = {"parent": parent, "trace": trace}
            else:
                self.agents[agent] = {"parent": None, "trace": agent}
            return self.agents[agent]["trace"]

    # ---- writing ---------------------------------------------------------------
    def _ensure_chain(self) -> None:
        with self._wlock:
            if self.db.execute("select 1 from verdicts where seq is not null limit 1").fetchone():
                return
            legacy = self.db.execute("select count(*) from verdicts where seq is null").fetchone()[0]
            note = (f"Tamper-evident chain starts here. {legacy} older row(s) above were written before "
                    "chaining and are not covered." if legacy else "Tamper-evident chain starts here.")
            self._write([{"id": f"chain-{uuid.uuid4().hex[:8]}", "ts": time.time(), "kind": "chain_start",
                          "json": json.dumps({"note": note, "legacy_rows": legacy, "key_id": self.kid})}])

    def append(self, kind: str, *, ref: str | None = None, session: str | None = None, agent: str | None = None,
               parent: str | None = None, trace: str | None = None, tool: str | None = None,
               decision: str | None = None, risk: int | None = None, body: Any = None,
               id: str | None = None, ts: float | None = None) -> None:
        ev = {"id": id or uuid.uuid4().hex[:12], "ts": time.time() if ts is None else ts, "kind": kind, "ref": ref,
              "session": session, "agent": agent, "parent": parent, "trace": trace, "tool": tool,
              "decision": decision, "risk": risk,
              "json": body if isinstance(body, str) else json.dumps(body if body is not None else {})}
        with self._cv:
            if len(self._queue) >= self.MAX_BACKLOG:
                self._queue.popleft()
                self.dropped += 1
                log.error("AUDIT BACKLOG FULL: dropped an unwritten audit event (%d dropped so far)", self.dropped)
            self._queue.append(ev)
            self.enqueued += 1
            self._cv.notify()
        if self._thread is None:
            self._drain()

    def _write(self, events: list[dict]) -> None:
        """Chain and store a batch in one transaction, head included. Reads the head inside the
        transaction, so a second process writing the same file cannot fork the chain."""
        t0 = time.perf_counter()
        db = self.db
        db.execute("begin immediate")
        try:
            row = db.execute("select seq, hash from audit_head where id = 1").fetchone()
            seq, prev = row if row else (0, GENESIS)
            for ev in events:
                seq += 1
                rec = {**{k: None for k in CHAIN_FIELDS}, **ev, "seq": seq}
                h = record_hash(prev, rec)
                db.execute("insert into verdicts (seq, id, ts, kind, ref, session, agent, parent, trace, tool, decision, risk, json,"
                           " prev_hash, hash, hmac) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (*(rec[k] for k in CHAIN_FIELDS), prev, h, sign(self.key, h)))
                prev = h
            db.execute("insert or replace into audit_head (id, seq, hash, hmac) values (1, ?, ?, ?)",
                       (seq, prev, sign(self.key, f"{seq}:{prev}")))
            db.execute("commit")
        except BaseException:
            try:
                db.execute("rollback")
            except sqlite3.Error:
                pass  # SQLite already rolled back (disk full, I/O error); keep the real error, not this one
            raise
        self.write_ms.append((time.perf_counter() - t0) * 1000)

    def _drain(self) -> bool:
        with self._cv:
            batch = list(self._queue)[:500]
        if not batch:
            return True
        try:
            with self._wlock:
                self._write(batch)
        except Exception as e:  # noqa: BLE001 - see the failure policy in the class docstring
            self.error, self.last_error_ts = f"{type(e).__name__}: {e}", time.time()
            log.error("AUDIT WRITE FAILED (%s). Verdicts are still enforced but NOT recorded; %d event(s) waiting to retry.",
                      self.error, len(self._queue))
            return False
        with self._cv:
            for _ in batch:
                if self._queue:
                    self._queue.popleft()
            self.written += len(batch)
            if self.error:
                log.warning("audit writes recovered after: %s", self.error)
            self.error = None
            self._cv.notify_all()
        return True

    def _run(self) -> None:
        backoff = 0.05
        while not self._stop:
            with self._cv:
                while not self._queue and not self._stop:
                    self._cv.wait(1.0)
            if self._drain():
                backoff = 0.05
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, 5.0)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until everything queued so far is on disk (or timeout). Readers call this first."""
        end = time.time() + timeout
        with self._cv:
            target = self.enqueued - self.dropped
            while self.written < target and self._queue:
                left = end - time.time()
                if left <= 0:
                    return False
                self._cv.wait(min(left, 0.1))
        return True

    def close(self) -> None:
        self.flush(2)
        self._stop = True
        with self._cv:
            self._cv.notify_all()
        if self._thread:
            self._thread.join(2)

    def health(self) -> dict:
        degraded = self.error is not None or self.dropped > 0 or (self._thread is not None and not self._thread.is_alive())
        ms = sorted(self.write_ms)
        return {"status": "degraded" if degraded else "ok", "error": self.error, "queued": len(self._queue),
                "written": self.written, "dropped": self.dropped, "path": str(self.path),
                "write_ms_p50": round(ms[len(ms) // 2], 3) if ms else None}

    # ---- reading ---------------------------------------------------------------
    def reader(self) -> "_Reader":
        return _Reader(self.path)

    def events(self, **kw) -> list[dict]:
        return read_events(self.path, **kw)

    def verdicts(self, *, limit: int = 1000, session: str | None = None, agent: str | None = None,
                 trace: str | None = None) -> list[dict]:
        """Verdicts newest first, each with its latest resolution folded in. Includes pre-chain rows,
        so the dashboard's audit view looks the same as before."""
        where, args = ["(kind = 'verdict' or kind is null)"], []
        for col, val in (("session", session), ("agent", agent), ("trace", trace)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        with self.reader() as db:
            rows = db.execute(f"select id, json from verdicts where {' and '.join(where)} order by ts desc limit ?",
                              (*args, limit)).fetchall()
            out = [json.loads(j) for _, j in rows]
            ids = [i for i, _ in rows]
            res: dict[str, tuple[str, str]] = {}
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                for ref, dec, body in db.execute(
                        f"select ref, decision, json from verdicts where kind = 'resolution' and ref in ({','.join('?' * len(chunk))})"
                        " order by seq", chunk):
                    res[ref] = (dec, _shown_by(json.loads(body).get("by", "human")))
        for v in out:
            if v.get("id") in res:
                v["decision"], v["resolved_by"] = res[v["id"]]
        return out

    def traces(self, *, trace: str | None = None, agent: str | None = None, session: str | None = None,
               limit: int = 20) -> list[dict]:
        """Trace trees: which agent spawned which, and what each did."""
        if agent and not trace:
            with self._alock:
                trace = self.agents.get(agent, {}).get("trace", agent)
        if trace:
            roots = [trace]
        else:
            with self.reader() as db:
                q = "select trace, max(ts) m from verdicts where seq is not null and trace is not null"
                q += " and session = ?" if session else ""
                q += " group by trace order by m desc limit ?"
                roots = [r[0] for r in db.execute(q, (session, limit) if session else (limit,))]
        return [build_tree(r, self.events(trace=r, kinds=("verdict", "resolution", "task", "observe"))) for r in roots]


def read_events(path: Path, *, kinds: Iterable[str] | None = None, agent: str | None = None, trace: str | None = None,
           session: str | None = None, since_seq: int = 0, limit: int | None = None, newest: bool = False) -> list[dict]:
    where, args = ["seq is not null", "seq > ?"], [since_seq]
    if kinds:
        kinds = list(kinds)
        where.append(f"kind in ({','.join('?' * len(kinds))})")
        args += kinds
    for col, val in (("agent", agent), ("trace", trace), ("session", session)):
        if val:
            where.append(f"{col} = ?")
            args.append(val)
    q = (f"select {', '.join(CHAIN_FIELDS)}, prev_hash, hash, hmac from verdicts where {' and '.join(where)}"
         f" order by seq {'desc' if newest else 'asc'}" + (" limit ?" if limit else ""))
    if limit:
        args.append(limit)
    db = connect(path)
    try:
        rows = db.execute(q, args).fetchall()
    finally:
        db.close()
    cols = (*CHAIN_FIELDS, "prev_hash", "hash", "hmac")
    return [dict(zip(cols, r)) for r in rows]


class _Reader:
    """`with` block that opens a read connection and closes it (sqlite3's own `with` only commits)."""

    def __init__(self, path: Path) -> None:
        self.db = connect(path)

    def __enter__(self) -> sqlite3.Connection:
        return self.db

    def __exit__(self, *exc) -> None:
        self.db.close()


def build_tree(trace: str, events: list[dict]) -> dict:
    nodes: dict[str, dict] = {}

    def node(agent: str) -> dict:
        if agent not in nodes:
            nodes[agent] = {"agent": agent, "parent": None, "session": None, "first_ts": None, "last_ts": None,
                            "counts": {"allow": 0, "ask": 0, "block": 0}, "tasks": [], "actions": [],
                            "injections": 0, "spawned_by": None, "children": []}
        return nodes[agent]

    node(trace)
    by_id: dict[str, dict] = {}
    for ev in events:
        agent = ev["agent"] or ev["session"] or trace
        n = node(agent)
        if ev["parent"] and ev["parent"] != agent:
            n["parent"] = n["parent"] or ev["parent"]
            node(ev["parent"])
        n["session"] = n["session"] or ev["session"]
        n["first_ts"] = n["first_ts"] or ev["ts"]
        n["last_ts"] = ev["ts"]
        body = json.loads(ev["json"] or "{}")
        if ev["kind"] == "verdict":
            a = {"id": ev["ref"] or ev["id"], "seq": ev["seq"], "ts": ev["ts"], "tool": ev["tool"],
                 "decision": ev["decision"], "risk": ev["risk"], "summary": body.get("summary"),
                 "capability": body.get("capability"), "resolved_by": None,
                 "subagent_type": ((body.get("action") or {}).get("args") or {}).get("subagent_type")}
            n["actions"].append(a)
            by_id[a["id"]] = a
        elif ev["kind"] == "resolution" and ev["ref"] in by_id:
            by_id[ev["ref"]].update(decision=ev["decision"], resolved_by=_shown_by(body.get("by")))
        elif ev["kind"] == "task":
            n["tasks"].append({"ts": ev["ts"], "prompt": body.get("prompt")})
        elif ev["kind"] == "observe" and body.get("injection"):
            n["injections"] += 1
    for n in nodes.values():
        for a in n["actions"]:
            if a["decision"] in n["counts"]:
                n["counts"][a["decision"]] += 1
    # Link each child to the spawn call (Task/Agent tool) in its parent that most likely started it.
    used: set[str] = set()
    for n in sorted(nodes.values(), key=lambda x: x["first_ts"] or 0):
        p = nodes.get(n["parent"] or "")
        if not p:
            continue
        p["children"].append(n)
        spawns = [a for a in p["actions"] if (a["tool"] or "").lower() in SPAWN_TOOLS and a["id"] not in used
                  and a["ts"] <= (n["first_ts"] or 0) and a["decision"] != "block"]
        typed = [a for a in spawns if a["subagent_type"] and a["subagent_type"] in n["agent"]]
        pick = (typed or spawns)[-1:] if (typed or spawns) else []
        if pick:
            n["spawned_by"] = pick[0]["id"]
            used.add(pick[0]["id"])
    root = nodes[trace]
    totals = {"allow": 0, "ask": 0, "block": 0}
    for n in nodes.values():
        for k in totals:
            totals[k] += n["counts"][k]
    return {"trace": trace, "agents": len(nodes), "totals": totals, "root": root}


# ---- verification ------------------------------------------------------------

class VerifyResult:
    def __init__(self) -> None:
        self.ok = True
        self.problems: list[str] = []
        self.checked = 0
        self.legacy = 0
        self.notes: list[str] = []

    def fail(self, msg: str) -> "VerifyResult":
        self.ok = False
        self.problems.append(msg)
        return self


def verify_rows(rows: Iterator[dict] | list[dict], key: bytes | None, head: dict | None = None,
                result: VerifyResult | None = None) -> VerifyResult:
    """Walk the chain in seq order. Stops at the first broken link and says what is wrong in plain words."""
    r = result or VerifyResult()
    prev, expect = GENESIS, 1
    last = None
    for row in rows:
        seq = row["seq"]
        if seq != expect:
            if seq is not None and seq > expect:
                gone = f"#{expect}" if seq == expect + 1 else f"#{expect} to #{seq - 1}"
                return r.fail(f"Record {gone} is missing: someone deleted or moved audit rows (next record found is #{seq}).")
            return r.fail(f"Record #{seq} is out of order (expected #{expect}): rows were reordered or duplicated.")
        if expect == 1:
            if row.get("kind") != "chain_start":
                return r.fail("The first record is not the chain start: the start of the log was deleted or replaced.")
            body = json.loads(row.get("json") or "{}")
            if key is not None and body.get("key_id") and body["key_id"] != key_id(key):
                return r.fail(f"This log was signed with a different key (id {body['key_id']}) than the one provided "
                              f"(id {key_id(key)}). The key was replaced or the wrong key file was given.")
        if row.get("prev_hash") != prev:
            return r.fail(f"Record #{seq} does not link to record #{seq - 1}: a row before it was changed, deleted or swapped.")
        h = record_hash(prev, row)
        if h != row.get("hash"):
            return r.fail(f"Record #{seq} ({row.get('kind')}, {row.get('tool') or row.get('id')}) was changed after it was written: "
                          "its contents no longer match its hash.")
        if key is not None and not hmac.compare_digest(sign(key, h), row.get("hmac") or ""):
            return r.fail(f"Record #{seq} has an invalid signature: it was rewritten by someone without the audit key, "
                          "or the key was replaced.")
        prev, expect, last = h, expect + 1, row
        r.checked += 1
    if head is not None:
        hs, hh = head.get("seq"), head.get("hash")
        if key is not None and not hmac.compare_digest(sign(key, f"{hs}:{hh}"), head.get("hmac") or ""):
            return r.fail("The signed end-of-log marker does not verify: it was edited by someone without the audit key.")
        last_seq = last["seq"] if last else 0
        if hs is not None and hs > last_seq:
            n = hs - last_seq
            return r.fail(f"The newest {n} record(s) were deleted: the signed end-of-log marker says the log ends at #{hs}, "
                          f"but the last record is #{last_seq}.")
        if hs is not None and (hs < last_seq or (last and hh != last["hash"])):
            return r.fail(f"Records after #{hs} were added without the audit key, or the end-of-log marker was rolled back.")
    elif r.checked:
        r.notes.append("No signed end-of-log marker was given, so deleting the newest records cannot be ruled out.")
    if r.checked == 0:
        return r.fail("No chained audit records found: the log was wiped or never started.")
    return r


def verify_db(path: Path, key: bytes | None) -> VerifyResult:
    r = VerifyResult()
    if not Path(path).exists():
        return r.fail(f"No audit database at {path}.")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        cols = {c[1] for c in db.execute("pragma table_info(verdicts)")}
        if "seq" not in cols:
            return r.fail("This audit database has no tamper-evident chain yet (old format). Start `tripwire serve` once to add it.")
        r.legacy = db.execute("select count(*) from verdicts where seq is null").fetchone()[0]
        h = db.execute("select seq, hash, hmac from audit_head where id = 1").fetchone()
        if h is None:
            return r.fail("The signed end-of-log marker is missing: it was deleted.")
        head = {"seq": h[0], "hash": h[1], "hmac": h[2]}
        cur = db.execute(f"select {', '.join(CHAIN_FIELDS)}, prev_hash, hash, hmac from verdicts where seq is not null order by seq")
        cols_ = (*CHAIN_FIELDS, "prev_hash", "hash", "hmac")
        verify_rows((dict(zip(cols_, row)) for row in cur), key, head, r)
    finally:
        db.close()
    if r.legacy:
        r.notes.append(f"{r.legacy} row(s) from before chaining are not covered by the chain.")
    return r


def export_lines(path: Path) -> Iterator[str]:
    """JSONL: one chained record per line (all fields + prev_hash, hash, hmac), then the signed head.
    Anyone can recheck the hashes; checking the HMACs needs the key."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        cols = (*CHAIN_FIELDS, "prev_hash", "hash", "hmac")
        for row in db.execute(f"select {', '.join(cols)} from verdicts where seq is not null order by seq"):
            yield json.dumps(dict(zip(cols, row)), ensure_ascii=False)
        h = db.execute("select seq, hash, hmac from audit_head where id = 1").fetchone()
        if h:
            yield json.dumps({"head": {"seq": h[0], "hash": h[1], "hmac": h[2]}})
    finally:
        db.close()


def verify_lines(lines: Iterable[str], key: bytes | None) -> VerifyResult:
    rows, head = [], None
    r = VerifyResult()
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return r.fail(f"Line {i} of the export is not valid JSON.")
        if "head" in obj and "seq" not in obj:
            head = obj["head"]
        else:
            rows.append(obj)
    return verify_rows(rows, key, head, r)


def _shown_by(by: str | None) -> str | None:
    """A click in the paired dashboard is a person ("human", as the live verdict says); the log keeps "dashboard"."""
    return "human" if by == "dashboard" else by
