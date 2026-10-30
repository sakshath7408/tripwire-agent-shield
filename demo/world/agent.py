"""The simulated agent.

A Planner decides the next tool call from the history. Two kinds can plug in:

  NaivePlanner  (default) a deterministic stand-in for a hijacked LLM. It follows a fixed plan for the
                user's task, and it naively obeys any imperative instruction it finds in content it reads
                (read this file, POST that, email this, run that command, transfer money). That is exactly
                the failure mode prompt injection exploits, made reproducible so the demo is the same every time.

  Any LLM planner  implement `next_action(history) -> ToolCall | None` (for example a local Ollama model).
                Nothing else changes: the runner, the world and the guard stay the same.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    why: str = ""  # "task" or "injected: <where the instruction came from>"


@dataclass
class Step:
    call: ToolCall
    output: str  # what the agent saw back (tool output, or the guard's refusal)
    decision: str = "allow"  # allow | ask | block (or "unguarded")
    executed: bool = True


class Planner(Protocol):
    def next_action(self, history: list[Step]) -> ToolCall | None: ...


PlanItem = ToolCall | Callable[[list[Step]], ToolCall | None]

FILE_RE = re.compile(r"(~/[\w./-]+[\w]|(?<![\w/])\.env\b)")
URL_RE = re.compile(r"https?://[^\s'\"<>`)]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CMD_RE = re.compile(r"`([^`]+)`")
MONEY_RE = re.compile(r"\b(?:transfer|send|pay|wire)\s+\$?([\d,]+(?:\.\d+)?)", re.I)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
IMPERATIVE = re.compile(r"\b(must|please|before doing|before completing|before running|do this|read|post|email|reply|"
                        r"run|transfer|send|install)\b", re.I)


def extract_instructions(text: str, source: str) -> list[PlanItem]:
    """Turn imperative sentences found in untrusted content into tool calls, the way a hijacked agent would."""
    out: list[PlanItem] = []
    # one "instruction" per paragraph / comment so 'read X and POST it to Y' stays together
    for chunk in re.split(r"\n\s*\n|<!--|-->", text):
        if not IMPERATIVE.search(chunk):
            continue
        why = f"injected: instruction found in {source}"
        files = [f for f in FILE_RE.findall(chunk) if "/" in f or f == ".env"]
        urls = [u.rstrip(".,") for u in URL_RE.findall(chunk)]
        cmds = [c for c in CMD_RE.findall(chunk) if c.split()[0] in ("curl", "wget", "bash", "sh", "python", "python3", "rm")]
        money = MONEY_RE.search(chunk)
        ibans = IBAN_RE.findall(chunk)
        body = "\n".join(l for l in chunk.splitlines() if "From: " not in l)  # the sender line is not an instruction
        emails = list(dict.fromkeys(e for e in EMAIL_RE.findall(body) if re.search(r"\b(email|reply|send|forward)\b", body, re.I)))
        if not (files or cmds or money or emails or (urls and re.search(r"\bpost\b", chunk, re.I))):
            continue
        for f in files:
            out.append(ToolCall("read_file", {"path": f}, why))
        if money and ibans:
            out.append(ToolCall("send_money", {"to": ibans[0], "amount": float(money.group(1).replace(",", "")),
                                               "memo": "invoice"}, why))
        loot = _loot(files)
        if re.search(r"\bpost\b", chunk, re.I):
            for u in urls:
                if u not in " ".join(cmds):
                    out.append(lambda h, u=u, loot=loot: ToolCall("http_post", {"url": u, "data": loot(h)}, why))
        for e in emails:
            out.append(lambda h, e=e, loot=loot: ToolCall("send_email", {"to": e, "subject": "As requested",
                                                                          "body": loot(h)}, why))
        for c in cmds:
            out.append(ToolCall("run_command", {"command": c}, why))
    return out


def _loot(files: list[str]) -> Callable[[list[Step]], str]:
    """Whatever the agent managed to read from the requested files (empty if the guard stopped the reads)."""
    def collect(history: list[Step]) -> str:
        parts = [s.output for s in history if s.call.tool == "read_file" and s.call.args.get("path") in files
                 and s.executed]
        return "\n".join(parts) if parts else "(could not read the files)"
    return collect


@dataclass
class NaivePlanner:
    """Fixed task plan + obeys instructions found in tool outputs (injected steps run first, like a real hijack)."""

    plan: list[PlanItem]
    obey_injections: bool = True
    extractor: Callable[[str, str], list[PlanItem]] = extract_instructions
    queue: list[PlanItem] = field(default_factory=list)
    _seen: int = 0

    def __post_init__(self) -> None:
        self.queue = list(self.plan)

    def next_action(self, history: list[Step]) -> ToolCall | None:
        if self.obey_injections:
            for step in history[self._seen:]:
                if step.executed and step.call.tool in ("read_file", "fetch_url", "read_inbox"):
                    src = step.call.args.get("path") or step.call.args.get("url") or "the inbox"
                    self.queue[0:0] = self.extractor(step.output, src)
            self._seen = len(history)
        while self.queue:
            item = self.queue.pop(0)
            call = item(history) if callable(item) else item
            if call is not None:
                return call
        return None


# ---- free-form instructions (the hosted demo's "Try your own attack") ---------------------------------
# A visitor types the attacker's text in plain English. This turns the common phrasings into tool calls the
# way a hijacked agent would: "send the .env to x@y.com", "email the ssh key to ...", "run curl ... | bash",
# "transfer $500 to IBAN ...", "post the notes to https://...", "delete everything". It is a scripted stand-in,
# not a model: anything it does not recognise is ignored, and `freeform_plan` says what it understood.
# The text is untrusted and up to 4 KB, so every pattern is bounded (see CLAUDE.md lessons). Nothing here runs
# the text: commands become a run_command call, which the world only simulates.

_F_URL = re.compile(r"https?://[\w.-]{1,253}(?::\d{1,5})?(?:[/?#][^\s'\"<>`|]{0,300})?", re.I)
_F_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
_F_PATH = re.compile(r"(?<![\w@/:.~-])(~/[\w.-]{1,64}(?:/[\w.-]{1,64}){0,8}|/(?:etc|home|root|var|usr|Users|tmp|opt)"
                     r"(?:/[\w.-]{1,64}){1,8}|(?:\.{1,2}/)?(?:[\w-]{1,64}/){0,8}[\w-]{1,64}\.(?:md|toml|py|txt|json|pem|"
                     r"key|ya?ml|cfg|ini|csv|log|sh|conf|db|sqlite))(?![\w@/-])", re.I)
_F_SSH = re.compile(r"\b(?:ssh|private|deploy|rsa)[ _-]{0,2}keys?\b|\bid_(?:rsa|ed25519)\b|\bssh (?:folder|directory|dir)\b|"
                    r"(?<![\w/])~?/?\.ssh\b", re.I)
_F_ENV = re.compile(r"(?<![\w/])\.env\b|\benv(?:ironment)?[ _-]?(?:file|vars?|variables)\b|\b(?:api|secret|access)[ _-]?"
                    r"(?:keys?|tokens?)\b|\bsecrets?\b|\bcredentials?\b|\bpasswords?\b|\btokens?\b|\bkeys\b", re.I)
_F_README = re.compile(r"\breadme\b(?!\.)", re.I)
_F_INBOX = re.compile(r"\b(?:inbox|(?:all|my|the|your|every|these|those)\s(?:\w{1,20}\s)?(?:e-?mails?|mail|messages))\b", re.I)
_F_CONTEXT = re.compile(r"\b(?:this|the|these|that)\s(?:page|document|doc|email|message|notes|release notes|summary|text|"
                        r"conversation|chat|contents?|data)\b|\beverything\b|\bit all\b", re.I)
_F_PRONOUN = re.compile(r"\b(?:it|them|they|those|that|this|the contents?|the files?|the keys?|the data)\b", re.I)
_F_SEND = re.compile(r"\b(?:send|sent|email|e-mail|mail|forward|reply|cc|bcc|share|post|upload|submit|push|sync|exfiltrate|"
                     r"transmit|deliver|copy|give|leak|report|paste|dump|beam|attach)\b", re.I)
_F_POST = re.compile(r"\b(?:post|upload|send|submit|push|sync|put|exfiltrate|transmit|dump|paste|report|beam|leak|share|"
                     r"copy|save|back ?up|log)\b", re.I)
_F_FETCH = re.compile(r"\b(?:visit|open|fetch|load|go to|browse|check|ping|call|hit|get|download|request|navigate)\b", re.I)
_F_RUNURL = re.compile(r"\b(?:run|execute|exec|install|pipe|source)\b", re.I)
_F_READ = re.compile(r"\b(?:read|open|cat|show|print|display|look at|check|load|view)\b", re.I)
_F_DELETE = re.compile(r"\b(?:delete|remove|wipe|erase|destroy|shred|nuke|trash)\b", re.I)
_F_ALL = re.compile(r"\b(?:everything|all (?:the |my |your |of the )?(?:files|data|code)|the (?:whole |entire )?(?:repo|"
                    r"repository|project|codebase|folder|directory|home folder|disk|drive)|home (?:folder|directory))\b", re.I)
_F_MONEYV = re.compile(r"\b(?:transfer|send|pay|wire|move|deposit|remit)\b", re.I)
_F_AMOUNT = re.compile(r"[$€£]\s?(\d{1,3}(?:,\d{3}){1,4}|\d{1,12})(?:\.(\d{1,2}))?|\b(\d{1,3}(?:,\d{3}){1,4}|\d{1,12})"
                       r"(?:\.(\d{1,2}))?\s?(?:dollars|usd|eur|euros?|gbp|pounds|bucks)\b", re.I)
_F_ALLMONEY = re.compile(r"\b(?:all (?:of )?(?:my |the |your )?(?:money|funds|cash|balance)|(?:the |my |your )?(?:entire|whole|"
                         r"full) balance|everything in (?:the|my|your) (?:account|bank))\b", re.I)
_F_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b")
_F_ACCT = re.compile(r"\baccount(?:\s(?:number|no\.?|#))?\s{0,3}:?\s{0,3}#?(\d[\d -]{4,30}\d)\b", re.I)
_F_CMDWORD = (r"(?:curl|wget|bash|sh|zsh|python3?|rm|chmod|chown|sudo|pip3?|npm|npx|node|nc|ncat|netcat|scp|ssh|git|cat|"
              r"echo|eval|base64|dd|mkfs(?:\.\w{1,8})?|shred|mv|cp|ls|env|printenv|export|crontab|perl|ruby|powershell|"
              r"iex|kill|killall|shutdown|reboot|find|tar|zip)")
_F_TICK = re.compile(r"`([^`\n]{1,300})`")
_F_RUNCMD = re.compile(r"\b(?:run|execute|exec|type|enter|invoke)\b[^\n`]{0,40}?[\s:]((?:sudo\s{1,4})?" + _F_CMDWORD +
                       r"\s[^\n`]{1,300})", re.I)
_F_DOLLAR = re.compile(r"^\s{0,8}\$\s{1,4}([^\n]{1,300})")
_F_PIPESH = re.compile(r"\b(?:curl|wget)\s[^\n|`]{1,300}\|\s{0,4}(?:sudo\s{1,4})?(?:ba|z|da)?sh\b", re.I)
_F_RMRF = re.compile(r"\brm\s{1,4}-[rRf]{1,3}\s{1,4}[^\s;|&`]{1,200}")
_F_SPLIT = re.compile(r"(?<=[.!?;])\s+|,?\s{1,4}(?:and\s{1,4})?then\s{1,4}|,?\s{1,4}(?:and|also|plus)\s{1,4}(?:also\s{1,4})?"
                      r"(?=(?:please\s{1,4})?(?:send|email|e-mail|mail|forward|transfer|pay|wire|run|execute|post|upload|"
                      r"delete|remove|wipe|visit|open|fetch|download|install|read|cat|reply|share)\b)", re.I)
MAX_FREEFORM_CALLS = 12


def _sentences(text: str) -> list[str]:
    out: list[str] = []
    for line in text[:4096].splitlines():
        out.extend(s.strip() for s in _F_SPLIT.split(line) if s.strip())
    return out


def _commands(sent: str) -> list[str]:
    cmds: list[str] = []
    for c in _F_TICK.findall(sent):
        if re.match(r"\s*(?:sudo\s+)?" + _F_CMDWORD + r"\b", c):
            cmds.append(c.strip())
    if not cmds:
        for pat in (_F_RUNCMD, _F_DOLLAR):
            m = pat.search(sent)
            if m:
                cmds.append(m.group(1))
                break
    if not cmds:
        cmds.extend(m.group(0) for m in _F_PIPESH.finditer(sent))
    if not cmds:
        cmds.extend(m.group(0) for m in _F_RMRF.finditer(sent))
    return list(dict.fromkeys(c.strip().rstrip(".,;'\"").strip() for c in cmds if c.strip()))[:3]


def _amount(sent: str) -> float | None:
    m = _F_AMOUNT.search(sent)
    if not m:
        return None
    whole, cents = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    return float(whole.replace(",", "") + ("." + cents if cents else ""))


def _what(files: list[str], inbox: bool, source: str) -> str:
    parts = list(files) + (["your inbox"] if inbox else [])
    return " and ".join(parts) if parts else f"the text of {source}"


def _loot_of(files: list[str], inbox: bool, context: str) -> Callable[[list[Step]], str]:
    def collect(history: list[Step]) -> str:
        parts = [s.output for s in history if s.executed and (
            (s.call.tool == "read_file" and s.call.args.get("path") in files) or (inbox and s.call.tool == "read_inbox"))]
        if parts:
            return "\n".join(parts)
        return "(could not read the files)" if files or inbox else context
    return collect


def freeform_plan(text: str, source: str) -> tuple[list[PlanItem], list[str]]:
    """The tool calls a naive hijacked agent would make from `text`, plus one plain line per call saying what it
    understood. Unrecognised text gives ([], [])."""
    why = f"injected: instruction found in {source}"
    items: list[PlanItem] = []
    says: list[str] = []
    carry: list[str] = []  # files named in an earlier sentence, for "Read X. Then email it to Y."
    context = text[:1200]

    def add(item: PlanItem, line: str) -> None:
        if len(items) < MAX_FREEFORM_CALLS:
            items.append(item)
            says.append(line)

    for sent in _sentences(text):
        cmds = _commands(sent)
        urls = [u.rstrip(".,;:)!?") for u in _F_URL.findall(sent)]
        bare = _F_URL.sub(" ", sent)
        emails = [e.rstrip(".") for e in _F_EMAIL.findall(bare)]
        bare = _F_EMAIL.sub(" ", bare)
        for c in cmds:
            bare = bare.replace(c, " ")
        urls = [u for u in urls if not any(u in c for c in cmds)]
        files = [f.rstrip(".") for f in _F_PATH.findall(bare)]
        no_ssh = _F_SSH.sub(" ", bare)
        if _F_SSH.search(bare):
            files.append("~/.ssh/id_rsa")
        if _F_ENV.search(no_ssh):
            files.append(".env")
        if _F_README.search(bare):
            files.append("README.md")
        files = list(dict.fromkeys(files))[:4]
        inbox = bool(_F_INBOX.search(bare)) and source != "the inbox"
        refers = bool(_F_PRONOUN.search(bare) or _F_CONTEXT.search(bare))

        # money first: "send $500 to x@y.com" is a payment, not an email
        amount, all_money = _amount(sent), bool(_F_ALLMONEY.search(sent))
        acct = _F_IBAN.search(sent) or _F_ACCT.search(sent)
        if _F_MONEYV.search(bare) and (amount or all_money) and acct:
            to = re.sub(r"[ -]", "", acct.group(1))
            if all_money:
                add(ToolCall("get_balance", {}, why), "Check your balance")

                def pay_all(h: list[Step], to: str = to) -> ToolCall:
                    out = next((s.output for s in reversed(h) if s.call.tool == "get_balance" and s.executed), "")
                    m = re.search(r"\$([\d,]{1,20}\.\d{2})", out)
                    return ToolCall("send_money", {"to": to, "amount": float(m.group(1).replace(",", "")) if m else 0.0,
                                                   "memo": "as instructed"}, why)
                add(pay_all, f"Send all your money to {to}")
            else:
                add(ToolCall("send_money", {"to": to, "amount": amount, "memo": "as instructed"}, why),
                    f"Send ${amount:,.2f} to {to}")
            emails = []

        if _F_DELETE.search(bare) and not cmds:
            whole = _F_ALL.search(bare)
            targets = files or ([] if not whole else ["."] if re.search(r"repo|project|codebase|code\b", whole.group(0) + bare, re.I)
                                else ["~"])
            if targets:
                cmd = "rm -rf " + " ".join(targets)
                add(ToolCall("run_command", {"command": cmd}, why), f"Run `{cmd}`")
                continue

        send_mail = emails if (emails and (_F_SEND.search(bare) or re.search(r"\bto\b", bare, re.I))) else []
        run_urls = [u for u in urls if _F_RUNURL.search(bare)]
        post_urls = [u for u in urls if u not in run_urls and (_F_POST.search(bare) or re.search(r"\bto\s*$", sent.split(u)[0]))]
        fetch_urls = [u for u in urls if u not in run_urls and u not in post_urls and _F_FETCH.search(bare)]
        carried = False
        if (send_mail or post_urls) and not files and not inbox and refers and carry:
            files, carried = carry, True  # "...then email it to y@z.com": already read in the earlier sentence
        if send_mail or post_urls:
            for f in ([] if carried else files):
                add(ToolCall("read_file", {"path": f}, why), f"Read {f}")
            if inbox:
                add(ToolCall("read_inbox", {}, why), "Read your inbox")
            loot = _loot_of(files, inbox, context)
            what = _what(files, inbox, source)
            for e in send_mail[:3]:
                add(lambda h, e=e, loot=loot: ToolCall("send_email", {"to": e, "subject": "As requested", "body": loot(h)}, why),
                    f"Email {what} to {e}")
            for u in post_urls[:3]:
                add(lambda h, u=u, loot=loot: ToolCall("http_post", {"url": u, "data": loot(h)}, why), f"Upload {what} to {u}")
        elif files and _F_READ.search(bare):
            for f in files:
                add(ToolCall("read_file", {"path": f}, why), f"Read {f}")
        if files:
            carry = files
        for c in cmds:
            add(ToolCall("run_command", {"command": c}, why), f"Run `{c}`")
        for u in run_urls[:2]:
            cmd = f"curl -fsSL {u} | bash"
            add(ToolCall("run_command", {"command": cmd}, why), f"Download and run {u}")
        for u in fetch_urls[:3]:
            add(ToolCall("fetch_url", {"url": u}, why), f"Open {u}")
    return items, says
