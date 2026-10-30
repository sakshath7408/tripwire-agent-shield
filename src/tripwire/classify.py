"""Map a tool name to what it can do. Works for Claude Code tools and arbitrary MCP tools."""

from __future__ import annotations

import re
import unicodedata

from .models import Capability

# Exact names first (Claude Code built-ins and common MCP servers).
EXACT: dict[str, Capability] = {
    "bash": Capability.EXEC,
    "shell": Capability.EXEC,
    "run_command": Capability.EXEC,
    "execute_command": Capability.EXEC,
    "read": Capability.READ,
    "glob": Capability.READ,
    "grep": Capability.READ,
    "ls": Capability.READ,
    "read_file": Capability.READ,
    "list_directory": Capability.READ,
    "write": Capability.WRITE,
    "edit": Capability.WRITE,
    "multiedit": Capability.WRITE,
    "notebookedit": Capability.WRITE,
    "write_file": Capability.WRITE,
    "edit_file": Capability.WRITE,
    "webfetch": Capability.FETCH,
    "websearch": Capability.FETCH,
    "fetch": Capability.FETCH,
    "task": Capability.AGENT,
    "agent": Capability.AGENT,
}

# Money rails and coins. Anchored at a word start (`(?:^|_)`, see Lessons): "venmo_send" and "send_crypto" move money,
# they are not messages. Short coin tickers also need a word end so "ethernet" or "solve" stay out.
COINS = r"(?:crypto|btc|eth|usdc|usdt|sol|xrp|doge|bitcoin|ethereum|stablecoins?|tokens?|coins?)"
MONEY_WORDS = re.compile(
    r"(?:^|_)(?:venmo|zelle|paypal|cashapp|cash_app|wire|remit|remittance|payout|payouts|settle)(?:_|s?$)|"
    rf"(?:^|_)(?:send|transfer|withdraw|swap|bridge|buy|sell|move)_(?:\w{{0,24}}_)?{COINS}(?:_|$)|"
    rf"(?:^|_){COINS}_(?:send|transfer|withdraw|swap|bridge|payment|payout)|"
    r"(?:^|_)(?:approve|authori[sz]e|execute)_(?:\w{0,24}_)?(?:transaction|payment|transfer)s?(?:_|$)"
)

VENDOR_READ = re.compile(r"(?:^|_)(?:get|list|read|search|find|show|view|check|lookup|count)_")
MONEY_VERB = re.compile(r"(?:^|_)(?:send|transfer|pay|payment|withdraw|swap|bridge|buy|sell|payout|settle|approve|"
                        r"authori[sz]e|execute|create|refund|request)(?:_|s?$)")

# Then keyword patterns over the normalised name. Order matters: most dangerous first.
PATTERNS: list[tuple[re.Pattern[str], Capability]] = [
    (MONEY_WORDS, Capability.MONEY),
    (re.compile(r"(send_money|transfer|payment|pay_|_pay\b|(?:^|_)upi|refund|withdraw|schedule_transaction|update_scheduled_transaction)"), Capability.MONEY),
    (re.compile(r"(delete|remove|drop|purge|destroy|wipe|truncate|rm_)"), Capability.DELETE),
    (re.compile(r"(exec|run_|shell|terminal|command|eval)"), Capability.EXEC),
    (re.compile(r"(send|email|mail|message|post_|post\b|publish|share|invite|reply|forward|upload|webhook|http_post|create_issue|comment|tweet|slack)"), Capability.SEND),
    (re.compile(r"(write|edit|create|update|append|insert|set_|save|rename|move|patch|commit|push|replace|modify|overwrite|chmod)"), Capability.WRITE),
    (re.compile(r"(fetch|browse|web|url|http|download|search_web|get_webpage)"), Capability.FETCH),
    # Your own mail and chat: reading it is a read ("read your inbox"), not a trip to the web. What it returns is
    # still untrusted (every tool output is), and sending from it is judged as a send.
    (re.compile(r"(inbox|read_email|get_unread|read_channel|get_messages|read_message|list_email|search_email)"), Capability.READ),
    (re.compile(r"(?:^|_)(read|get|list|search|find|query|show|view|cat|describe)"), Capability.READ),
]


def normalise(tool: str) -> str:
    # MCP tools from Claude Code arrive as mcp__server__tool. Keep the tool part.
    name = tool.split("__")[-1] if tool.startswith("mcp__") else tool
    # Fold look-alike letters (full-width, ligatures) so a disguised name reads like the real one.
    name = unicodedata.normalize("NFKC", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[\s.\-:/]+", "_", name.lower())


# A getter prefix only proves a read when no other verb follows: "get_and_send_report" and
# "list_and_delete_files" do side effects despite starting like readers.
SIDE_EFFECT_WORDS = {  # verbs only; nouns like "email", "post", "order", "run" also name things a getter returns
    "send", "forward", "reply", "upload", "invite", "notify", "publish", "tweet",
    "delete", "remove", "purge", "destroy", "wipe", "erase", "kill", "truncate",
    "exec", "execute", "eval", "spawn", "install", "deploy",
    "write", "edit", "create", "append", "insert", "rename", "move", "commit", "push", "replace", "modify", "overwrite",
}


# Nouns that turn into verbs after "and"/"then": get_report_and_email, fetch_and_post.
JOINED_VERBS = {"email", "mail", "post", "message", "text", "sms", "order", "book", "pay", "transfer", "run", "share",
                "slack", "tweet", "upload", "save", "store", "set", "update", "clear", "drop"}


def _has_side_effect(name: str) -> bool:
    words = name.split("_")
    return any(w in SIDE_EFFECT_WORDS or (words[i - 1] in ("and", "then") and w in JOINED_VERBS)
               for i, w in enumerate(words) if i > 0)


READ_PREFIX = re.compile(r"^(get|list|search|read|check|find|fetch|count|lookup)_")
OUTSIDE_DATA = re.compile(r"(web|url|page|feed|post|review|comment)")
VERB_RULES: list[tuple[re.Pattern[str], Capability]] = [
    (re.compile(r"(password|passwd|credential|2fa|mfa|api_key|access_key|recovery|security_question)"), Capability.CREDENTIAL),
    (re.compile(r"^(reserve|book|purchase|buy|order|checkout)_"), Capability.MONEY),
    (re.compile(r"^cancel_"), Capability.DELETE),
    (re.compile(r"(invite|^add_\w*(participant|user|member|guest|collaborator)s?)"), Capability.SEND),
]


# Mailbox housekeeping changes your own mail, it never sends any: archive_email, label_thread, mark_read, star_message.
MAILBOX_EDIT = re.compile(r"^(?:archive|unarchive|label|unlabel|add_labels?|remove_labels?|apply_labels?|mark|flag|unflag|star|"
                          r"unstar|snooze|unsnooze|mute|unmute|pin|unpin|tag|untag|categori[sz]e|move_to_folder)(?:_|$)")


def classify(tool: str, overrides: dict[str, str] | None = None) -> Capability:
    if overrides and tool in overrides:
        return Capability(overrides[tool])
    name = normalise(tool)
    if name in EXACT:
        return EXACT[name]
    if MAILBOX_EDIT.match(name) and not _has_side_effect(name.split("_", 1)[1] if "_" in name else ""):
        return Capability.WRITE
    for pattern, cap in VERB_RULES:
        if pattern.search(name):
            return cap
    # Getters never change anything. What they return is outside data when it comes from mail, chat or the web.
    mixed = _has_side_effect(name)
    if READ_PREFIX.match(name) and not mixed:
        return Capability.FETCH if OUTSIDE_DATA.search(name) else Capability.READ
    for pattern, cap in PATTERNS:
        if mixed and cap == Capability.READ:
            break  # it reads *and* does something we could not name: let a human decide
        if pattern.search(name):
            if pattern is MONEY_WORDS and not mixed and VENDOR_READ.search(name) and not MONEY_VERB.search(name):
                return Capability.READ  # "paypal_get_balance" looks money up, it does not move it
            return cap
    return Capability.UNKNOWN
