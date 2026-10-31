"""Provenance tracking.

The user's prompt is the only trusted text. Every tool output (files, web pages,
emails) is untrusted data. When an outgoing action uses a value that first showed
up in untrusted data and never in the user's words, the agent is probably obeying
something it read, not something it was asked. That is the prompt-injection signal,
and it does not depend on another model checking itself.
"""

from __future__ import annotations

import ipaddress
import os
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

URL = re.compile(r"https?://[^\s'\"<>)\]]{1,2048}", re.I)
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
UPI = re.compile(r"(?<![\w.-])[\w.-]{2,64}@(?:ok\w+|ybl|paytm|upi|ibl|axl|apl|sbi|icici|hdfc\w*|ptyes|yapl)\b", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
# Glued to letters or digits it is part of something else (the tail of a key "sk-...0000000000", an id), not a phone.
PHONE = re.compile(r"(?<![\w+])\+?\d[\d -]{8,18}\d(?!\w)")
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.){1,8}(?:com|net|org|io|xyz|ru|cn|top|sh|dev|app|co|in|me|info|biz|site|online|tk)\b", re.I)

MAX_OBSERVE = 1_000_000  # characters scanned per tool output; keeps a giant output from stalling the guard

INDICATOR_PATTERNS = {
    "url": URL,
    "email": EMAIL,
    "iban": IBAN,
    "upi": UPI,
    "ip": IP,
    "phone": PHONE,
    "domain": DOMAIN,
}

# Imperative phrases that betray instructions hidden in data. Each one speaks to the AI. Plain shouting such as
# "IMPORTANT! Board meeting moved" is everyday email, so it is not here (it hard-blocked a normal forward).
INJECTION_MARKERS = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|prompts?)|disregard (the )?(previous|above)|"
    r"you (must|should) now|new instructions?:|system prompt|<\s*/?\s*(system|instructions?|important)\s*>|"
    r"as an ai (agent|assistant)|do not (tell|inform|mention to) the user|without (asking|telling) the user|"
    r"assistant,? please|before (doing|completing) (anything|the task)|<\s*/?\s*information\s*>|"
    r"this is an important message from|before you can (solve|complete|finish) the task|"
    r"please do the following first|after you do that,? you can (solve|complete)|"
    # Paraphrased: text that speaks to the AI reading it rather than to a human.
    r"(note|message|instructions?|reminder|request) (to|for) (any |the |all )?(ai|llm|automated|assistant|agent|model|bot)s?\b|"
    r"(?:^|[\n>\-*#/\"'{,])\s{0,8}(ai|llm|assistant|agent|bot)\s{0,3}:\s{0,8}(please |you must |always |first |also |when )|"
    r"if you are an? (ai|llm|language model|assistant|agent)|(ai|automated) (agents?|assistants?) (must|should|reading this))",
    re.I | re.M,
)

# "From: alice@x.com" / "sender: alice@x.com": who wrote a message the agent read. Replying to them is normal.
# An inbox listing may number its messages ("[3] From: ...", "3. From: ..."). Reply-To is kept apart: it is where a
# reply would go, chosen by whoever wrote the email, so it never inherits the sender's trust (a classic phish).
SENDER_LINE = re.compile(r"^[ \t]{0,8}(?:\[[\w-]{1,12}\][ \t]{0,4}|\d{1,6}[.)][ \t]{1,4})?[-*\"']?[ \t]{0,4}"
                         r"(from|sender|reply-to|reply_to|replyto|sender_email|from_email)[\"']?[ \t]{0,4}[:=][ \t]{0,4}([^\n]{1,300})$",
                         re.I | re.M)
MAX_MESSAGES = 500  # messages remembered per session (newest kept)
# Mail-system words that are not a person's name: "reply to the support email" must not pick support@ on its own.
GENERIC_NAMES = frozenset("""info team support admin noreply reply hello contact help helpdesk mail email news newsletter
notifications notification notify alerts alert service services office sales billing security it no do not the and you me
my all us bot bots system mailer daemon postmaster root user users account accounts updates update""".split())
# A value that sits alone on its line, as a list item or a field value ("- general", "sender: bob", "recipients:
# - alice@x.com"): directory data such as a channel list, a contact card or a message header, not a sentence.
# Instructions hide in sentences, so a recipient seen only in prose still needs your OK.
LISTED_LINE = re.compile(r"^[ \t]{0,40}(?:[-*][ \t]{0,4})?(?:[\"']?[\w .-]{1,40}[\"']?[ \t]{0,4}:[ \t]{0,4})?[\"']?"
                         r"([@#]?[\w.+-]{1,100}(?:@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8})?)[\"']?,?[ \t]{0,8}$")
# "reply to the latest email", "answer this message": the email meant is the newest one read.
LATEST_MSG = re.compile(r"\b(?:latest|last|most recent|newest|this|that)\s+(?:e-?mail|message|mail)\b", re.I)
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]")
# A host written as one number (http://3232235777/) or in hex/octal parts is still an IP address.
NUMERIC_HOST = re.compile(r"(?<=://)((?:0x[0-9a-f]{1,8}|\d{1,10})(?:\.(?:0x[0-9a-f]{1,8}|\d{1,10})){0,3})(?=[:/?#]|$)", re.I | re.M)


def _ip_from_parts(host: str) -> str:
    try:
        parts = [int(p, 16) if p.lower().startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)
                 for p in host.split(".")]
        if len(parts) == 1:
            return str(ipaddress.IPv4Address(parts[0]))
        if len(parts) == 4 and all(0 <= x <= 255 for x in parts):
            return ".".join(map(str, parts))
    except (ValueError, ipaddress.AddressValueError):
        pass
    return host


def canon(text: str) -> str:
    """One spelling for the same value: fold full-width/compatibility letters, drop invisible characters,
    undo URL encoding (%40 -> @) and write numeric IP hosts as dotted quads. Attackers use every one of these
    to make a value look different from the one in the poisoned content."""
    if not text.isascii():
        text = INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    if "%" in text:
        for _ in range(2):  # double encoding
            new = unquote(text)
            if new == text:
                break
            text = new
    if "://" in text:
        text = NUMERIC_HOST.sub(lambda m: _ip_from_parts(m.group(1)), text)
    return text


# Addresses spelled out to dodge scrapers (and guards): "name (at) host dot com", "name[at]host[dot]info",
# "name at host dot com". Scanned from each "at" outward with short bounded patterns (see Lessons), so a
# megabyte of prose full of "at" stays fast.
_DOT = r"\s{0,3}[\[({<]\s{0,2}(?:dot|\.)\s{0,2}[\])}>]\s{0,3}|[ \t]{1,3}dot[ \t]{1,3}|\."
_OBF_AT = re.compile(r"\s{0,3}[\[({<]\s{0,2}at\s{0,2}[\])}>]\s{0,3}|(?<=[\w.+-])[ \t]{1,3}at[ \t]{1,3}(?=[\w-])|(?<=[\w.+-])@(?=[\w-])", re.I)
_OBF_LOCAL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}$")
_OBF_DOMAIN = re.compile(rf"[\w-]{{1,63}}(?:(?:{_DOT})[\w-]{{1,63}}){{1,8}}(?![\w-])", re.I)
_OBF_HINT = re.compile(r"[\[({<]\s{0,2}(?:at|dot)\s{0,2}[\])}>]|[ \t]dot[ \t]", re.I)
MAX_OBF = 5000  # candidate "at"s checked per output


def deobfuscated_emails(text: str) -> set[str]:
    out: set[str] = set()
    if not _OBF_HINT.search(text):
        return out
    for n, m in enumerate(_OBF_AT.finditer(text)):
        if n >= MAX_OBF:
            break
        at = m.group(0)
        lm = _OBF_LOCAL.search(text, max(0, m.start() - 65), m.start())
        dm = _OBF_DOMAIN.match(text, m.end())
        if not lm or not dm:
            continue
        local, dom = lm.group(0), dm.group(0)
        labels = re.split(_DOT, dom, flags=re.I)
        spelled_dot = re.sub(r"[\w-]{1,63}", "", dom).replace(".", "") != ""
        if not spelled_dot and (at == "@" or at.strip().lower() == "at"):
            continue  # an ordinary address (EMAIL has it), or prose like "meet at example.com"
        if not re.fullmatch(r"[a-z]{2,24}", labels[-1], re.I) or local.lower() in ("at", "dot"):
            continue
        out.add(f"{local}@{'.'.join(labels)}".strip(".").lower())
    return out


class Found(set):
    """A set that always iterates in sorted order. Verdicts and their wording must never depend on Python's hash
    seed (review 4: the same call got ASK or BLOCK after a restart because "the first tainted value" moved)."""

    def __iter__(self):
        return iter(sorted(set.__iter__(self)))


def indicators(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    text = canon(text)
    for kind, pat in INDICATOR_PATTERNS.items():
        found = {m.group(0).rstrip(".,;:").lower() for m in pat.finditer(text)}
        if kind == "phone":
            found = {re.sub(r"[ -]", "", f) for f in found if len(re.sub(r"\D", "", f)) >= 10}
        if kind == "email":
            found |= deobfuscated_emails(text)
        if found:
            out[kind] = Found(found)
    return out


# Text a reader never sees (a CSS-hidden element) that tells someone to run, install or send something: nobody hides
# instructions from the human reader except to aim them at an AI (review 4: a display:none div with `npm i -g ...`).
HIDDEN_ELEMENT = re.compile(r"<(\w{1,10})\b[^>]{0,300}?(?:style\s{0,3}=\s{0,3}[\"']?[^\"'>]{0,200}?(?:display\s{0,3}:\s{0,3}none|"
                            r"visibility\s{0,3}:\s{0,3}hidden|font-size\s{0,3}:\s{0,3}0(?![.\d])|opacity\s{0,3}:\s{0,3}0(?![.\d])|"
                            r"color\s{0,3}:\s{0,3}(?:white|#fff(?:fff)?)\b)|\shidden(?=[\s>]))[^>]{0,300}>([^<]{1,2000})", re.I)
HIDDEN_ORDER = re.compile(r"`[^`\n]{3,300}`|\b(?:run|execute|install|upload|send|post|email|forward|delete|curl|wget|npm|npx|pip|"
                          r"pipx|uvx|cargo|go install|bash|sh -c|python3?)\b", re.I)


def _hidden_orders(text: str):
    if "<" not in text:
        return None
    for n, m in enumerate(HIDDEN_ELEMENT.finditer(text)):
        if n > 200:
            break
        o = HIDDEN_ORDER.search(m.group(2))
        if o:
            return o
    return None


# Text smuggled past the human reader: Unicode "tag" characters (U+E0020-E007E) render as nothing but spell out
# ASCII to a model, and a base64 run decodes to words a model can follow. Both are revealed and read like the rest of
# the content; a hidden payload that gives orders counts as hidden instructions, like a CSS-hidden element.
TAG_CHARS = re.compile("[\U000e0020-\U000e007e]{4,4000}")
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{24,4096}={0,2}(?![A-Za-z0-9+/=_-])")


def reveal(text: str) -> list[str]:
    """The readable text hidden in `text` as tag characters or base64 (at most 50 pieces)."""
    out: list[str] = []
    if not text.isascii():
        for n, m in enumerate(TAG_CHARS.finditer(text)):
            if n >= 50:
                break
            out.append("".join(chr(ord(c) - 0xE0000) for c in m.group(0)))
    if len(text) >= 24:
        import base64
        import binascii
        for n, m in enumerate(B64_RUN.finditer(text)):
            if n >= 200 or len(out) >= 50:
                break
            t = m.group(0)
            if not re.search(r"[A-Z]", t) or not re.search(r"[a-z]", t):
                continue  # a plain word, path or hex digest, not base64
            try:
                d = base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if " " in d and sum(ch.isprintable() for ch in d) / len(d) > 0.95:
                out.append(d)
    return out


def _smuggled(text: str):
    """A match on the hidden payload when hidden text gives orders, else None."""
    for d in reveal(text):
        m = INJECTION_MARKERS.search(d) or HIDDEN_ORDER.search(d)
        if m:
            return re.search(re.escape(d[:120]), d) or m
    return None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


# ---- Orders in content: a small grammar, not a phrase list ---------------------------------------------------------
# A sentence that tells whoever reads it to act on the outside world: it opens with a verb in the imperative ("Send
# ...", "Please delete ...", "TODO: email ...", "You must transfer ..."), and it names an action an agent can take
# (send, pay, delete, book, invite, visit, create, change). The words that make it an order are ordinary verbs, so
# this works on any wording of an attack; what it catches is the shape. Each kind maps to the capabilities it can
# cause. Nouns that look like verbs ("Book club: Tuesdays", "Transfer complete.") rarely carry the very target the
# agent then acts on, and the engine only uses an order when the action's own target sits inside it.
_K_SEND, _K_MONEY, _K_DELETE, _K_FETCH, _K_WRITE, _K_CRED = "send", "money", "delete", "fetch", "write", "credential"
ORDER_VERBS: dict[str, tuple[str, ...]] = {}
for _words, _kinds in (
    ("send", (_K_SEND, _K_MONEY)),
    ("email e-mail mail forward share post upload message dm text reply tell notify contact cc bcc publish submit ping "
     "introduce leak", (_K_SEND,)),
    ("invite add", (_K_SEND, _K_WRITE)),
    ("pay transfer wire refund deposit donate tip buy purchase", (_K_MONEY,)),
    ("reserve book", (_K_MONEY, _K_WRITE)),
    ("delete remove erase wipe purge cancel trash discard destroy empty unsubscribe kick ban uninstall", (_K_DELETE,)),
    ("visit open browse navigate click load fetch download follow access", (_K_FETCH,)),
    ("create schedule set make write append put save rename move edit modify insert reschedule", (_K_WRITE,)),
    ("change update reset", (_K_WRITE, _K_CRED)),
    # a few other languages, where it is cheap: Spanish, French, German, Portuguese, Italian
    ("envía envia envíe envie manda reenvía reenvia comparte publica sube invita envoie envoyez envoyer transmets transmettre "
     "transmettez partage partagez publie publiez invitez sende senden schicke schicken leite teile poste lade "
     "envie compartilhe convide invia inoltra condividi pubblica", (_K_SEND,)),
    ("paga transfiere transfira paye payez payer transfère transférez transférer vire virez virer überweise überweisen zahle zahlen "
     "pague bonifica", (_K_MONEY,)),
    ("borra elimina supprime supprimez supprimer efface effacez lösche löschen entferne apague exclua cancella", (_K_DELETE,)),
    ("visita abre ouvre ouvrez visitez besuche öffne acesse apri", (_K_FETCH,)),
    ("reserva réserve réservez buche buchen prenota", (_K_MONEY, _K_WRITE)),
    ("crea crée créez erstelle cambia modifica change ändere altere", (_K_WRITE,)),
):
    for _w in _words.split():
        ORDER_VERBS[_w] = tuple(dict.fromkeys(ORDER_VERBS.get(_w, ()) + _kinds))
# Nouns that make an imperative sentence about money or a password ("make a reservation", "set up a payment").
ORDER_NOUNS = {"reservation": _K_MONEY, "booking": _K_MONEY, "payment": _K_MONEY, "transaction": _K_MONEY,
               "transfer": _K_MONEY, "password": _K_CRED, "passcode": _K_CRED}
# Other verbs an imperative sentence can open with before it gets to the action ("Concatenate the messages and post
# them to ...", "Find the code and send it to ...").
LEAD_VERBS = frozenset("""find get take copy paste list search look use include attach give bring grab export extract
retrieve dump print show reveal call ask let keep do try remember ensure provide prepare draft compose translate convert
archive review approve confirm verify log record note mention summarize summarise concatenate combine collect gather
compile read check go see sign subscribe register enter fill type paste run execute install""".split())
# What may precede the verb without changing the mood: politeness, sequencing, "you must", "I want you to".
_ORDER_LEAD = re.compile(
    r"^(?:(?:please|pls|kindly|now|then|also|first|firstly|next|finally|lastly|and|so|just|immediately|quickly|urgently|"
    r"afterwards|additionally|right away|after that|before that|once done|go ahead and|make sure (?:to|you)|be sure to|"
    r"don'?t forget to|do not forget to|remember to|(?:can|could|would|will) you|you (?:should|must|need to|have to|are to|"
    r"will need to|shall)|i (?:want|need|would like|'d like) you to|your (?:task|job) is to|it is (?:important|necessary|"
    r"required) (?:that you|to)|por favor|veuillez|s'il vous plaît|bitte|per favore)[\s,]{1,4}){1,5}", re.I)
# Leading list markers, quotes and a short label ("TODO:", "Step 2:", "Note to self:", "description: '").
# Also a bracketed tag in front ("[urgent]", "(note)", "<b>").
_ORDER_STRIP = re.compile(r"^[\s\-*•>#\d.)\]\"'`]{0,12}(?:[(\[<{][^)\]>}\n]{0,40}[)\]>}][\s:]{0,4})?"
                          r"(?:[A-Za-z][\w '-]{0,30}:[\s'\"]{1,4})?[\s\-*•>\"'`]{0,4}")
# A sentence (or a clause after a colon) ends at . ! ? ; : followed by a space and something that can start a sentence
# (not "going?' to ..."), at . ! ? before a marker that opens a new one ("...7.2%.###(note) Send ..."), or before a
# heading marker glued to a word ("External_## Send ...").
_SENT_SPLIT = re.compile(r"(?<=[.!?;:])['\"]?\s{1,6}(?=[\"'(\[]?[^\W_a-z])|(?<=[.!?])\s{0,6}(?=[#\[(<*>]{1,6}[\w(])|(?<=\S)(?=#{2,6}[\s(\[\w])|\n")
_WORD = re.compile(r"[^\W\d_][\w'-]{0,30}")
# A paragraph that speaks to the AI reading it, not to a person: "AI assistant: ...", "Note to the agent", "if you are
# an LLM", "Claude, please ...". An order there is never the user's, whatever the task says. ("agent" alone is a job:
# "contact your travel agent".)
_AI_WHO = (r"(?:ai|a\.i\.|llms?|chatbots?|bots?|language models?|claude|chatgpt|gpt-?\d?|copilot|gemini|"
           r"(?:ai|virtual|digital|coding|automated|autonomous) (?:assistants?|agents?|models?)|assistants?|agents?|models?)")
AI_ADDRESS = re.compile(
    rf"(?:^|[.!?:]\s{{1,4}})[\W_]{{0,4}}(?:(?:dear|hey|hi|hello|attention|note (?:to|for)|message (?:to|for)|instructions? "
    rf"(?:to|for)|to|for) )?(?:the |an? |any |all )?{_AI_WHO}\s{{0,2}}[:,]|"
    rf"\b(?:dear|hey|attention|note (?:to|for)|message (?:to|for)|instructions? (?:to|for)) (?:the |an? |any |all )?{_AI_WHO}\b|"
    rf"\bif you(?:'re| are) (?:an? |the )?{_AI_WHO}\b|\b(?:ai|llm|language model|chatbot) (?:reading|processing|summari[sz]ing) this\b"
    rf"|\bto you,?\s{{0,2}}(?:the |an? )?{_AI_WHO}\b|\byou are (?:an? )?(?:ai|llm|language model|chatbot)\b|\b(?:claude|chatgpt|gpt-?\d?|copilot|gemini)\s{{0,2}},", re.I)
MAX_ORDERS = 500  # order sentences remembered per session (newest kept)
MAX_ORDER_SCAN = 200_000  # characters of each output read for orders


def _unescape(text: str) -> str:
    """YAML and JSON escapes ("the\\ \\ AI language model") read as spaces, so an address to the AI is still seen."""
    return re.sub(r"\s{2,}", " ", text.replace("\\n", " ").replace("\\", " ")) if "\\" in text else text


def _paragraphs(text: str) -> list[list[str]]:
    """Split prose into paragraphs of sentences. Literal "\\n" escapes are line breaks; a line that just continues the
    one before it (wrapped prose, YAML-folded strings) is joined, while a new list item, a "label:" line, a blank line
    or a line after one that ended a sentence starts a new paragraph. Linear time: parts are joined once at the end."""
    text = text.replace("\\n", "\n").replace("''", "'")
    paras: list[list[str]] = []
    size = 0
    head_indent = -1  # indentation of a "label: value" line that opened the paragraph, else -1
    for ln in text.split("\n"):
        st = ln.strip()[:2000]
        indent = len(ln) - len(ln.lstrip())
        prev = paras[-1][-1] if paras and paras[-1] else ""
        # A header line at the margin ("From: a@b.c") never continues onto the body below it; an indented one (inside a
        # folded YAML value) does.
        if prev and st and size < 20_000 and not _NEW_ITEM.match(st) and not _ENDS.search(prev[-8:]) \
                and (indent > head_indent or indent == head_indent > 0):
            paras[-1].append(st)
            size += len(st)
        else:
            paras.append([st] if st else [])
            size = len(st)
            head_indent = indent if _NEW_ITEM.match(st) and ":" in st[:34] else -1
    return [[p for p in _SENT_SPLIT.split(" ".join(parts)) if p.strip()] for parts in paras if parts]


_NEW_ITEM = re.compile(r"[-*•>#]|\d{1,3}[.)]\s|[A-Za-z][\w '-]{0,30}:\s")
_ENDS = re.compile(r"[.!?:;]['\"]?\s{0,4}$")
# A word after the first that makes the first a noun: "Transfer complete", "Payment received", "Book of the month".
_NOUN_NEXT = frozenset("""is are was were has have had of 's complete completed confirmed received failed pending
successful succeeded scheduled sent done status summary history details id number date notification receipt
confirmation report reminder club office""".split())


def order_kinds(sentence: str) -> tuple[str, ...]:
    """The kinds of action a sentence orders its reader to take, or () if it is not an order. An order opens with a verb
    in the imperative (after politeness, sequencing words, "you must" or a short label) and names an action."""
    s = _ORDER_STRIP.sub("", sentence.strip(), count=1)
    for _ in range(2):  # "AI: TODO: please ..."
        s = _ORDER_LEAD.sub("", s, count=1)
        s = _ORDER_STRIP.sub("", s, count=1)
    words = [w.lower() for w in _WORD.findall(s[:600])]
    if not words:
        return ()
    head = words[0]
    if head not in ORDER_VERBS and head not in LEAD_VERBS:
        return ()
    if len(words) > 1 and words[1] in _NOUN_NEXT:
        return ()  # "Transfer complete", "Book of the month": a noun, not a command
    kinds: dict[str, None] = {}
    for w in words[:80]:
        for k in ORDER_VERBS.get(w, ()):
            kinds[k] = None
        if w in ORDER_NOUNS:
            kinds[ORDER_NOUNS[w]] = None
    return tuple(kinds)


@dataclass
class TaintSource:
    tool: str
    snippet: str
    injected: bool = False  # the output this came from also carried hidden instructions
    label: str = ""  # human name for the source, e.g. "README.md"; falls back to the tool name
    seq: int = 0  # which observation it came from (one number per tool output)

    @property
    def where(self) -> str:
        return self.label or self.tool


@dataclass
class TaintStore:
    trusted_text: str = ""
    trusted: dict[str, set[str]] = field(default_factory=dict)
    # indicator value -> where it came from
    untrusted: dict[str, TaintSource] = field(default_factory=dict)
    # normalised lines from untrusted outputs that look like commands or instructions
    untrusted_lines: list[tuple[str, TaintSource]] = field(default_factory=list)
    injection_seen: list[TaintSource] = field(default_factory=list)
    seen: int = 0  # tool outputs observed so far
    # people who wrote messages the agent read: address -> came from content with hidden instructions
    senders: dict[str, bool] = field(default_factory=dict)
    # values listed on their own line in some output (see LISTED_LINE): value -> came from injected content
    listed: dict[str, bool] = field(default_factory=dict)
    # values you named only after hidden instructions were seen: not trusted, but not "never mentioned" either
    unverified: set[str] = field(default_factory=set)
    # one row per message read (sender, its name words, whether that message itself had hidden instructions, which
    # output it came from); used to find "the email from Sam" when you ask to reply to Sam
    messages: list[list] = field(default_factory=list)
    # Reply-To addresses seen on messages: where the writer asked replies to go, never trusted as the sender
    reply_to: dict[str, bool] = field(default_factory=dict)
    # addresses mentioned inside a message that had hidden instructions (not as its sender)
    in_orders: set[str] = field(default_factory=set)
    # sentences in content that order the reader to act (see order_kinds): [lower-cased sentence, kinds, source]
    orders: list[list] = field(default_factory=list)

    def add_trusted(self, text: str, exclude_injected: bool = False) -> None:
        """exclude_injected: values that came from content with hidden instructions stay untrusted (a prompt sent
        over the API after an injection can't vouch for the attacker's own address)."""
        norm = _norm(canon(text))
        for kind, vals in indicators(text).items():
            if exclude_injected:
                # After an attack, a new prompt vouches for no address, host or value at all. Matching only the values
                # still in memory wasn't enough: after a reset the memory is empty and the attacker's address
                # would be trusted again. A real follow-up to a new person just asks once.
                bad = set(vals)
                self.unverified |= bad
                for v in bad:
                    norm = norm.replace(v, "[unverified]")
                vals = vals - bad
            self.trusted.setdefault(kind, set()).update(vals)
        self.trusted_text += "\n" + norm

    def add_untrusted(self, tool: str, text: str, label: str = "") -> None:
        text = text[:MAX_OBSERVE]
        self.seen += 1
        seq = self.seen
        m = INJECTION_MARKERS.search(text) or INJECTION_MARKERS.search(canon(text)) or _hidden_orders(text)
        hidden = reveal(text)
        if hidden:
            m = m or _smuggled(text)
            raw = text  # message headers are split on what the reader sees
            text = text + "\n\n" + "\n\n".join(hidden)
        else:
            raw = text
        for vals in indicators(text).values():
            for v in vals:
                if v not in self.untrusted or (m and not self.untrusted[v].injected):
                    self.untrusted[v] = TaintSource(tool, _snippet(text, v), injected=bool(m), label=label, seq=seq)
        for line in text.splitlines():
            if len(line) <= 240:
                lm = LISTED_LINE.match(line)
                if lm:
                    v = lm.group(1).lower()
                    self.listed[v] = self.listed.get(v, False) or bool(m)
            n = _norm(line)
            if 8 <= len(n) <= 400:
                self.untrusted_lines.append((n, TaintSource(tool, line.strip()[:160], injected=bool(m), label=label, seq=seq)))
        self.untrusted_lines = self.untrusted_lines[-5000:]
        spoke_to_ai = False  # once a text speaks to the AI ("a message to you, GPT-4."), what follows is for it too
        for para in _paragraphs(text[:MAX_ORDER_SCAN]):
            # An order and the sentences after it in the same paragraph ("Create an event on May 1. The title should
            # be 'X'.") are one instruction: the details belong to the order.
            kinds: tuple[str, ...] = ()
            to_ai = spoke_to_ai = spoke_to_ai or any(AI_ADDRESS.search(_unescape(x[:1000])) for x in para)
            for sent in para:
                if len(sent) > 1000:
                    continue
                kinds = tuple(dict.fromkeys(kinds + order_kinds(sent)))
                if kinds:
                    src = TaintSource(tool, " ".join(sent.split())[:200], injected=bool(m), label=label, seq=seq)
                    self.orders.append([_norm(canon(sent)), list(kinds), src, to_ai])
        self.orders = self.orders[-MAX_ORDERS:]
        heads = []
        for sm in SENDER_LINE.finditer(raw):
            reply_to = sm.group(1).lower().replace("_", "-") in ("reply-to", "replyto")
            for kind in ("email", "phone"):
                for v in indicators(sm.group(2)).get(kind, ()):
                    if reply_to:
                        self.reply_to[v] = self.reply_to.get(v, False) or bool(m)
                    else:
                        self.senders[v] = self.senders.get(v, False) or bool(m)
            if not reply_to:
                heads.append(sm)
        if heads:
            self._add_messages(raw, heads, seq, bool(m))
        if m:
            self.injection_seen.append(TaintSource(tool, _snippet(text, m.group(0)), injected=True, label=label))

    def _add_messages(self, text: str, heads: list, seq: int, any_orders: bool) -> None:
        """Split one output into messages at each From/sender line and judge each message on its own: an inbox with
        one attacker email does not make Sam's lunch email an attacker's. Text before the first sender line belongs
        to the first message."""
        heads = heads[:MAX_MESSAGES]
        for i, sm in enumerate(heads):
            start = 0 if i == 0 else sm.start()
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            seg = text[start:end]
            orders = bool(any_orders and (INJECTION_MARKERS.search(seg) or INJECTION_MARKERS.search(canon(seg))
                                          or _hidden_orders(seg) or _smuggled(seg)))
            line = canon(sm.group(2))
            addrs = sorted(indicators(line).get("email", ()))
            if orders:
                hid = "\n".join(reveal(seg))
                self.in_orders |= {v for v in indicators(seg + "\n" + hid).get("email", ()) if v not in addrs}
            for a in addrs:
                local = a.split("@")[0]
                words = re.findall(r"[a-z]{2,30}", EMAIL.sub(" ", line).lower()) + re.findall(r"[a-z]{2,30}", local)
                self.messages.append([a, sorted(set(words)), orders, seq])
        self.messages = self.messages[-MAX_MESSAGES:]

    def reply_targets(self, task: str) -> dict[str, bool]:
        """The people you asked to reply to: the sender of the email you pointed at, by name ("reply to Sam",
        "answer Priya's email") or as "the latest email". Address -> True if that very email had hidden
        instructions. A name that fits two different addresses picks nobody (one could be a forged display name)."""
        if not self.messages or not task:
            return {}
        words = {w.lower() for w in re.findall(r"[A-Za-z]{3,30}", task)} - GENERIC_NAMES
        by_name: dict[str, set[str]] = {}
        for a, names, _, _ in self.messages:
            for n in names:
                if n in words and n not in GENERIC_NAMES:
                    by_name.setdefault(n, set()).add(a)
        picked = {next(iter(v)) for v in by_name.values() if len(v) == 1}
        if LATEST_MSG.search(task):
            last = self.messages[-1][3]
            first = next(r for r in self.messages if r[3] == last)
            picked.add(first[0])
        out: dict[str, bool] = {}
        for a in sorted(picked):
            # "taken from hidden instructions" anywhere else also counts against it
            out[a] = any(r[2] for r in self.messages if r[0] == a) or a in self.in_orders
        return out

    def ordered(self, values: list[str], kinds: tuple[str, ...]) -> tuple[str, TaintSource, bool] | None:
        """A value the action uses that sits inside a sentence in content ordering the reader to take this kind of
        action, and that you never named yourself. Longest value first (the most specific), then by name. The flag
        says the order's paragraph speaks to the AI ("AI assistant: ...", "if you are an agent")."""
        if not self.orders:
            return None
        cands = sorted({_norm(canon(v)).strip("'\" ") for v in values if v}, key=lambda v: (-len(v), v))
        for v in cands:
            if not (2 <= len(v) <= 200) or self.is_trusted_value(v) or _whole(v, self.trusted_text):
                continue
            pat = None
            for sent, ks, src, *rest in reversed(self.orders):
                if v not in sent or not any(k in kinds for k in ks):
                    continue
                pat = pat or re.compile(rf"(?<![\w@+-]){re.escape(v)}(?![\w@+-]|\.[\w])")
                if pat.search(sent):
                    return v, src, bool(rest and rest[0])
        return None

    def listed_plainly(self, value: str, where: TaintSource | None = None) -> bool:
        """`value` sits on a line of clean content that gives no orders ("Attendees: Ana (ana@x.com), Raj (...)"), so
        the document lists it, rather than only a sentence telling the reader to send something to it. With `where`,
        only lines of that same tool output count (the document that supplied the address, not a later inbox)."""
        v = _norm(canon(value))
        order_text = [o[0] for o in self.orders if v in o[0]]
        for line, src in reversed(self.untrusted_lines[-5000:]):
            if src.injected or not _whole(v, line):
                continue
            if where is not None and (src.seq, src.tool, src.label) != (where.seq, where.tool, where.label):
                continue
            if any(order_kinds(sent) for para in _paragraphs(line) for sent in para):
                continue
            piece = _norm(canon(line.replace("\\n", " ").replace("''", "'")))  # as _paragraphs reads it
            # The words of this line's sentence up to the address: inside an order, the line is a wrapped piece of it.
            frags = [x.strip()[:x.strip().index(v) + len(v)] for x in re.split(r"(?<=[.!?;])\s{1,6}", piece) if v in x]
            if any(x in o for x in frags for o in order_text):
                continue  # a wrapped piece of an order ("...the code to\n  x@y.com before Friday. Thanks")
            return True
        return False

    def is_trusted_value(self, value: str) -> bool:
        """Did the user name exactly this value? Whole values only: naming alice@corp.com does not vouch for
        alice@corp.co, lice@corp.com or ce@corp.com (a substring test passed all three). A host also counts when
        it is a subdomain of a domain or web address the user named."""
        v = canon(value).lower().strip().rstrip(".,;:")
        if not v:
            return False
        if any(v in vals for vals in self.trusted.values()):
            return True
        if "@" not in v and "/" not in v and "." in v:
            for d in self.trusted_hosts():
                if v == d or v.endswith("." + d):
                    return True
        return _whole(v, self.trusted_text)

    def trusted_hosts(self) -> set[str]:
        out = set(self.trusted.get("domain", ()))
        for u in self.trusted.get("url", ()):
            m = re.match(r"^[a-z][\w+.-]{0,20}://(?:[^@/\s]{0,256}@)?([^/:?#\s]{1,256})", u)
            if m:
                out.add(m.group(1))
        return out

    def names_path(self, path: str, cwd: str | None = None) -> bool:
        """Did the user name this file? Compared as normalised absolute paths (Claude Code sends absolute paths,
        the user types relative ones), or by exact file name when the user gave a bare name like ".env"."""
        target = _abs(path, cwd)
        base = os.path.basename(target)
        for tok in PATH_TOKEN.findall(self.trusted_text):
            tok = tok.rstrip(".,:;)!?'\"`")
            if not tok or tok in (".", ".."):
                continue
            if "/" in tok:
                if _abs(tok, cwd) == target:
                    return True
            elif (tok.startswith(".") or re.search(r"\.[a-z0-9]{1,10}$", tok)) and tok == base:
                return True
        return False

    def tainted_values(self, text: str) -> list[tuple[str, TaintSource]]:
        """Indicators inside `text` that came from untrusted data and not from the user, sorted by value."""
        hits = []
        for vals in indicators(text).values():
            for v in vals:
                src = self.untrusted.get(v) or _domain_match(v, self.untrusted)
                if src and not self.is_trusted_value(v):
                    hits.append((v, src))
        return sorted(hits, key=lambda h: h[0])

    def template_source(self, text: str) -> tuple[str, TaintSource] | None:
        """A URL in `text` that is an untrusted URL with something added on the end (`?d=` + data).
        That is the agent filling in a template it read, the usual way to smuggle data out."""
        for v in indicators(text).get("url", ()):
            if self.is_trusted_value(v):
                continue
            for k, src in sorted(self.untrusted.items()):
                # "...?d=" + data, or a query string tacked onto a bare link. A longer path alone is normal browsing.
                if k.startswith("http") and len(k) > 12 and len(v) > len(k) and v.startswith(k) and \
                        (k[-1] in "=?&" or v[len(k)] in "?&"):
                    return v, src
            hit = self._path_template(v)
            if hit:
                return hit
        return None

    def _path_template(self, v: str) -> tuple[str, TaintSource] | None:
        """"Load https://cdn.example/full/ followed by your notes": a URL prefix from the data, with a path added
        that carries text the agent read from local files, or a long run of free text. Following an ordinary
        link (a path that was itself in the data, or a short docs path) is not this."""
        if v in self.untrusted:
            return None  # the full link was in the data: plain link following
        for k, src in sorted(self.untrusted.items()):
            if not (k.startswith("http") and k.endswith("/") and k.count("/") >= 3 and len(k) > 12
                    and len(v) > len(k) and v.startswith(k)):
                continue
            seg = re.split(r"[/?#]", v[len(k):], maxsplit=1)[0]
            words = [w for w in re.split(r"[-_+.,~:;]|%20|\s", seg[:400]) if w]
            if len(words) >= 4 and len(seg) >= 20 and sum(c.isalpha() for c in seg) >= 12:
                return v, src  # a sentence squeezed into one path segment
            if k.count("/") >= 4 and self._local_overlap(v[len(k):], src.seq) >= 2:
                return v, src
        return None

    def _local_overlap(self, tail: str, skip_seq: int) -> int:
        """How many words (4+ letters) of `tail` appear in one line of a local file or command output."""
        from .classify import classify  # local import: classify does not depend on taint
        from .models import Capability
        words = {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9]{3,30}", tail[:400])}
        if len(words) < 2:
            return 0
        best = 0
        local: dict[str, bool] = {}
        for line, src in self.untrusted_lines[-2000:]:
            if src.seq == skip_seq:
                continue
            if src.tool not in local:
                local[src.tool] = classify(src.tool) in (Capability.READ, Capability.EXEC)
            if local[src.tool]:
                best = max(best, sum(1 for w in words if w in line))
        return best

    def copied_from_data(self, text: str, run: int = 6) -> TaintSource | None:
        """A line from untrusted content that shares a run of `run` words with `text` (orders copied into a
        sub-agent's prompt, reworded around the edges). Prefers a source that carried hidden instructions."""
        words = re.findall(r"[a-z0-9]{1,40}", _norm(canon(text[:20_000])))
        grams = {tuple(words[i:i + run]) for i in range(len(words) - run + 1)}
        if not grams:
            return None
        best = None
        for line, src in reversed(self.untrusted_lines[-2000:]):
            lw = re.findall(r"[a-z0-9]{1,40}", line)
            if any(tuple(lw[i:i + run]) in grams for i in range(len(lw) - run + 1)):
                if _whole(line, self.trusted_text):
                    continue
                if src.injected:
                    return src
                best = best or src
        return best

    def value_source(self, value: str) -> TaintSource | None:
        """Where content the agent read named `value` as a whole word (a package name, a program), preferring a
        source with hidden instructions."""
        v = value.lower()
        pat = re.compile(rf"(?<![\w@/.-]){re.escape(v)}(?![\w/-])")
        best = None
        for line, src in reversed(self.untrusted_lines[-5000:]):
            if v in line and pat.search(line):
                if src.injected:
                    return src
                best = best or src
        return best

    def command_from_data(self, command: str) -> TaintSource | None:
        """Did this shell command appear verbatim inside something the agent read?"""
        n = _norm(command)
        if len(n) < 8 or n in self.trusted_text:
            return None
        for line, src in reversed(self.untrusted_lines):
            if n in line:
                return src
        return None


_NO_SRC = TaintSource("", "")
PATH_TOKEN = re.compile(r"(?<![\w@:/])[~.\w][\w./~+-]{0,255}")


def _abs(path: str, cwd: str | None) -> str:
    p = os.path.expanduser(os.path.expandvars(path.strip()))
    if not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    return os.path.normpath(p).lower()


def _whole(v: str, text: str) -> bool:
    """`v` appears in `text` as a whole value, not as part of a longer address, word or path."""
    if not v or v not in text:
        return False
    return re.search(rf"(?<![\w.@+-]){re.escape(v)}(?![\w@+-]|\.[\w])", text) is not None


def _domain_match(value: str, untrusted: dict[str, TaintSource]) -> TaintSource | None:
    """The untrusted value this one is part of (or that is part of it). Several can match: prefer one from content
    with hidden instructions, then the longest, then by name, so the answer never depends on dict order."""
    hits = [(src.injected, len(k), k, src) for k, src in untrusted.items() if len(k) > 5 and (k in value or value in k)]
    return max(hits, key=lambda h: h[:3])[3] if hits else None


def _snippet(text: str, needle: str, width: int = 70) -> str:
    i = text.lower().find(needle.lower())
    if i < 0:
        return text[:width * 2].strip()
    s = text[max(0, i - width): i + len(needle) + width]
    return " ".join(s.split())
