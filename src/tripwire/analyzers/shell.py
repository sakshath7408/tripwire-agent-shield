"""Shell command analysis. Parses commands into an AST (bashlex), never plain regex alone.

Contract: analyze_shell(command, session) -> list[Finding]. Pure, fast (<5 ms typical),
never raises (a parse failure is itself a finding, since obfuscation often breaks parsers).

How it works:
1. Raw-text checks that survive any parse (fork bombs, invisible characters, homoglyphs, $IFS,
   /dev/tcp, guard tampering). Tricks that hide a command are undone and the clean text is re-analyzed.
2. The command is parsed into a small IR: a script is a list of pipelines, a pipeline is a list of
   simple commands. bashlex is the main parser; a shlex-based tokenizer is the fallback.
   Command substitutions, process substitutions, heredocs, `bash -c`, `eval`, `python -c` payloads and
   decoded base64/hex payloads are all re-analyzed recursively.
3. Rules run per command (rm, curl, chmod, git ...), per pipeline (download | sh, cat secret | nc)
   and per script (download, then chmod +x, then run).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import glob
import gzip
import os
import re
import shlex
import unicodedata
from dataclasses import dataclass, field

import bashlex

from ..models import CRITICAL, HIGH, LOW, MEDIUM, Finding
from ..session import Session
from . import paths

MAX_DEPTH = 6
MAX_LEN = 50_000
HOME = os.path.expanduser("~")

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "mksh"}
INTERPS = {"python", "node", "nodejs", "perl", "ruby", "php", "pwsh", "powershell", "lua", "bun", "deno", "osascript"}
DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "http", "https", "xh", "lwp-download", "lwp-request"}
NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "tftp",
             "http", "https", "xh", "mail", "mailx", "sendmail", "mutt", "aws", "gsutil", "rclone", "gh", "s3cmd",
             "azcopy", "smbclient"}
RAW_SOCKET = {"nc", "ncat", "netcat", "socat", "telnet"}
READERS = {"cat", "tac", "less", "more", "head", "tail", "nl", "bat", "batcat", "view", "vi", "vim", "nvim", "nano",
           "emacs", "base64", "xxd", "od", "hexdump", "strings", "grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk",
           "sed", "cut", "sort", "uniq", "jq", "yq", "openssl", "gpg", "tar", "zip", "7z", "gzip", "bzip2", "xz",
           "sqlite3", "cp", "diff", "paste", "pbcopy", "xclip", "column", "fold", "iconv", "rev", "tr"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed", "jq", "yq"}
DNS_TOOLS = {"dig", "nslookup", "host", "drill", "ping", "ping6", "traceroute", "whois"}
SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "clickhouse-client", "cockroach", "mongo", "mongosh",
               "redis-cli", "cqlsh", "duckdb"}
DANGEROUS_NAMES = {"rm", "curl", "wget", "nc", "ncat", "netcat", "bash", "sh", "zsh", "dd", "chmod", "chown", "eval",
                   "base64", "mkfs", "shred", "socat", "perl", "sudo", "crontab", "kill", "pkill", "scp", "rsync",
                   "ssh", "xxd", "openssl", "telnet", "python", "cat", "find", "mv"}
BUILD_DIRS = {"node_modules", "dist", "build", "out", ".next", ".nuxt", "target", "__pycache__", ".pytest_cache",
              ".mypy_cache", ".ruff_cache", ".tox", ".nox", "coverage", ".coverage", "htmlcov", ".venv", "venv", "env",
              ".cache", ".turbo", ".parcel-cache", ".svelte-kit", ".angular", ".gradle", "bin", "obj", "tmp", "temp",
              ".expo", "storybook-static", "site", "_build", ".eggs", "pip-wheel-metadata", "logs", ".terraform"}
EXTRA_SYSTEM = {"/Users", "/home", "/Applications", "/Volumes", "/root", "/dev", "/proc", "/sys", "/mnt", "/srv",
                "/lib", "/lib64", "/tmp", "/private/tmp", "/private", "/private/var", "/cores", "/Network"}
TMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/", "/var/tmp/", "/private/var/tmp/")
OFFICIAL_REGISTRIES = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
                       "crates.io", "rubygems.org", "proxy.golang.org", "test.pypi.org"}

SECRET_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PASS|API_?KEY|PRIVATE_KEY|"
                        r"ACCESS_KEY|CREDENTIALS?)[A-Za-z0-9_]*)\}?")
GUARD_RE = re.compile(r"(?:^|[\s/~\"'=:}])\.tripwire\b|\.claude/settings[\w.-]*\.json")
KILL_GUARD_RE = re.compile(r"\b(pkill|killall|kill)\b[^;&|\n]*\b(tripwire|7777)\b|\b(lsof|fuser)\b[^;&\n]*\b7777\b[^;&\n]*\bkill\b|"
                           r"\buninstall\b[^;&|\n]*\btripwire\b|\blaunchctl\s+(unload|bootout|remove|disable)\b[^;&|\n]*tripwire", re.I)
FORK_BOMB = re.compile(r"([\w:]+)\s*\(\s*\)\s*\{[^}]*\1\s*\|\s*\1\s*&|\bwhile\s*(?:\(\s*1\s*\)|true|:)\s*[;{]?\s*(?:do)?\s*\{?[^}]*\bfork\b")
DEV_TCP = re.compile(r"/dev/(tcp|udp)/[^\s;|&)]+")
REV_SHELL_HINT = re.compile(r"\b(?:ba|z|k|da)?sh\b[^|;&]*\s-i\b|0>&1|>&\s*/dev/tcp|<&\s*\d|\bexec\s+\d*<>")
HIST_RE = re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null|\bHISTSIZE=0\b|\bHISTFILESIZE=0\b|"
                     r"\bset\s+\+o\s+history\b")
SEC_OFF_RE = re.compile(r"\bcsrutil\s+disable\b|\bspctl\s+--(?:master|global)-disable\b|\bsetenforce\s+0\b|"
                        r"\bufw\s+disable\b|\biptables\s+-F\b|Set-MpPreference\b.*-Disable|LSQuarantine\b.*\bfalse\b|"
                        r"\bsystemsetup\s+-setremotelogin\s+on\b|\bauditctl\s+-D\b", re.I)
DB_WIPE_RE = re.compile(r"\b(?:rake|rails)\s+db:(?:drop|reset|purge)\b|\bprisma\s+migrate\s+reset\b|--force-reset\b|"
                        r"\bmanage\.py\s+flush\b|\bdropdb\b")
SQL_DROP_DB = re.compile(r"\bdrop\s+(?:database|schema)\b|dropDatabase\s*\(", re.I)
SQL_DROP_TABLE = re.compile(r"\bdrop\s+table\b|\btruncate\s+table\b|\btruncate\s+[\w.\"`]+\s*;|\.drop\s*\(\s*\)|"
                            r"deleteMany\s*\(\s*\{\s*\}\s*\)|\bflushall\b|\bflushdb\b", re.I)
SQL_DELETE_ALL = re.compile(r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*(?:;|$|[\"')])", re.I | re.M)
SUSPICIOUS = re.compile(r"\b(eval|base64|xxd|openssl|nc|ncat|socat|curl|wget)\b|\\x[0-9a-fA-F]{2}|/dev/(tcp|udp)")
URLISH = re.compile(r"^(?:git\+)?(?:https?|git|ssh|ftp|file)://|^git@|^(?:github|gitlab|bitbucket):", re.I)
URL_HOST = re.compile(r"^(?:[a-z][\w+.-]*://)?(?:[^@/\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)", re.I)
DOMAINISH = re.compile(r"^(?:[\w-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#].*)?$", re.I)
LOCAL_HOST = re.compile(r"^(localhost|127\.[\d.]+|0\.0\.0\.0|\[?::1\]?|[\w.-]+\.localhost|host\.docker\.internal)$", re.I)
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ӏ": "l", "ɑ": "a", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "ο": "o", "α": "a", "ν": "v", "ι": "i", "ρ": "p", "τ": "t", "κ": "k", "ԝ": "w",
    "ɡ": "g", "ѵ": "v", "ԛ": "q", "ս": "u", "ɩ": "i", "Ꭵ": "i",
})
REV_SOCK = re.compile(r"socket|fsockopen|TCPSocket|net\.connect|new\s+net\.Socket|IO::Socket|TCPClient", re.I)
REV_EXEC = re.compile(r"\bpty\b|subprocess|dup2|/bin/(?:ba)?sh|\bexec\b|spawn|popen|system\s*\(|child_process|"
                      r"proc_open|cmd\.exe|powershell", re.I)
FETCH_CODE = re.compile(r"urlopen|requests\.(?:get|post)|urllib|http\.client|\bfetch\s*\(|https?\.get\s*\(|"
                        r"open-uri|Net::HTTP|LWP::|Invoke-WebRequest|\biwr\b|DownloadString|WebClient|curl_exec")
EXEC_CODE = re.compile(r"\b(?:exec|eval|IEX|Invoke-Expression|execfile|compile)\b|new\s+Function\s*\(|\bFunction\s*\(")
DECODE_CODE = re.compile(r"b64decode|base64|atob\s*\(|fromCharCode|unhexlify|fromhex|codecs\.decode|rot13|"
                         r"zlib\.decompress|marshal\.loads|FromBase64String|Buffer\.from\([^)]*['\"](?:base64|hex)", re.I)
SHELL_CALL = re.compile(r"""(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|"""
                        r"""getstatusoutput)|commands\.getoutput|\.exec(?:Sync)?|spawnSync|\bsystem|shell_exec|passthru|"""
                        r"""proc_open|\bpopen|do\s+shell\s+script|`)\s*\(?\s*(['"])(.+?)(?<!\\)\1""", re.S)


# ---------------------------------------------------------------------------- IR
@dataclass
class Cmd:
    words: list[str]
    raw_words: list[str] = field(default_factory=list)
    redirects: list[tuple[str, str]] = field(default_factory=list)
    subs: list[tuple[str, int, list]] = field(default_factory=list)  # (kind, word index or -1, inner script)
    assigns: list[tuple[str, str]] = field(default_factory=list)
    assign_subs: dict[str, list] = field(default_factory=dict)
    heredoc: str | None = None
    herestring: str | None = None
    raw: str = ""


@dataclass
class Info:
    c: Cmd
    name: str = ""
    args: list[str] = field(default_factory=list)
    exec_path: str = ""
    wrappers: set[str] = field(default_factory=set)
    traits: set[str] = field(default_factory=set)
    host: str | None = None
    stdin_send: bool = False
    outputs: list[str] = field(default_factory=list)
    find_roots: list[str] = field(default_factory=list)
    find_filtered: bool = False


# ---------------------------------------------------------------------------- helpers
def _clip(s: str | None, n: int = 160) -> str | None:
    if s is None:
        return None
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _base(word: str) -> str:
    w = word.lstrip("\\")
    if "/" in w and not w.endswith("/"):
        w = w.rsplit("/", 1)[1]
    w = w.lower()
    return re.sub(r"^(python|pip)[\d.]*$", r"\1", w)


def _unescape(s: str) -> tuple[str, bool]:
    """Decode bash $'...' / printf style escapes. Returns (text, used_hex_or_octal)."""
    out: list[str] = []
    i, hexy = 0, False
    simple = {"n": "\n", "t": "\t", "r": "\r", "e": "\x1b", "E": "\x1b", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
              "\\": "\\", "'": "'", '"': '"', "?": "?"}
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
                if m:
                    out.append(chr(int(m.group(), 16)))
                    i += 2 + len(m.group())
                    hexy = True
                    continue
            if n in "01234567":
                m = re.match(r"0?[0-7]{1,3}", s[i + 1:])
                if m:
                    out.append(chr(int(m.group(), 8) & 0xFF))
                    i += 1 + len(m.group())
                    hexy = True
                    continue
            if n in "uU":
                m = re.match(r"[0-9a-fA-F]{1,8}", s[i + 2:])
                if m:
                    try:
                        out.append(chr(int(m.group(), 16)))
                    except (ValueError, OverflowError):
                        pass
                    i += 2 + len(m.group())
                    hexy = True
                    continue
            if n in simple:
                out.append(simple[n])
                i += 2
                continue
            out.append(c + n)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out), hexy


def _b64(s: str) -> str | None:
    t = re.sub(r"\s+", "", s)
    if not t:
        return None
    t += "=" * (-len(t) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(t.encode("latin-1", "ignore")).decode("latin-1")
        except (binascii.Error, ValueError):
            continue
    return None


def _printable(s: str) -> bool:
    if not s:
        return False
    try:
        s = s.encode("latin-1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    ok = sum(ch.isprintable() or ch in "\n\t\r" for ch in s)
    return ok / len(s) > 0.9


def _to_text(s: str) -> str:
    try:
        return s.encode("latin-1").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return s


def _is_secret(full: str) -> bool:
    return paths.is_secret(full) or paths.is_secret(full.rstrip("/") + "/")


def _host(url: str | None) -> str | None:
    if not url:
        return None
    m = URL_HOST.match(url.strip())
    return m.group(1).lower() if m else None


def _first_url(args: list[str]) -> str | None:
    for a in args:
        if "://" in a:
            return a
    for a in args:
        if not a.startswith("-") and DOMAINISH.match(a):
            return a
    for a in args:  # user@host:path, host:path
        m = re.match(r"^(?:[\w.-]+@)?([\w.-]+\.[\w.-]+|\d+\.\d+\.\d+\.\d+):", a)
        if m:
            return m.group(1)
    return None


def _parse_opts(args: list[str], short_val: str, long_val: set[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Generic getopt-ish parser. Returns ([(flag, value)], positionals). Flags without values get ''."""
    opts: list[tuple[str, str]] = []
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos += args[i + 1:]
            break
        if a.startswith("--") and len(a) > 2:
            if "=" in a:
                k, v = a.split("=", 1)
                opts.append((k, v))
            elif a in long_val and i + 1 < len(args):
                opts.append((a, args[i + 1]))
                i += 1
            else:
                opts.append((a, ""))
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in short_val:
                    rest = a[j + 1:]
                    if rest:
                        opts.append(("-" + ch, rest))
                    elif i + 1 < len(args):
                        opts.append(("-" + ch, args[i + 1]))
                        i += 1
                    else:
                        opts.append(("-" + ch, ""))
                    break
                opts.append(("-" + ch, ""))
                j += 1
        else:
            pos.append(a)
        i += 1
    return opts, pos


def _unwrap(words: list[str]) -> tuple[list[str], set[str]]:
    """Strip sudo/env/nohup/timeout/xargs/... and return the real command plus what wrapped it."""
    wr: set[str] = set()
    i = 0
    n = len(words)
    while i < n:
        name = _base(words[i])
        if name in ("sudo", "doas", "pkexec", "run0"):
            wr.add("sudo")
            i += 1
            while i < n and words[i].startswith("-"):
                o = words[i]
                i += 1
                if o == "--":
                    break
                if o in ("-u", "-g", "-C", "-p", "-h", "-U", "-r", "-t", "-D", "-T", "--user", "--group", "--prompt"):
                    i += 1
                if not o.startswith("--"):
                    if "i" in o[1:] or "s" in o[1:]:
                        wr.add("sudo_shell")
                    if "S" in o[1:]:
                        wr.add("sudo_stdin")
                elif o in ("--login", "--shell"):
                    wr.add("sudo_shell")
                elif o == "--stdin":
                    wr.add("sudo_stdin")
            while i < n and re.match(r"^\w+=", words[i]):
                i += 1
            continue
        if name == "env":
            j = i + 1
            while j < n:
                w = words[j]
                if w in ("-u", "--unset", "-C", "--chdir"):
                    j += 2
                elif w in ("-S", "--split-string") and j + 1 < n:
                    try:
                        words = words[:j] + shlex.split(words[j + 1]) + words[j + 2:]
                    except ValueError:
                        words = words[:j] + words[j + 1].split() + words[j + 2:]
                    n = len(words)
                elif w.startswith("-") or re.match(r"^\w+=", w):
                    j += 1
                else:
                    break
            if j >= n:
                return ["env"], wr
            i = j
            continue
        if name in ("nohup", "time", "builtin", "caffeinate", "unbuffer", "nocorrect", "noglob", "exec", "then", "do",
                    "else", "!", "busybox", "torsocks", "proxychains", "proxychains4", "tsocks", "chronic"):
            i += 1
            while i < n and words[i].startswith("-") and name in ("time", "exec", "caffeinate"):
                i += 2 if words[i] == "-a" else 1
            continue
        if name == "command":
            if i + 1 < n and words[i + 1] in ("-v", "-V"):
                break
            i += 1
            while i < n and words[i].startswith("-"):
                i += 1
            continue
        if name in ("nice", "ionice", "stdbuf", "chrt", "taskset"):
            i += 1
            while i < n and (words[i].startswith("-") or re.fullmatch(r"\d+", words[i])):
                i += 2 if words[i] in ("-n", "-c", "-p") else 1
            continue
        if name in ("timeout", "gtimeout"):
            i += 1
            while i < n and words[i].startswith("-"):
                i += 2 if words[i] in ("-s", "-k", "--signal", "--kill-after") else 1
            i += 1  # duration
            continue
        if name == "watch":
            wr.add("watch")
            i += 1
            while i < n and words[i].startswith("-"):
                i += 2 if words[i] in ("-n", "--interval") else 1
            continue
        if name == "xargs":
            wr.add("xargs")
            i += 1
            while i < n and words[i].startswith("-"):
                o = words[i]
                i += 1
                if o in ("-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter"):
                    i += 1
            if i >= n:
                return ["echo"], wr
            continue
        if name in ("uv", "poetry", "pipenv", "pdm", "hatch", "rye", "bundle") and i + 1 < n and words[i + 1] in ("run", "exec"):
            i += 2
            while i < n and words[i].startswith("-"):
                i += 2 if words[i] in ("--with", "--python", "-p", "--env-file", "--package", "--extra", "--group",
                                        "--directory", "--project", "--from", "--with-requirements") else 1
            continue
        break
    return words[i:], wr


# ---------------------------------------------------------------------------- parsing
def _preprocess(text: str) -> tuple[str, list[tuple[str, bool]]]:
    decoded: list[tuple[str, bool]] = []

    def ansi(m: re.Match) -> str:
        val, hexy = _unescape(m.group(1))
        decoded.append((val, hexy))
        return shlex.quote(val)

    t = re.sub(r"\$'((?:[^'\\]|\\.)*)'", ansi, text)
    t = re.sub(r"\$\(\((?:[^()]|\([^()]*\))*\)\)", "0", t)
    t = re.sub(r"(^|[\s;&|(])\[\[(?=\s)", r"\1[", t)
    t = re.sub(r"(?<=\s)\]\](?=$|[\s;&|)])", "]", t)
    t = re.sub(r"<<-?\s*(['\"])(\w+)\1", r"<<\2", t)
    t = re.sub(r"(^|[;&|(]\s*)time\s+(?:-p\s+)?", r"\1", t)
    return t, decoded


# bashlex 0.18 loops forever on an unclosed `${` inside a quote that starts mid-word (e.g. -'${').
# Found by fuzzing; such text goes straight to the fallback tokenizer.
BASHLEX_HANG = re.compile(r"\$\{[^}']*(?:'|$)")


def _parse(text: str) -> tuple[list, bool]:
    try:
        if BASHLEX_HANG.search(text):
            raise ValueError("unsafe for bashlex")
        trees = bashlex.parse(text)
        script: list = []
        for t in trees:
            _walk(t, text, script)
        return script, True
    except Exception:
        try:
            return _fallback(text), False
        except Exception:
            return [[Cmd(words=text.split(), raw_words=text.split(), raw=text)]], False


def _walk(node, text: str, out: list) -> None:
    k = getattr(node, "kind", "")
    if k == "pipeline":
        pipe: list[Cmd] = []
        for p in node.parts:
            if p.kind == "command":
                pipe.append(_mk_cmd(p, text, out))
            elif p.kind != "pipe":
                sub: list = []
                _walk(p, text, sub)
                for pl in sub:
                    pipe.extend(pl)
        out.append(pipe)
    elif k == "command":
        out.append([_mk_cmd(node, text, out)])
    elif k == "list":
        for p in node.parts:
            if p.kind not in ("operator", "pipe"):
                _walk(p, text, out)
    elif k == "compound":
        start = len(out)
        for p in node.list:
            if p.kind not in ("reservedword", "operator"):
                _walk(p, text, out)
        reds = getattr(node, "redirects", None) or []
        if reds and len(out) > start:  # `{ ...; } > file` applies to every inner command
            extra = Cmd(words=[], raw=text[node.pos[0]:node.pos[1]])
            for r in reds:
                _add_redirect(extra, r, text, out)
            out.append([extra])
    elif k in ("if", "for", "while", "until", "function"):
        for p in node.parts:
            if p.kind in ("list", "command", "pipeline", "compound", "if", "for", "while", "until", "function"):
                _walk(p, text, out)
            elif p.kind == "word":
                for kind, inner in _subs_of(p, text):
                    out.extend(inner)


def _subs_of(node, text: str) -> list[tuple[str, list]]:
    res: list[tuple[str, list]] = []
    for p in getattr(node, "parts", None) or []:
        if p.kind == "commandsubstitution":
            inner: list = []
            _walk(p.command, text, inner)
            res.append(("$", inner))
        elif p.kind == "processsubstitution":
            inner = []
            _walk(p.command, text, inner)
            res.append((text[p.pos[0]: p.pos[0] + 1] + "(", inner))
        else:
            res += _subs_of(p, text)
    return res


def _add_redirect(c: Cmd, p, text: str, out: list) -> None:
    typ = p.type
    tgt = p.output
    if tgt is None or isinstance(tgt, int):
        target = str(tgt) if tgt is not None else ""
    else:
        target = tgt.word
        for kind, inner in _subs_of(tgt, text):
            c.subs.append((kind, -1, inner))
    if getattr(p, "heredoc", None) is not None:
        body = p.heredoc.value
        c.heredoc = body.rsplit("\n", 1)[0] if "\n" in body else ""
    if typ == "<<<":
        c.herestring = target
    c.redirects.append((typ, target))


def _mk_cmd(node, text: str, out: list) -> Cmd:
    c = Cmd(words=[], raw=text[node.pos[0]:node.pos[1]])
    for p in node.parts:
        if p.kind == "word":
            idx = len(c.words)
            c.words.append(p.word)
            c.raw_words.append(text[p.pos[0]:p.pos[1]])
            for kind, inner in _subs_of(p, text):
                c.subs.append((kind, idx, inner))
        elif p.kind == "assignment":
            name, _, val = p.word.partition("=")
            c.assigns.append((name, val))
            for kind, inner in _subs_of(p, text):
                c.subs.append((kind, -1, inner))
                c.assign_subs.setdefault(name, []).append(inner)
        elif p.kind == "redirect":
            _add_redirect(c, p, text, out)
    return c


def _match_paren(s: str, i: int) -> int:
    """s[i] == '('; return index of the matching ')' (or len-1)."""
    depth = 0
    q = None
    j = i
    while j < len(s):
        ch = s[j]
        if q:
            if ch == "\\" and q == '"':
                j += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "\\":
            j += 2
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(s) - 1


REDIR_OPS = {">", ">>", "<", "<<", "<<<", ">&", "&>", ">|", "<>", "&>>", "<&"}


def _fallback(text: str) -> list:
    """Tokenizer fallback for syntax bashlex cannot handle. Same IR, less precise."""
    subs: dict[str, tuple[str, list, str]] = {}
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if ch == "'":
            j = text.find("'", i + 1)
            j = n - 1 if j < 0 else j
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if (text.startswith("$(", i) and not text.startswith("$((", i)) or text.startswith("<(", i) or text.startswith(">(", i):
            j = _match_paren(text, i + 1)
            inner = text[i + 2:j]
            key = f"__TWSUB{len(subs)}__"
            subs[key] = ("$" if ch == "$" else ch + "(", _parse(inner)[0], text[i:j + 1])
            out.append(key)
            i = j + 1
            continue
        if ch == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            key = f"__TWSUB{len(subs)}__"
            subs[key] = ("$", _parse(text[i + 1:j])[0], text[i:j + 1])
            out.append(key)
            i = j + 1
            continue
        out.append(ch)
        i += 1
    s = "".join(out).replace("\n", " ; ")
    try:
        lex = shlex.shlex(s, posix=True, punctuation_chars=";&|<>()")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        tokens = [t.strip("'\"") for t in re.findall(r"[;&|<>()]+|[^\s;&|<>()]+", s)]

    script: list = []
    pipe: list[Cmd] = []
    cur = Cmd(words=[])

    def end_cmd() -> None:
        nonlocal cur
        if cur.words or cur.redirects or cur.assigns:
            cur.raw = " ".join(cur.words)
            pipe.append(cur)
        cur = Cmd(words=[])

    def end_pipe() -> None:
        nonlocal pipe
        end_cmd()
        if pipe:
            script.append(pipe)
        pipe = []

    k = 0
    while k < len(tokens):
        tok = tokens[k]
        if tok and all(c in ";&|<>()" for c in tok):
            if tok in REDIR_OPS:
                target = tokens[k + 1] if k + 1 < len(tokens) else ""
                if tok == "<<":
                    k += 2
                    continue
                cur.redirects.append((tok, target))
                if tok == "<<<":
                    cur.herestring = target
                k += 2
                continue
            if tok in ("|", "|&"):
                end_cmd()
            else:
                end_pipe()
            k += 1
            continue
        if not cur.words and re.match(r"^[A-Za-z_]\w*=", tok):
            name, _, val = tok.partition("=")
            cur.assigns.append((name, val))
        else:
            cur.words.append(tok)
            cur.raw_words.append(tok)
        k += 1
    end_pipe()

    for pl in script:
        for c in pl:
            for idx, w in enumerate(c.words):
                for key in re.findall(r"__TWSUB\d+__", w):
                    kind, inner, orig = subs[key]
                    c.subs.append((kind, idx, inner))
                    c.words[idx] = c.words[idx].replace(key, orig)
                    c.raw_words[idx] = c.words[idx]
            for name, val in list(c.assigns):
                for key in re.findall(r"__TWSUB\d+__", val):
                    kind, inner, orig = subs[key]
                    c.subs.append((kind, -1, inner))
                    c.assign_subs.setdefault(name, []).append(inner)
            new_r = []
            for op, tgt in c.redirects:
                for key in re.findall(r"__TWSUB\d+__", tgt):
                    kind, inner, orig = subs[key]
                    c.subs.append((kind, -1, inner))
                    tgt = tgt.replace(key, orig)
                new_r.append((op, tgt))
            c.redirects = new_r
            if c.herestring:
                c.herestring = next((t for o, t in c.redirects if o == "<<<"), c.herestring)
    return script


def _eval_pipe(cmds: list[Cmd]) -> tuple[str | None, bool]:
    """Statically evaluate `echo X | base64 -d | rev ...` style pipelines. Returns (text, used_a_decoder)."""
    val: str | None = None
    dec = False
    for c in cmds:
        words, _ = _unwrap(c.words)
        if not words:
            return None, dec
        n, a = _base(words[0]), words[1:]
        if c.herestring is not None:
            val = c.herestring
        elif c.heredoc is not None:
            val = c.heredoc
        flags = "".join(x[1:] for x in a if x.startswith("-") and not x.startswith("--"))
        longs = {x for x in a if x.startswith("--")}
        if n == "echo":
            parts = [x for x in a if not re.fullmatch(r"-[neE]+", x)]
            val = " ".join(parts)
            if "e" in flags:
                val = _unescape(val)[0]
            continue
        if n == "printf":
            if not a:
                return None, dec
            fmt = a[0]
            if fmt in ("%s", "%b") and len(a) > 1:
                val = " ".join(a[1:])
                if fmt == "%b":
                    val = _unescape(val)[0]
            else:
                val, hexy = _unescape(fmt)
                dec = dec or hexy
            continue
        if val is None:
            return None, dec
        if n == "cat" and not [x for x in a if not x.startswith("-")]:
            continue
        if n in ("base64", "gbase64", "basenc") and ("d" in flags or "D" in flags or "--decode" in longs):
            val = _b64(val)
            dec = True
        elif n == "openssl" and ("base64" in a or "enc" in a) and "-d" in a:
            val = _b64(val)
            dec = True
        elif n == "xxd" and "r" in flags:
            try:
                val = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", val)).decode("latin-1")
            except (binascii.Error, ValueError):
                return None, True
            dec = True
        elif n == "rev":
            val = "\n".join(line[::-1] for line in val.split("\n"))
            dec = True
        elif n == "tr" and len(a) >= 2 and "n-z" in a[1].lower():
            val = codecs.decode(val, "rot13")
            dec = True
        elif n in ("gunzip", "zcat") or (n == "gzip" and "d" in flags):
            try:
                val = gzip.decompress(val.encode("latin-1")).decode("latin-1")
            except Exception:
                return None, True
            dec = True
        else:
            return None, dec
        if val is None:
            return None, dec
    if val is not None:
        val = _to_text(val)
    return val, dec


# ---------------------------------------------------------------------------- analyzer
class _Analyzer:
    def __init__(self, s: Session) -> None:
        self.s = s
        self.cwd = s.cwd
        self.env: dict[str, str] = {}
        self.var_traits: dict[str, set[str]] = {}
        self.found: dict[tuple[str, str | None], Finding] = {}
        self.hex_literals: set[str] = set()
        self.tainted_files: set[str] = set()  # files that now hold copies of secrets
        self.task = (s.task or "").lower()

    # ---- bookkeeping ----
    def add(self, rule: str, sev: int, cat: str, msg: str, ev: str | None = None) -> None:
        msg = " ".join(str(msg).split())
        if len(msg) > 220:
            msg = msg[:219] + "…"
        ev = _clip(ev)
        key = (rule, ev)
        old = self.found.get(key)
        if old is None or old.severity < sev:
            self.found[key] = Finding(rule=rule, severity=max(0, min(sev, 100)), category=cat, message=msg, evidence=ev)

    def result(self) -> list[Finding]:
        return sorted(self.found.values(), key=lambda f: -f.severity)[:25]

    def mentioned(self, x: str | None) -> bool:
        if not x or not self.task:
            return False
        x = x.lower()
        return x in self.task or (_host(x) or "\0") in self.task

    def rce_sev(self, hosts: list[str | None]) -> int:
        hs = [h for h in hosts if h]
        if hs and all(self.mentioned(h) for h in hs):
            return MEDIUM + 10
        return CRITICAL

    def expand_path(self, p: str) -> str:
        p = re.sub(r"\$\{?PWD\}?", self.cwd or ".", p)
        return paths.expand(p, self.cwd)

    def in_ws(self, full: str) -> bool:
        return self.s.in_workspace(full)

    # ---- text level ----
    def text(self, cmd: str, depth: int, quiet: bool = False) -> set[str]:
        if not cmd or not cmd.strip():
            return set()
        if depth > MAX_DEPTH:
            self.add("shell.too_deep", HIGH, "obfuscation",
                     "Hides commands inside commands so many layers deep that they cannot be checked.", cmd)
            return set()
        cmd = cmd[:MAX_LEN]
        self.raw_checks(cmd, depth)
        pre, decoded = _preprocess(cmd)
        for val, hexy in decoded:
            if hexy and re.fullmatch(r"[\w\s./~:@=+-]+", val or "") and re.search(r"[A-Za-z]", val):
                self.hex_literals.add(val)
                self.add("shell.hex_escape", MEDIUM, "obfuscation",
                         f"Hides text using hex or octal codes (it really says '{_clip(val, 60)}').", val)
        script, ok = _parse(pre)
        if not ok and not quiet:
            sev = MEDIUM if SUSPICIOUS.search(cmd) else LOW
            self.add("shell.unparseable", sev, "obfuscation",
                     "Uses shell syntax that could not be fully checked, so it was checked more roughly.", cmd)
        return self.script(script, depth)

    def raw_checks(self, cmd: str, depth: int) -> None:
        if INVISIBLE.search(cmd):
            self.add("shell.invisible_chars", HIGH, "obfuscation",
                     "Contains invisible characters that can hide what the command really does.", repr(cmd[:80]))
            self.text(INVISIBLE.sub("", cmd), depth + 1)
        if any(ord(ch) > 127 for ch in cmd):
            self.homoglyphs(cmd, depth)
        if re.search(r"\$\{?IFS\b", cmd):
            self.add("shell.ifs_trick", HIGH, "obfuscation",
                     "Uses a shell trick ($IFS) to hide the spaces in a command.", cmd)
            self.text(re.sub(r"\$\{IFS(?:[^}]*)\}|\$IFS\b", " ", cmd), depth + 1)
        m = FORK_BOMB.search(cmd)
        if m:
            self.add("shell.fork_bomb", CRITICAL, "destructive",
                     "Freezes your computer by copying itself over and over (a fork bomb).", m.group(0))
        m = DEV_TCP.search(cmd)
        if m:
            if REV_SHELL_HINT.search(cmd):
                self.add("shell.reverse_shell", CRITICAL, "network",
                         "Gives someone on the internet remote control of this computer (reverse shell).", cmd)
            else:
                self.add("shell.dev_tcp", HIGH, "network",
                         "Opens a hidden raw network connection straight from the shell.", m.group(0))
        if re.search(r"\bmkfifo\b", cmd) and re.search(r"\b(nc|ncat|netcat|telnet|openssl\s+s_client)\b", cmd):
            self.add("shell.reverse_shell", CRITICAL, "network",
                     "Gives someone on the internet remote control of this computer (reverse shell).", cmd)
        if re.search(r"\bNOPASSWD\b", cmd):
            self.add("shell.sudoers", CRITICAL, "privilege",
                     "Gives a user permanent administrator power without a password.", cmd)
        m = GUARD_RE.search(cmd)
        if m:
            self.add("shell.guard_tamper", CRITICAL, "scope",
                     "Tries to change or read Tripwire's own settings, the guard watching this agent.", cmd)
        m = KILL_GUARD_RE.search(cmd)
        if m:
            self.add("shell.guard_tamper", CRITICAL, "scope",
                     "Tries to switch off Tripwire, the guard watching this agent.", m.group(0))
        if re.search(r"\bTRIPWIRE_\w+=", cmd):
            self.add("shell.guard_env", HIGH, "scope", "Changes Tripwire's settings through an environment variable.", cmd)
        if "--dangerously-skip-permissions" in cmd:
            self.add("shell.skip_permissions", HIGH, "privilege",
                     "Starts an AI agent with all of its safety prompts turned off.", cmd)
        m = HIST_RE.search(cmd)
        if m:
            self.add("shell.hide_tracks", MEDIUM, "obfuscation",
                     "Erases or turns off your command history, hiding what was run.", m.group(0))
        m = SEC_OFF_RE.search(cmd)
        if m:
            self.add("shell.disable_security", HIGH, "privilege",
                     "Turns off a built-in security protection on this computer.", m.group(0))
        m = DB_WIPE_RE.search(cmd)
        if m:
            self.add("shell.db_wipe", HIGH, "destructive", "Wipes a database and all of its data.", m.group(0))

    def homoglyphs(self, cmd: str, depth: int) -> None:
        hit = None
        for m in re.finditer(r"\S+", cmd):
            tok = m.group(0)
            weird = [ch for ch in tok if ord(ch) > 127 and (
                unicodedata.name(ch, "").startswith(("CYRILLIC", "GREEK", "FULLWIDTH", "MATHEMATICAL", "CHEROKEE",
                                                      "ARMENIAN", "LATIN SMALL LETTER DOTLESS", "LATIN SMALL LETTER SCRIPT"))
                or ch in CONFUSABLE_KEYS)]
            if not weird:
                continue
            ascii_letters = any("a" <= ch.lower() <= "z" for ch in tok)
            fullwidth = any(unicodedata.name(ch, "").startswith("FULLWIDTH") for ch in tok)
            if ascii_letters or fullwidth:
                first = m.start() == 0 or bool(re.search(r"[|;&(`]\s*$|\$\(\s*$", cmd[:m.start()]))
                sev = HIGH if first or "://" in tok or "." in tok else MEDIUM
                hit = (sev, tok)
                self.add("shell.homoglyph", sev, "obfuscation",
                         f"Uses look-alike letters from another alphabet to disguise '{_clip(tok, 50)}'.", tok)
        if hit:
            clean = unicodedata.normalize("NFKC", cmd.translate(CONFUSABLE))
            if clean != cmd:
                self.text(clean, depth + 1, quiet=True)

    # ---- script / pipeline ----
    def script(self, script: list, depth: int) -> set[str]:
        traits: set[str] = set()
        downloads: dict[str, str | None] = {}
        for pipe in script:
            infos = [self.cmd(c, depth) for c in pipe]
            self.pipeline(infos, depth)
            for inf in infos:
                traits |= inf.traits
                if inf.host:
                    traits.add("host=" + inf.host)
                self.sequence(inf, downloads)
        return traits

    def pipeline(self, infos: list[Info], depth: int) -> None:
        if not infos:
            return
        names = [i.name for i in infos]
        if len(infos) > 1 and any(n in SHELLS for n in names) and any(n in RAW_SOCKET for n in names):
            self.add("shell.reverse_shell", CRITICAL, "network",
                     "Gives someone on the internet remote control of this computer (reverse shell).",
                     " | ".join(i.c.raw for i in infos))
        if any(n in SQL_CLIENTS for n in names):
            blob = " ".join(i.c.raw + " " + (i.c.heredoc or "") + " " + (i.c.herestring or "") for i in infos)
            self.sql(blob)
        for j, inf in enumerate(infos):
            up: set[str] = set().union(*(i.traits for i in infos[:j])) if j else set()
            up_hosts = [t[5:] for t in up if t.startswith("host=")]
            ev = " | ".join(i.c.raw for i in infos[: j + 1])
            if "shell_in" in inf.traits and j > 0:
                payload, used_dec = _eval_pipe([i.c for i in infos[:j]])
                if "download_stdout" in up:
                    self.add("shell.pipe_to_shell", self.rce_sev(up_hosts), "exfiltration" if False else "network",
                             f"Downloads a script from {up_hosts[0] if up_hosts else 'the internet'} and runs it "
                             "right away, without anyone seeing what's inside.", ev)
                elif used_dec or "decode" in up:
                    hint = f": {_clip(payload, 70)}" if payload and _printable(payload) else "."
                    self.add("shell.decode_to_shell", HIGH, "obfuscation",
                             f"Decodes hidden text and runs it as a command{hint}", ev)
                if payload and _printable(payload):
                    self.text(payload, depth + 1)
            if j > 0 and (inf.name in NET_TOOLS or "net" in inf.traits):
                host = inf.host or "another computer"
                if "secret_read" in up:
                    self.add("shell.exfil_secret", CRITICAL, "exfiltration",
                             f"Sends your secret files or keys to {host}.", ev)
                elif "env_dump" in up:
                    self.add("shell.exfil_env", CRITICAL, "exfiltration",
                             f"Sends your environment variables, which hold passwords and keys, to {host}.", ev)
                elif "file_read" in up and inf.stdin_send and not (inf.host and LOCAL_HOST.match(inf.host)):
                    sev = LOW if self.mentioned(inf.host) else MEDIUM
                    self.add("shell.upload_file", sev, "exfiltration", f"Sends the contents of a local file to {host}.", ev)
            if j > 0 and "sudo_stdin" in inf.wrappers:
                self.add("shell.sudo_password", HIGH, "privilege", "Types a password into sudo automatically.", ev)
            if j > 0 and inf.name in ("rm", "shred", "unlink", "srm") and "xargs" in inf.wrappers:
                for up_inf in infos[:j]:
                    for r in up_inf.find_roots:
                        self.find_delete(r, up_inf.find_filtered, ev)

    def sequence(self, inf: Info, downloads: dict[str, str | None]) -> None:
        def norm(p: str) -> str:
            return os.path.normpath(self.expand_path(p))

        cands: list[str] = []
        if inf.exec_path and ("/" in inf.exec_path or norm(inf.exec_path) in downloads):
            cands.append(inf.exec_path)
        if inf.name in SHELLS | INTERPS | {"source", ".", "chmod"}:
            pos = [a for a in inf.args if not a.startswith("-") and not a.startswith("+")]
            if inf.name == "chmod":
                mode = next((a for a in inf.args if not a.startswith("-") or re.fullmatch(r"-[rwxXst]+", a)), "")
                if "x" in mode or re.fullmatch(r"[0-7]*[1357][0-7]{0,2}", mode or "z"):
                    for t in pos[1:]:
                        if norm(t) in downloads:
                            self.add("shell.download_chmod", MEDIUM, "network",
                                     f"Makes a file downloaded from the internet runnable: {t}", inf.c.raw)
            elif pos:
                cands.append(pos[0])
        for e in cands:
            if norm(e) in downloads:
                self.add("shell.download_exec", self.rce_sev([downloads[norm(e)]]), "network",
                         f"Downloads a program from {downloads[norm(e)] or 'the internet'} and runs it.", inf.c.raw)
        for out in inf.outputs:
            downloads[norm(out)] = inf.host

    # ---- command level ----
    def expand(self, w: str) -> str:
        if "$" not in w or not self.env:
            return w

        def rep(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            return self.env.get(name, m.group(0))

        return re.sub(r"\$\{(\w+)\}|\$(\w+)", rep, w)

    def cmd(self, c: Cmd, depth: int) -> Info:
        inf = Info(c=c)
        sub_info: list[tuple[str, int, list, set[str]]] = []
        for kind, idx, inner in c.subs:
            sub_info.append((kind, idx, inner, self.script(inner, depth + 1)))
        for name, val in c.assigns:
            self.assign(name, val, c)
        words = [self.expand(w) for w in c.words]
        for _, _, _, t in sub_info:
            inf.traits |= t & {"secret_read", "env_dump", "download_stdout", "decode"}
            inf.traits |= {x for x in t if x.startswith("host=")}
        for w in c.words:  # "$x" where x holds downloaded/secret content
            for v in re.findall(r"\$\{?(\w+)", w):
                inf.traits |= self.var_traits.get(v, set())
        if not words:
            self.redirects(inf, depth)
            return inf
        w0raw = c.raw_words[0] if c.raw_words else c.words[0]

        # --- tricks that hide the command name ---
        sub0 = [(inner, t) for kind, idx, inner, t in sub_info if idx == 0]
        if sub0:
            inner, t = sub0[0]
            val = _eval_pipe(inner[0])[0] if len(inner) == 1 else None
            if val and val.strip():
                try:
                    new = shlex.split(val)
                except ValueError:
                    new = val.split()
                words = new + words[1:]
                self.add("shell.dynamic_command", HIGH, "obfuscation",
                         f"Works out the command name at run time to hide it (it really runs '{_clip(val, 50)}').", w0raw)
            else:
                self.add("shell.dynamic_command", HIGH if "decode" in t else MEDIUM, "obfuscation",
                         "Runs a command whose name is worked out at run time, so it can't be checked in advance.", w0raw)
        elif "$" in w0raw and not w0raw.startswith("$'"):
            if words[0] != c.words[0] and "$" not in words[0]:
                nm = _base(words[0].split()[0]) if words[0].split() else ""
                self.add("shell.var_command", HIGH if nm in DANGEROUS_NAMES else MEDIUM, "obfuscation",
                         f"Builds the command '{nm}' out of variables to hide it.", w0raw)
                try:
                    words = shlex.split(words[0]) + words[1:]
                except ValueError:
                    pass
            elif "$" in words[0]:
                self.add("shell.dynamic_command", LOW, "obfuscation", "Runs a program whose name is stored in a variable.", w0raw)
        stripped = w0raw.lstrip("\\")
        if (stripped != c.words[0] and re.fullmatch(r"[\w.+-]+", c.words[0]) and re.search(r"['\"\\]", stripped)
                and not w0raw.startswith("$'")):
            nm = _base(c.words[0])
            self.add("shell.quote_split", HIGH if nm in DANGEROUS_NAMES else MEDIUM, "obfuscation",
                     f"Hides the command '{nm}' by splitting its name with quotes or backslashes.", w0raw)
        if words[0] in self.hex_literals:
            self.add("shell.hex_escape", HIGH, "obfuscation",
                     f"Hides the command '{_clip(words[0], 40)}' using hex or octal codes.", w0raw)
        m = re.fullmatch(r"\{([^{}]*,[^{}]*)\}", words[0])
        if m:
            parts = [p for p in m.group(1).split(",") if p != ""]
            nm = _base(parts[0]) if parts else ""
            self.add("shell.brace_trick", HIGH if nm in DANGEROUS_NAMES else MEDIUM, "obfuscation",
                     f"Uses a brace trick to hide the command '{nm}' and its spaces.", w0raw)
            words = parts + words[1:]
        if words and words[0] not in ("[", "[[") and re.search(r"[?*\[]", words[0]) and "/" in words[0]:
            try:
                hits = sorted(glob.glob(words[0]))[:3]
            except Exception:
                hits = []
            self.add("shell.glob_command", HIGH, "obfuscation",
                     f"Uses wildcards to hide which program it runs ({_clip(words[0], 40)}).", w0raw)
            if hits:
                words = [hits[0]] + words[1:]
        if not words:
            return inf

        rest, wrappers = _unwrap(words)
        inf.wrappers = wrappers
        if "watch" in wrappers and rest:
            self.text(" ".join(rest), depth + 1)
            return inf
        if not rest:
            if "sudo" in wrappers:
                self.add("shell.root_shell", HIGH, "privilege", "Opens a full administrator (root) shell.", c.raw)
            self.redirects(inf, depth)
            return inf
        inf.exec_path = rest[0]
        inf.name = _base(rest[0])
        inf.args = rest[1:]

        if inf.name in ("export", "declare", "local", "readonly", "typeset"):
            for idx, w in enumerate(c.words):
                m = re.match(r"^([A-Za-z_]\w*)=(.*)$", w, re.S)
                if not m:
                    continue
                if "$(" not in m.group(2) and "`" not in m.group(2):
                    self.env[m.group(1)] = m.group(2)
                t = set().union(*[t for _, i2, _, t in sub_info if i2 == idx] or [set()])
                if t:
                    self.var_traits[m.group(1)] = t
        before = set(self.found)
        self.rules(inf, depth, sub_info)
        self.redirects(inf, depth)
        if "sudo" in wrappers:
            new = [self.found[k] for k in self.found if k not in before or (
                k[1] and (k[1].rstrip("…") in _clip(c.raw) or _clip(c.raw).rstrip("…") in k[1]))]
            bad = [f for f in new if not f.rule.startswith("shell.sudo") and f.category in ("destructive", "persistence", "scope", "privilege")
                   and f.severity >= MEDIUM]
            if bad:
                top = max(bad, key=lambda f: f.severity)
                self.add("shell.sudo_destructive", CRITICAL, "privilege",
                         f"Uses administrator power to do something dangerous: {top.message}", c.raw)
            elif "sudo_shell" in wrappers or inf.name in SHELLS and not inf.args:
                self.add("shell.root_shell", HIGH, "privilege", "Opens a full administrator (root) shell.", c.raw)
            else:
                self.add("shell.sudo", MEDIUM, "privilege",
                         f"Runs '{inf.name}' with administrator (root) power.", c.raw)
        return inf

    def assign(self, name: str, val: str, c: Cmd) -> None:
        if name.upper() in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH") and name.upper() != "LD_LIBRARY_PATH":
            self.add("shell.preload", HIGH, "privilege", "Injects a hidden library into every program that runs next.", c.raw)
        if name == "PROMPT_COMMAND":
            self.add("shell.prompt_command", MEDIUM, "persistence",
                     "Sets a command to run silently every time the shell shows a prompt.", c.raw)
        if "$(" not in val and "`" not in val:
            self.env[name] = self.expand(val)
        for inner in c.assign_subs.get(name, []):
            t = self.script_traits(inner)
            if t:
                self.var_traits[name] = t

    def script_traits(self, script: list) -> set[str]:
        t: set[str] = set()
        for pipe in script:
            for c in pipe:
                words, _ = _unwrap(c.words)
                if not words:
                    continue
                n = _base(words[0])
                if n in DOWNLOADERS:
                    t.add("download_stdout")
                    h = _host(_first_url(words[1:]))
                    if h:
                        t.add("host=" + h)
                if n in ("base64", "xxd", "openssl") and any(x in ("-d", "-D", "--decode", "-r") for x in words):
                    t.add("decode")
                if n in READERS and any(paths.is_secret(self.expand_path(a)) for a in words[1:] if not a.startswith("-")):
                    t.add("secret_read")
                if n in ("env", "printenv") and len(words) == 1:
                    t.add("env_dump")
        return t

    def redirects(self, inf: Info, depth: int) -> None:
        c = inf.c
        for op, tgt in c.redirects:
            if op in (">", ">>", ">|", "&>", "&>>", ">&"):
                if not tgt or tgt.isdigit() or tgt == "-":
                    continue
                self.write(tgt, c.raw)
                if "secret_read" in inf.traits:
                    self.tainted_files.add(os.path.normpath(self.expand_path(tgt)))
                if inf.name in DOWNLOADERS:
                    inf.outputs.append(tgt)
            elif op in ("<", "<>"):
                if tgt.startswith("/dev/"):
                    continue
                full = self.expand_path(tgt)
                if paths.is_secret(full):
                    self.add("shell.secret_read", MEDIUM + 5, "secrets", f"Reads your credential file {tgt}.", c.raw)
                    inf.traits.add("secret_read")
                else:
                    inf.traits.add("file_read")
        is_shell_reader = inf.name in SHELLS and not self._shell_payload(inf.args)[0] and not self._has_file_arg(inf)
        if is_shell_reader or inf.name in ("eval", "source", "."):
            body = c.heredoc if c.heredoc is not None else (c.herestring if c.herestring is not None else None)
            if body:
                self.text(body, depth + 1)
        elif inf.name in INTERPS and (c.heredoc or c.herestring) and not self._has_file_arg(inf):
            self.code(inf.name, c.heredoc or c.herestring or "", inf, depth)

    def _has_file_arg(self, inf: Info) -> bool:
        a = inf.args
        i = 0
        while i < len(a):
            x = a[i]
            if x in ("--",):
                return i + 1 < len(a)
            if x in ("-", "/dev/stdin"):
                return False
            if x.startswith("-"):
                if x in ("-o", "-O", "+O", "--rcfile", "--init-file"):
                    i += 2
                    continue
                if inf.name == "python" and x in ("-m", "-c"):
                    return True
                if inf.name in ("node", "nodejs", "bun", "deno") and x in ("-e", "--eval", "-p", "--print", "-r", "--require"):
                    return True
                i += 1
                continue
            return True
        return False

    def _shell_payload(self, args: list[str]) -> tuple[str | None, int]:
        for i, a in enumerate(args):
            if a == "--":
                return None, -1
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                j = i + 1
                while j < len(args) and args[j].startswith("-") and args[j] != "-":
                    j += 2 if args[j] == "-o" else 1
                return (args[j], j) if j < len(args) else (None, -1)
            if a in ("-o", "+o"):
                continue
            if not a.startswith(("-", "+")) and (i == 0 or args[i - 1] not in ("-o", "+o")):
                return None, -1
        return None, -1

    def _code_payload(self, name: str, args: list[str]) -> tuple[str | None, bool]:
        flags = {
            "python": ("-c",), "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval", "-p", "--print"),
            "bun": ("-e", "--eval"), "perl": ("-e", "-E"), "ruby": ("-e",), "php": ("-r",), "lua": ("-e",),
            "osascript": ("-e",), "deno": ("eval",),
            "pwsh": ("-c", "-command", "-encodedcommand", "-enc", "-e", "-ec"),
            "powershell": ("-c", "-command", "-encodedcommand", "-enc", "-e", "-ec"),
        }.get(name, ())
        if name == "osascript":
            parts = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-e"]
            return ("\n".join(parts) if parts else None), False
        for i, a in enumerate(args):
            al = a.lower()
            if al in flags:
                payload = args[i + 1] if i + 1 < len(args) else None
                if name in ("pwsh", "powershell"):
                    payload = " ".join(args[i + 1:]) or None
                return payload, name in ("pwsh", "powershell") and al in ("-enc", "-encodedcommand", "-e", "-ec")
            if name == "python" and a.startswith("-c") and len(a) > 2:
                return a[2:], False
            if name == "perl" and re.fullmatch(r"-[a-zA-Z]*[eE]", a):
                return (args[i + 1] if i + 1 < len(args) else None), False
            if name == "python" and a == "-m":
                return None, False
            if not a.startswith("-"):
                return None, False
        return None, False

    # ---- rules ----
    def rules(self, inf: Info, depth: int, sub_info: list) -> None:
        n, a, c = inf.name, inf.args, inf.c
        raw = c.raw

        # executors: sh -c, eval, source, interpreters
        if n in SHELLS:
            inf.traits.add("executor")
            payload, _ = self._shell_payload(a)
            if payload is not None:
                inf.traits |= self.var_payload_traits(payload)
                self.text(payload, depth + 1)
            elif not self._has_file_arg(inf):
                inf.traits.add("shell_in")
        elif n in INTERPS:
            inf.traits.add("executor")
            payload, encoded = self._code_payload(n, a)
            if payload is not None:
                if encoded:
                    try:
                        payload = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-16-le", "replace")
                        self.add("shell.encoded_command", HIGH, "obfuscation",
                                 f"Runs a PowerShell command hidden with base64: {_clip(payload, 60)}", raw)
                    except Exception:
                        self.add("shell.encoded_command", HIGH, "obfuscation",
                                 "Runs a PowerShell command hidden with base64.", raw)
                self.code(n, payload, inf, depth)
            elif n == "python" and a[:1] == ["-m"] and len(a) > 1:
                if a[1] in ("pip", "pip3"):
                    self.install("pip", a[2:], raw)
                elif a[1] in ("http.server", "SimpleHTTPServer"):
                    self.add("shell.serve_files", LOW, "network",
                             "Shares the files in this folder with other computers on the network.", raw)
            elif not self._has_file_arg(inf) and n != "osascript":
                inf.traits.add("shell_in")
        elif n == "eval":
            inf.traits.add("executor")
            payload = " ".join(a)
            if any(re.search(r"\$\{?\w", rw) for rw in c.raw_words[1:]) and "$" in payload:
                self.add("shell.eval_variable", MEDIUM, "obfuscation",
                         "Runs a command hidden inside a variable, so it can't be checked first.", raw)
            self.text(payload, depth + 1)
        elif n in ("source", "."):
            inf.traits.add("executor")
            if a and a[0] in ("/dev/stdin", "-", "/dev/fd/0"):
                inf.traits.add("shell_in")
        if "executor" in inf.traits:
            dl = "download_stdout" in inf.traits
            hosts = [t[5:] for t in inf.traits if t.startswith("host=")]
            if dl:
                self.add("shell.pipe_to_shell", self.rce_sev(hosts), "network",
                         f"Downloads code from {hosts[0] if hosts else 'the internet'} and runs it right away, "
                         "without anyone seeing what's inside.", raw)
            elif "decode" in inf.traits:
                val = None
                for _, _, inner, t in sub_info:
                    if "decode" in t and len(inner) == 1:
                        val = _eval_pipe(inner[0])[0]
                hint = f": {_clip(val, 70)}" if val and _printable(val) else "."
                self.add("shell.decode_to_shell", HIGH, "obfuscation", f"Decodes hidden text and runs it as a command{hint}", raw)
                if val and _printable(val):
                    self.text(val, depth + 1)

        if n in ("rm", "unlink", "srm", "rmdir"):
            self.rm(inf)
        elif n == "find":
            self.find(inf, depth)
        elif n == "dd":
            for x in a:
                if x.startswith("of="):
                    tgt = x[3:]
                    if re.match(r"/dev/(r?disk|sd|hd|nvme|mmcblk|xvd|vd)", tgt):
                        self.add("shell.disk_overwrite", CRITICAL, "destructive",
                                 f"Overwrites a whole disk ({tgt}), wiping everything on it.", raw)
                    else:
                        self.write(tgt, raw)
                if x.startswith("if=") and paths.is_secret(self.expand_path(x[3:])):
                    self.add("shell.secret_read", MEDIUM + 5, "secrets", f"Reads your credential file {x[3:]}.", raw)
                    inf.traits.add("secret_read")
        elif n.startswith(("mkfs", "newfs", "mke2fs")) or n in ("wipefs", "fdisk", "sfdisk", "parted", "gdisk", "sgdisk"):
            self.add("shell.format_disk", CRITICAL, "destructive", "Erases and reformats a whole disk.", raw)
        elif n == "diskutil" and a and a[0].lower() in ("erasedisk", "erasevolume", "zerodisk", "randomdisk",
                                                         "secureerase", "partitiondisk", "reformat", "apfs"):
            if a[0].lower() != "apfs" or any(x.lower().startswith("delete") or x.lower().startswith("erase") for x in a[1:]):
                self.add("shell.format_disk", CRITICAL, "destructive", "Erases a whole disk.", raw)
        elif n in ("shred", "wipe"):
            targets = [x for x in a if not x.startswith("-")]
            for t in targets:
                full = self.expand_path(t)
                sev = MEDIUM if self.s.cwd and self.in_ws(full) else HIGH
                self.add("shell.shred", sev, "destructive",
                         f"Permanently destroys {t} so it can never be recovered.", raw)
        elif n == "truncate":
            for t in [x for x in a if not x.startswith("-") and not re.fullmatch(r"[\d+<>%/-]+[KMGkmg]?", x)]:
                self.write(t, raw)
        elif n in ("chmod", "chown", "chgrp"):
            self.chmod(inf)
        elif n == "mv":
            self.mv_cp(inf, move=True)
        elif n in ("cp", "install", "ln", "rsync") and not (n == "rsync" and self._remote_dest(a)):
            self.mv_cp(inf, move=False)
        elif n == "tee":
            for t in [x for x in a if not x.startswith("-")]:
                self.write(t, raw)
        elif n in ("sed", "perl") and any(x.startswith("-i") or re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", x) for x in a):
            pos = [x for x in a if not x.startswith("-")]
            for t in pos[1:]:
                if t not in ("''", ""):
                    self.write(t, raw)
        elif n == "git":
            self.git(inf)
        elif n == "kubectl" or n == "oc":
            if "delete" in a:
                broad = any(x in ("--all", "-A", "--all-namespaces", "namespace", "namespaces", "ns", "node", "nodes",
                                  "pv", "crd") for x in a)
                self.add("shell.kubectl_delete", HIGH if broad else MEDIUM, "destructive",
                         "Deletes resources from a live Kubernetes cluster." if not broad else
                         "Deletes a large part of a live Kubernetes cluster.", raw)
        elif n == "helm" and a[:1] and a[0] in ("uninstall", "delete", "del"):
            self.add("shell.helm_uninstall", MEDIUM, "destructive", "Removes an app from a live Kubernetes cluster.", raw)
        elif n in ("terraform", "tofu", "terragrunt", "pulumi", "cdk") and ("destroy" in a or "-destroy" in a):
            self.add("shell.infra_destroy", HIGH, "destructive", "Destroys all the cloud infrastructure this project manages.", raw)
        elif n in ("serverless", "sls") and a[:1] == ["remove"]:
            self.add("shell.infra_destroy", HIGH, "destructive", "Deletes the deployed cloud app.", raw)
        elif n in ("docker", "podman", "docker-compose"):
            self.docker(inf)
        elif n == "aws":
            self.aws(inf)
        elif n in ("gcloud", "az") and ("delete" in a):
            big = "projects" in a or "group" in a
            self.add("shell.cloud_delete", HIGH if big else MEDIUM, "destructive", "Deletes resources from your cloud account.", raw)
        elif n == "gsutil" and a[:1] in (["rm"], ["rb"]):
            self.add("shell.cloud_delete", HIGH if "-r" in a or a[0] == "rb" else MEDIUM, "destructive",
                     "Deletes files from cloud storage.", raw)
        elif n == "gh":
            if a[:2] == ["repo", "delete"]:
                self.add("shell.gh_repo_delete", HIGH, "destructive", "Deletes a whole GitHub repository.", raw)
            elif a[:2] == ["repo", "edit"] and any("public" in x for x in a):
                self.add("shell.gh_public", MEDIUM, "exfiltration", "Makes a GitHub repository public for anyone to see.", raw)
        elif n == "dropdb":
            self.add("shell.db_wipe", HIGH, "destructive", "Deletes a whole database.", raw)

        if n in ("cd", "pushd"):
            tgt = next((x for x in a if not x.startswith("-")), "~")
            if "$" in tgt and not tgt.startswith(("$HOME", "${HOME}")):
                self.cwd = None
            else:
                self.cwd = os.path.normpath(self.expand_path(tgt))

        # privilege
        if n == "su":
            if "-c" in a:
                i = a.index("-c")
                if i + 1 < len(a):
                    self.text(a[i + 1], depth + 1)
                self.add("shell.su", MEDIUM, "privilege", "Runs a command as a different user.", raw)
            else:
                self.add("shell.root_shell", HIGH, "privilege", "Switches to another user, usually the administrator.", raw)
        elif n == "visudo":
            self.add("shell.sudoers", HIGH, "privilege", "Edits who gets administrator power on this computer.", raw)
        elif n in ("usermod", "gpasswd", "dseditgroup", "dscl", "adduser", "useradd", "sysadminctl", "passwd", "chpasswd"):
            j = " ".join(a)
            if re.search(r"\b(sudo|wheel|admin|root|docker)\b", j) and (n != "dscl" or "append" in j.lower() or "create" in j.lower()):
                self.add("shell.add_admin", HIGH, "privilege", "Gives a user administrator power.", raw)
            else:
                self.add("shell.user_change", MEDIUM, "privilege", "Creates or changes a user account or password.", raw)
        elif n == "setcap":
            self.add("shell.setcap", HIGH, "privilege", "Gives a program special system powers.", raw)

        # persistence
        if n == "crontab":
            if "-r" in a:
                self.add("shell.crontab_remove", MEDIUM, "destructive", "Deletes all your scheduled tasks.", raw)
            elif a != ["-l"] and not (a and a[0] == "-l" and len(a) == 1):
                self.add("shell.crontab", HIGH, "persistence",
                         "Schedules a command to run automatically in the background.", raw)
        elif n == "launchctl" and a:
            if a[0] in ("load", "bootstrap", "submit", "enable", "kickstart"):
                self.add("shell.launchd", HIGH, "persistence", "Sets up a program to start automatically on your Mac.", raw)
            elif a[0] in ("unload", "bootout", "remove", "disable"):
                self.add("shell.launchd_stop", MEDIUM, "persistence", "Stops a background service on your Mac.", raw)
        elif n == "systemctl" and a:
            verb = next((x for x in a if not x.startswith("-")), "")
            if verb in ("enable", "link", "edit", "set-default", "preset", "reenable"):
                self.add("shell.systemd", HIGH, "persistence", "Sets up a service to start automatically on boot.", raw)
            elif verb in ("disable", "mask", "stop", "kill"):
                self.add("shell.systemd_stop", MEDIUM, "persistence", "Turns off a system service.", raw)
        elif n in ("update-rc.d", "chkconfig", "rc-update"):
            self.add("shell.systemd", HIGH, "persistence", "Sets up a service to start automatically on boot.", raw)
        elif n in ("at", "batch") and a[:1] != ["-l"]:
            self.add("shell.at_job", MEDIUM, "persistence", "Schedules a command to run later in the background.", raw)
        elif n == "defaults" and a[:1] == ["write"] and re.search(r"loginitems|loginwindow|LoginHook|LogoutHook",
                                                                  " ".join(a), re.I):
            self.add("shell.login_item", HIGH, "persistence", "Sets a program to run every time you log in.", raw)
        elif n == "xattr" and "com.apple.quarantine" in a and any(x.startswith("-d") or x == "-c" or "d" in x[1:] for x in a if x.startswith("-")):
            self.add("shell.unquarantine", MEDIUM, "privilege",
                     "Removes macOS's safety check on a downloaded file so it can run without warning.", raw)
        elif n == "security" and a:
            if a[0] in ("find-generic-password", "find-internet-password") and any(x in ("-w", "-g") for x in a) \
                    or a[0] in ("dump-keychain", "export", "find-certificate") and a[0] != "find-certificate":
                self.add("shell.keychain", HIGH, "secrets", "Reads saved passwords out of your keychain.", raw)
                inf.traits.add("secret_read")

        # network tools / exfil
        if n in DOWNLOADERS or n in NET_TOOLS:
            self.net(inf, sub_info)
        if n in DNS_TOOLS:
            if any(idx >= 0 for _, idx, _, _ in sub_info) or any(SECRET_VAR.search(rw) for rw in c.raw_words[1:]):
                bad = any(t & {"secret_read", "env_dump"} for _, _, _, t in sub_info) or any(
                    SECRET_VAR.search(rw) for rw in c.raw_words[1:])
                self.add("shell.dns_exfil", CRITICAL if bad else HIGH, "exfiltration",
                         "Smuggles data out by hiding it inside a website name lookup.", raw)

        # secret reads
        if (n in READERS and n != "cp") or (n == "openssl" and a):
            self.secret_reads(inf)
        if n in ("env", "printenv", "set", "export", "declare", "compgen") or n == "cat" and any("/environ" in x for x in a):
            if not a or (n == "export" and a == ["-p"]) or (n == "declare" and a[:1] in (["-p"], ["-x"])) \
                    or (n == "compgen" and a[:1] == ["-v"]) or n == "cat":
                inf.traits.add("env_dump")
                self.add("shell.env_dump", LOW, "secrets",
                         "Prints all your environment variables, which can include passwords and keys.", raw)
            elif n == "printenv" and any(re.search(r"SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|ACCESS_KEY", x) for x in a):
                inf.traits.add("env_dump")
                self.add("shell.print_secret_env", MEDIUM, "secrets", "Prints a secret key from your environment.", raw)
        if n in ("echo", "printf") and any(SECRET_VAR.search(rw) for rw in c.raw_words[1:]):
            inf.traits.add("env_dump")
            self.add("shell.print_secret_env", MEDIUM, "secrets", "Prints a secret key from your environment.", raw)
        if n == "history":
            inf.traits.add("secret_read")

        # decoders / obfuscation building blocks
        if (n in ("base64", "gbase64", "basenc") and any(x in ("-d", "-D", "--decode") or (x.startswith("-") and not x.startswith("--") and "d" in x) for x in a)) \
                or (n == "xxd" and any(x.startswith("-") and "r" in x for x in a)) \
                or (n == "openssl" and "-d" in a and ("base64" in a or "enc" in a)) \
                or n in ("rev", "uudecode") or (n == "printf" and a and re.search(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}", a[0])) \
                or (n == "echo" and any(re.fullmatch(r"-[nE]*e[nE]*", x) for x in a) and re.search(r"\\x[0-9a-fA-F]{2}", " ".join(a))) \
                or (n == "tr" and len(a) >= 2 and "n-z" in a[1].lower()):
            inf.traits.add("decode")

        # reverse shells / listeners
        if n in ("nc", "ncat", "netcat"):
            opts, _ = _parse_opts(a, "pswiqWIOT", {"--source-port", "--wait"})
            fl = {f for f, _ in opts}
            if fl & {"-e", "-c", "--exec", "--sh-exec", "--lua-exec"}:
                self.add("shell.reverse_shell", CRITICAL, "network",
                         "Gives someone on the internet remote control of this computer (reverse shell).", raw)
            elif fl & {"-l", "--listen"}:
                self.add("shell.listener", MEDIUM, "network", "Opens a network port so other computers can connect in.", raw)
        elif n == "socat":
            j = " ".join(a).lower()
            if re.search(r"\b(exec|system):", j):
                self.add("shell.reverse_shell", CRITICAL, "network",
                         "Connects a shell on this computer to the network, giving someone remote control.", raw)
            elif "listen" in j:
                self.add("shell.listener", MEDIUM, "network", "Opens a network port so other computers can connect in.", raw)
        elif n == "ssh" and any(x == "-R" or x.startswith("-R") for x in a):
            self.add("shell.tunnel", MEDIUM, "network", "Exposes a port on this computer to another machine.", raw)
        elif n in ("ngrok", "cloudflared", "localtunnel", "lt", "bore", "frpc", "serveo"):
            self.add("shell.tunnel", MEDIUM, "network", "Opens a public internet tunnel into this computer.", raw)

        # installs / publishing
        if n in ("npm", "pnpm", "yarn", "bun", "pip", "uv", "poetry", "pipx", "pipenv", "gem", "cargo", "go", "brew",
                 "composer", "deno", "twine"):
            self.install(n, a, raw)

    def var_payload_traits(self, payload: str) -> set[str]:
        out: set[str] = set()
        for v in re.findall(r"\$\{?(\w+)", payload):
            out |= self.var_traits.get(v, set())
        return out

    def code(self, name: str, code: str, inf: Info, depth: int) -> None:
        raw = inf.c.raw or code
        if REV_SOCK.search(code) and REV_EXEC.search(code):
            self.add("shell.reverse_shell", CRITICAL, "network",
                     "Gives someone on the internet remote control of this computer (reverse shell).", raw)
        fetchy = FETCH_CODE.search(code)
        if fetchy:
            inf.traits.add("download_stdout")
            h = _host(_first_url(re.findall(r"""['"]([^'"]+)['"]""", code)))
            if h:
                inf.host = inf.host or h
            if EXEC_CODE.search(code):
                self.add("shell.remote_code", self.rce_sev([h]), "network",
                         "Downloads code from the internet and runs it right away.", raw)
        if DECODE_CODE.search(code) and (EXEC_CODE.search(code) or re.search(r"\bsystem\s*\(|popen|execSync|spawn|subprocess", code)):
            self.add("shell.obfuscated_code", HIGH, "obfuscation", "Runs code that was hidden with an encoding trick.", raw)
            for m in re.finditer(r"""['"]([A-Za-z0-9+/=_-]{12,})['"]""", code):
                dec = _b64(m.group(1))
                if dec and _printable(dec):
                    self.text(_to_text(dec), depth + 1, quiet=True)
                    if depth + 1 <= MAX_DEPTH:
                        self.code(name, _to_text(dec), inf, depth + 1)
        for m in SHELL_CALL.finditer(code):
            self.text(m.group(2), depth + 1, quiet=True)
        if name in ("ruby", "perl", "php"):
            for m in re.finditer(r"`([^`]+)`|%x\{([^}]+)\}|qx\{([^}]+)\}", code):
                self.text(next(g for g in m.groups() if g), depth + 1, quiet=True)
        for m in re.finditer(r"(?:subprocess\.\w+|Popen|spawnSync|execFileSync|spawn|execFile)\s*\(\s*\[([^\]]*)\]", code):
            parts = re.findall(r"""['"]([^'"]*)['"]""", m.group(1))
            if parts:
                self.text(" ".join(shlex.quote(p) for p in parts), depth + 1, quiet=True)
        for m in re.finditer(r"""(?:rmtree|rmSync|rm_rf|rm_r|remove_dir_all|rimraf)\s*\(\s*(?:os\.path\.expanduser\(\s*)?['"]([^'"]+)['"]""", code):
            self.delete(m.group(1), True, raw)
        lits = re.findall(r"""['"]([~/.$][^'"\n]{0,200})['"]""", code)
        secrets = [x for x in lits if paths.is_secret(self.expand_path(x))]
        if secrets:
            inf.traits.add("secret_read")
            if fetchy or re.search(r"socket|smtplib|requests|urllib|http|fetch|axios", code):
                self.add("shell.exfil_secret", CRITICAL, "exfiltration",
                         f"Reads your credential file {secrets[0]} and sends it over the internet.", raw)
            else:
                self.add("shell.secret_read", MEDIUM + 5, "secrets", f"Reads your credential file {secrets[0]}.", raw)
        if name == "osascript":
            if re.search(r"login\s+item", code, re.I):
                self.add("shell.login_item", HIGH, "persistence", "Sets a program to run every time you log in.", raw)
            if re.search(r"display\s+dialog", code, re.I) and re.search(r"password|hidden\s+answer", code, re.I):
                self.add("shell.fake_prompt", HIGH, "secrets", "Shows a fake password prompt to trick you into typing your password.", raw)
        for lit in lits:
            if GUARD_RE.search(" " + lit):
                self.add("shell.guard_tamper", CRITICAL, "scope",
                         "Tries to change or read Tripwire's own settings, the guard watching this agent.", raw)

    # ---- path classification ----
    def classify_delete(self, t: str, recursive: bool) -> tuple[str, int, str] | None:
        """Return (tag, severity, message) for deleting t, or None if harmless."""
        if not t or t == "-":
            return None
        base_t = t
        if re.search(r"/\.?\*$", t):
            base_t = t[: t.rfind("/")] or "/"
        if base_t in ("*", ".*", ".", "./", "./*", "*.*"):
            if self.cwd and self.s.cwd and os.path.realpath(self.cwd) != os.path.realpath(self.s.cwd):
                base_t = self.cwd
            elif self.cwd and not self.s.cwd:
                base_t = self.cwd
            else:
                return ("glob", HIGH if recursive else MEDIUM,
                        "Deletes everything in your project folder." if self.s.cwd else "Deletes everything in the current folder.")
        full = self.expand_path(base_t)
        if "$" in full:
            return ("unknown_var", MEDIUM if recursive else LOW,
                    f"Deletes {t}, and if that variable is empty it could wipe far more than intended.")
        full = os.path.normpath(full)
        if full == "/":
            return ("root", CRITICAL if recursive else HIGH, "Deletes everything on your computer.")
        if full == HOME:
            return ("home", CRITICAL if recursive else HIGH, "Deletes your whole home folder.")
        if GUARD_RE.search(" " + full):
            return ("guard", CRITICAL, "Deletes Tripwire's own settings, the guard watching this agent.")
        if full.startswith(TMP_PREFIXES) and full not in EXTRA_SYSTEM:
            return None
        if full in EXTRA_SYSTEM or paths.is_system(full) or full.startswith(("/Applications/", "/Users/Shared")):
            if full.startswith(("/usr/local/", "/opt/homebrew/")) and full.count("/") > 3:
                return ("system", MEDIUM, f"Deletes files from a shared software folder: {t}")
            sev = CRITICAL if recursive and full.count("/") <= 2 else HIGH
            return ("system", sev, f"Deletes a system folder the computer needs: {t}")
        if _is_secret(full) or full.startswith(os.path.join(HOME, ".ssh")):
            return ("secret", HIGH, f"Deletes your credential or key files: {t}")
        ws_real = os.path.realpath(self.s.cwd) if self.s.cwd else None
        if ws_real and os.path.realpath(full) == ws_real:
            return ("ws_root", HIGH, "Deletes your whole project folder.")
        bn = os.path.basename(full)
        if bn in BUILD_DIRS or bn.endswith((".egg-info", ".pyc", ".log", ".tmp")):
            return None
        if re.search(r"/\.cache(/|$)|/Library/Caches(/|$)|/\.npm/_cacache|/\.gradle/caches|/Library/Developer/Xcode/DerivedData", full):
            return ("cache", LOW, f"Deletes cached files: {t}")
        if bn == ".git":
            return ("git", HIGH if recursive else MEDIUM, "Deletes your project's whole git history.")
        if os.path.dirname(full) == HOME and not (ws_real and ws_real.startswith(os.path.realpath(full) + os.sep)):
            return ("home_child", HIGH if recursive else MEDIUM, f"Deletes {t} from your home folder.")
        if ws_real and ws_real.startswith(os.path.realpath(full) + os.sep):
            return ("ws_parent", HIGH, f"Deletes a folder that contains your whole project: {t}")
        if self.s.cwd and not self.in_ws(full):
            return ("outside", HIGH if recursive else MEDIUM,
                    f"Deletes a {'folder' if recursive else 'file'} outside your project: {t}")
        if recursive:
            return ("ws", LOW, f"Deletes a folder in your project: {t}")
        return None

    def delete(self, t: str, recursive: bool, ev: str) -> None:
        r = self.classify_delete(t, recursive)
        if r:
            tag, sev, msg = r
            rule = {"root": "shell.rm_root", "home": "shell.rm_home", "system": "shell.rm_system",
                    "secret": "shell.rm_secrets", "guard": "shell.guard_tamper"}.get(tag, "shell.rm_" + tag)
            self.add(rule, sev, "scope" if tag == "guard" else "destructive", msg, ev)

    def find_delete(self, root: str, filtered: bool, ev: str) -> None:
        r = self.classify_delete(root, True)
        if not r or r[0] in ("ws", "ws_root", "glob", "cache", "unknown_var"):
            return
        tag, sev, msg = r
        if filtered and sev > HIGH:
            sev = HIGH
        self.add("shell.find_delete", sev, "destructive", "Bulk-deletes files: " + msg[0].lower() + msg[1:], ev)

    def write(self, t: str, ev: str) -> None:
        if not t or t.startswith("&"):
            return
        if DEV_TCP.match(t):
            return  # handled by raw check
        if t.startswith("/dev/"):
            if re.match(r"/dev/(r?disk|sd|hd|nvme|mmcblk|xvd|vd|mem|kmem)", t):
                self.add("shell.disk_overwrite", CRITICAL, "destructive",
                         f"Overwrites a whole disk or system memory ({t}), wiping what's on it.", ev)
            return
        full = os.path.normpath(self.expand_path(t))
        if GUARD_RE.search(" " + full):
            self.add("shell.guard_tamper", CRITICAL, "scope",
                     "Tries to change Tripwire's own settings, the guard watching this agent.", ev)
        elif re.search(r"^/(private/)?etc/sudoers", full):
            self.add("shell.sudoers", CRITICAL, "privilege", "Changes who gets administrator power on this computer.", ev)
        elif paths.is_persistence(full):
            self.add("shell.persistence", HIGH + 5, "persistence",
                     f"Changes a file that controls what runs on your machine later: {t}", ev)
        elif full.startswith(TMP_PREFIXES):
            return
        elif paths.is_system(full) or full.split("/")[1:2] and "/" + full.split("/")[1] in EXTRA_SYSTEM and full.count("/") <= 2:
            if full.startswith(("/usr/local/", "/opt/homebrew/", "/opt/")):
                self.add("shell.system_write", MEDIUM, "scope", f"Installs or changes a file in a shared system folder: {t}", ev)
            else:
                self.add("shell.system_write", HIGH, "scope", f"Changes a system file: {t}", ev)
        elif paths.is_secret(full) and not (self.s.cwd and self.in_ws(full)):
            self.add("shell.secret_overwrite", HIGH, "secrets", f"Overwrites a credential file: {t}", ev)
        elif self.s.cwd and not self.in_ws(full):
            self.add("shell.outside_write", MEDIUM, "scope", f"Writes a file outside your project: {t}", ev)

    # ---- specific commands ----
    def rm(self, inf: Info) -> None:
        recursive = inf.name == "rmdir"
        nopreserve = False
        targets: list[str] = []
        endopts = False
        for x in inf.args:
            if not endopts and x == "--":
                endopts = True
                continue
            if not endopts and x.startswith("--"):
                recursive |= x in ("--recursive", "--dir")
                nopreserve |= x == "--no-preserve-root"
                continue
            if not endopts and x.startswith("-") and len(x) > 1:
                recursive |= bool(set("rR") & set(x[1:]))
                continue
            targets.append(x)
        if nopreserve:
            self.add("shell.rm_root", CRITICAL, "destructive",
                     "Turns off the safety check that stops rm from wiping the whole disk.", inf.c.raw)
        for t in targets:
            self.delete(t, recursive, inf.c.raw)

    def find(self, inf: Info, depth: int) -> None:
        a = inf.args
        roots: list[str] = []
        i = 0
        while i < len(a) and not a[i].startswith(("-", "(", "!")):
            roots.append(a[i])
            i += 1
        expr = a[i:]
        roots = roots or ["."]
        deleting = "-delete" in expr
        for k, x in enumerate(expr):
            if x in ("-exec", "-execdir", "-ok", "-okdir"):
                sub = []
                for y in expr[k + 1:]:
                    if y in (";", "\\;", "+"):
                        break
                    sub.append(y)
                if not sub:
                    continue
                sn = _base(sub[0])
                if sn in ("rm", "shred", "unlink", "srm"):
                    deleting = True
                elif sn in SHELLS:
                    p, _ = self._shell_payload(sub[1:])
                    if p:
                        self.text(p.replace("{}", "FILE"), depth + 1)
                elif sn in ("chmod", "chown", "mv", "cp"):
                    sub_c = Cmd(words=[w.replace("{}", "FILE") for w in sub], raw=inf.c.raw)
                    sub_c.raw_words = list(sub_c.words)
                    self.cmd(sub_c, depth + 1)
        inf.find_roots = roots
        inf.find_filtered = any(x in ("-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-newer", "-mtime",
                                      "-mmin", "-size", "-empty", "-user") for x in expr)
        if deleting:
            for r in roots:
                self.find_delete(r, inf.find_filtered, inf.c.raw)

    def chmod(self, inf: Info) -> None:
        n, a, raw = inf.name, inf.args, inf.c.raw
        recursive = any(x in ("-R", "--recursive") or (x.startswith("-") and not x.startswith("--") and "R" in x) for x in a)
        pos = [x for x in a if not (x.startswith("-") and not re.fullmatch(r"-[rwxXst]+", x))]
        if not pos:
            return
        mode, targets = (pos[0], pos[1:])
        if n == "chmod":
            if re.fullmatch(r"[ugoa]*[+=][rwxXt]*s[rwxXst]*", mode) or re.fullmatch(r"[2-7][0-7]{3}", mode) and mode[0] in "4567 2"[:5] and mode[0] != "0":
                if re.fullmatch(r"[ugoa]*[+=][rwxXt]*s[rwxXst]*", mode) or mode[0] in "4567" or mode[0] == "2":
                    self.add("shell.setuid", HIGH, "privilege",
                             "Lets a program run with its owner's power (often administrator) for anyone who starts it.", raw)
            world = mode in ("777", "0777", "666", "0666", "a+rwx", "o+w", "a+w", "ugo+rwx", "o+rwx") or re.fullmatch(r"[0-7]?[0-7][0-7][2367]", mode)
        else:
            world = False
            targets = pos[1:]
        for t in targets:
            r = self.classify_delete(t, True)
            tag = r[0] if r else None
            if tag in ("root", "home", "system", "ws_parent", "home_child", "secret"):
                if tag in ("root", "home") or (tag == "system" and recursive and r and r[1] == CRITICAL):
                    sev = CRITICAL if (recursive or tag == "root") else HIGH
                elif recursive or world or tag == "system":
                    sev = HIGH
                else:
                    sev = MEDIUM if tag != "secret" else LOW
                what = "permissions" if n == "chmod" else "owner"
                msg = (f"Makes {t} open for anyone on this computer to change." if world else
                       f"Changes the {what} of {'everything in ' if recursive else ''}{t}.")
                if sev >= MEDIUM:
                    self.add("shell.chmod_system" if n == "chmod" else "shell.chown_system", sev, "destructive", msg, raw)

    def mv_cp(self, inf: Info, move: bool) -> None:
        n, a, raw = inf.name, inf.args, inf.c.raw
        pos = []
        skip = False
        for i, x in enumerate(a):
            if skip:
                skip = False
                continue
            if x in ("-t", "--target-directory", "-S", "--suffix", "-m", "-o", "-g", "--exclude", "-e"):
                skip = True
                continue
            if x.startswith("-"):
                continue
            pos.append(x)
        if len(pos) < 2:
            return
        srcs, dest = pos[:-1], pos[-1]
        if move:
            if dest == "/dev/null":
                for s_ in srcs:
                    self.add("shell.mv_destroy", HIGH, "destructive", f"Destroys {s_} by moving it into nothing.", raw)
            for s_ in srcs:
                r = self.classify_delete(s_, True)
                if r and r[1] >= HIGH and r[0] not in ("ws", "glob"):
                    self.add("shell.mv_away", r[1], "destructive", "Moves away " + r[2][0].lower() + r[2][1:], raw)
        elif n in ("cp", "rsync"):
            for s_ in srcs:
                if _is_secret(self.expand_path(s_)) and not (self.s.cwd and self.in_ws(self.expand_path(s_))):
                    self.add("shell.secret_read", MEDIUM + 5, "secrets", f"Copies your credential file {s_}.", raw)
                    inf.traits.add("secret_read")
                    self.tainted_files.add(os.path.normpath(self.expand_path(dest)))
                    self.tainted_files.add(os.path.normpath(os.path.join(self.expand_path(dest), os.path.basename(s_))))
        if dest != "/dev/null":
            self.write(dest, raw)

    def git(self, inf: Info) -> None:
        a, raw = inf.args, inf.c.raw
        i = 0
        while i < len(a) and a[i].startswith("-"):
            i += 2 if a[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
        if i >= len(a):
            return
        sub, rest = a[i], a[i + 1:]
        flags = [x for x in rest if x.startswith("-")]
        pos = [x for x in rest if not x.startswith("-")]
        if sub == "push":
            if any(x in ("-f", "--force", "--mirror") or (x.startswith("-") and not x.startswith("--") and "f" in x) for x in flags) \
                    or any(p.startswith("+") for p in pos):
                self.add("shell.git_force_push", MEDIUM, "destructive",
                         "Force-pushes, which can overwrite history on the shared copy of your code.", raw)
            elif any(x.startswith("--force-with-lease") or x.startswith("--force-if-includes") for x in flags):
                self.add("shell.git_force_push", LOW, "destructive", "Force-pushes (safely, with a lease check).", raw)
            if "--delete" in flags or "-d" in flags or any(p.startswith(":") for p in pos):
                self.add("shell.git_delete_branch", MEDIUM, "destructive", "Deletes a branch on the shared server.", raw)
            if any(re.search(r"(^|:)(main|master)$", p) for p in pos[1:]):
                self.add("shell.git_push_main", LOW, "scope", "Pushes straight to the main branch.", raw)
        elif sub == "reset" and "--hard" in flags:
            self.add("shell.git_reset_hard", MEDIUM, "destructive", "Throws away all your uncommitted changes.", raw)
        elif sub == "clean":
            fl = "".join(x.lstrip("-") for x in flags if not x.startswith("--"))
            if ("f" in fl or "--force" in flags) and "n" not in fl and "--dry-run" not in flags:
                if "d" in fl or "x" in fl:
                    self.add("shell.git_clean", MEDIUM, "destructive",
                             "Deletes every file git isn't tracking, including new work you haven't saved anywhere.", raw)
                else:
                    self.add("shell.git_clean", LOW, "destructive", "Deletes untracked files.", raw)
        elif sub in ("checkout", "restore") and ("." in pos or "--" in rest and "." in rest):
            self.add("shell.git_discard", LOW, "destructive", "Discards your uncommitted changes.", raw)
        elif sub == "branch" and any(x in ("-D",) for x in flags):
            self.add("shell.git_branch_delete", LOW, "destructive", "Force-deletes a local branch.", raw)
        elif sub == "stash" and pos[:1] in (["drop"], ["clear"]):
            self.add("shell.git_stash_drop", LOW, "destructive", "Throws away saved stashed changes.", raw)
        elif sub in ("filter-branch", "filter-repo"):
            self.add("shell.git_rewrite", MEDIUM, "destructive", "Rewrites your whole git history.", raw)
        elif sub == "config":
            j = " ".join(rest)
            if re.search(r"core\.(hooksPath|sshCommand|pager|fsmonitor|editor)|alias\.\S+\s+['\"]?!|credential\.helper|"
                         r"url\..*insteadOf", j, re.I):
                self.add("shell.git_config_exec", MEDIUM, "persistence",
                         "Changes git settings so it quietly runs a command later.", raw)

    def docker(self, inf: Info) -> None:
        a, raw = inf.args, inf.c.raw
        j = " ".join(a)
        if a[:2] == ["system", "prune"]:
            big = any(x in ("-a", "--all", "--volumes") or (x.startswith("-") and not x.startswith("--") and "a" in x) for x in a[2:])
            self.add("shell.docker_prune", HIGH if big else MEDIUM, "destructive",
                     "Deletes all Docker images, containers and saved data." if big else "Deletes unused Docker data.", raw)
        elif a[:2] in (["volume", "prune"], ["volume", "rm"]) or (a[:1] in (["compose"],) or inf.name == "docker-compose") and "down" in a and any(x in ("-v", "--volumes") for x in a):
            self.add("shell.docker_volumes", MEDIUM, "destructive", "Deletes Docker volumes, which often hold database data.", raw)
        elif a[:2] == ["image", "prune"] and ("-a" in a or "--all" in a):
            self.add("shell.docker_prune", MEDIUM, "destructive", "Deletes all Docker images.", raw)
        if a[:1] in (["run"], ["create"], ["exec"]) or a[:2] == ["container", "run"]:
            if re.search(r"(?:-v|--volume|--mount)[ =](?:type=bind,\s*source=)?/(?::|,|\s|$)|/var/run/docker\.sock|--pid[ =]host|"
                         r"--privileged|--cap-add[ =](?:ALL|SYS_ADMIN)", j):
                self.add("shell.docker_escape", HIGH, "privilege",
                         "Gives a container full control of your computer.", raw)

    def aws(self, inf: Info) -> None:
        a, raw = inf.args, inf.c.raw
        if a[:2] == ["s3", "rm"] and "--recursive" in a or a[:2] == ["s3", "rb"]:
            self.add("shell.cloud_delete", HIGH, "destructive", "Deletes files or a whole bucket from Amazon S3.", raw)
        elif any(x.startswith(("delete-", "terminate-")) for x in a[1:2]):
            big = any(x in ("terminate-instances", "delete-db-instance", "delete-db-cluster", "delete-stack", "delete-bucket",
                            "delete-table") for x in a)
            self.add("shell.cloud_delete", HIGH if big else MEDIUM, "destructive", "Deletes resources from your AWS account.", raw)

    def sql(self, blob: str) -> None:
        if SQL_DROP_DB.search(blob):
            self.add("shell.sql_drop_database", CRITICAL, "destructive", "Deletes a whole database.", SQL_DROP_DB.search(blob).group(0))
        elif SQL_DROP_TABLE.search(blob):
            self.add("shell.sql_drop_table", HIGH, "destructive", "Deletes a database table and all of its data.",
                     SQL_DROP_TABLE.search(blob).group(0))
        m = SQL_DELETE_ALL.search(blob)
        if m and not re.search(r"\bwhere\b", blob[m.start():m.start() + 400], re.I):
            self.add("shell.sql_delete_all", HIGH, "destructive", "Deletes every row in a database table.", m.group(0))

    def secret_reads(self, inf: Info) -> None:
        n, a = inf.name, inf.args
        cand: list[str] = []
        pos_seen = 0
        has_pat_flag = any(x in ("-e", "-f", "--regexp", "--file") for x in a)
        for i, x in enumerate(a):
            if x.startswith("-"):
                if "=" in x:
                    cand.append(x.split("=", 1)[1])
                continue
            if i > 0 and a[i - 1] in ("-in", "-f", "--file", "-i", "-inkey", "--input", "if"):
                cand.append(x)
                continue
            pos_seen += 1
            if n in PATTERN_FIRST and pos_seen == 1 and not has_pat_flag:
                continue
            if n == "dd":
                continue
            cand.append(x)
        hit = False
        for x in cand:
            full = self.expand_path(x)
            if os.path.normpath(full) in self.tainted_files:
                hit = True
            if _is_secret(full):
                verb = "Copies" if n == "cp" else "Archives" if n in ("tar", "zip", "7z") else "Reads"
                self.add("shell.secret_read", MEDIUM + 5, "secrets", f"{verb} your credential file {x}.", inf.c.raw)
                hit = True
        if hit:
            inf.traits.add("secret_read")
        elif cand:
            inf.traits.add("file_read")

    def _remote_dest(self, a: list[str]) -> bool:
        pos = [x for x in a if not x.startswith("-")]
        return bool(pos) and bool(re.match(r"^(?:[\w.-]+@)?[\w.-]+:(?!//)", pos[-1])) and not pos[-1].startswith(("/", "."))

    def net(self, inf: Info, sub_info: list) -> None:
        n, a, c, raw = inf.name, inf.args, inf.c, inf.c.raw
        inf.traits.add("net")
        files: list[str] = []
        data_vals: list[str] = []
        url = None
        if n == "curl":
            opts, pos = _parse_opts(a, "dFHoeuXAbcTxwmKErCYyzQtUD", {
                "--data", "--data-binary", "--data-raw", "--data-ascii", "--data-urlencode", "--json", "--form",
                "--form-string", "--header", "--output", "--referer", "--user", "--request", "--user-agent", "--cookie",
                "--cookie-jar", "--upload-file", "--proxy", "--write-out", "--max-time", "--connect-timeout", "--config",
                "--cert", "--range", "--url", "--resolve", "--retry", "--cacert", "--key", "--output-dir",
                "--dump-header", "--limit-rate", "--interface", "--proxy-user", "--oauth2-bearer", "--unix-socket"})
            url = next((v for f, v in opts if f == "--url"), None) or _first_url(pos)
            to_file = False
            for f, v in opts:
                if f in ("-d", "--data", "--data-binary", "--data-ascii", "--json"):
                    data_vals.append(v)
                    if v.startswith("@"):
                        files.append(v[1:])
                elif f == "--data-urlencode":
                    data_vals.append(v)
                    m = re.match(r"^[^=@]*@(.+)$", v)
                    if m:
                        files.append(m.group(1))
                elif f in ("-F", "--form"):
                    data_vals.append(v)
                    m = re.search(r"=[@<]([^;]+)", v)
                    if m:
                        files.append(m.group(1))
                elif f in ("-T", "--upload-file"):
                    files.append(v)
                elif f in ("-o", "--output"):
                    if v != "-":
                        to_file = True
                        inf.outputs.append(v)
                        self.write(v, raw)
                elif f in ("-O", "--remote-name", "--remote-name-all"):
                    to_file = True
                    if url:
                        bn = os.path.basename(url.split("?")[0].rstrip("/")) or "index.html"
                        inf.outputs.append(bn)
            if not to_file:
                inf.traits.add("download_stdout")
            data_vals += [p for p in pos if p != url]
            if url:
                data_vals.append(url)
        elif n == "wget":
            opts, pos = _parse_opts(a, "OoaPtTwUeiBQlARDIX", {
                "--output-document", "--post-file", "--post-data", "--body-file", "--body-data", "--header", "--user",
                "--password", "--user-agent", "--directory-prefix", "--method", "--output-file", "--input-file"})
            url = _first_url(pos)
            out = None
            prefix = None
            for f, v in opts:
                if f in ("-O", "--output-document"):
                    out = v
                elif f in ("-P", "--directory-prefix"):
                    prefix = v
                elif f in ("--post-file", "--body-file"):
                    files.append(v)
                elif f in ("--post-data", "--body-data"):
                    data_vals.append(v)
            if out == "-":
                inf.traits.add("download_stdout")
            else:
                if out is None and url:
                    out = os.path.basename(url.split("?")[0].rstrip("/")) or "index.html"
                    if prefix:
                        out = os.path.join(prefix, out)
                elif out:
                    self.write(out, raw)
                if out:
                    inf.outputs.append(out)
            if url:
                data_vals.append(url)
        elif n in ("http", "https", "xh"):
            pos = [x for x in a if not x.startswith("-")]
            if pos and pos[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                pos = pos[1:]
            url = pos[0] if pos else None
            for x in pos[1:]:
                m = re.match(r"^[^=:@]*:?=@(.+)$|^@(.+)$|^[^=:@]+@(.+)$", x)
                if m:
                    files.append(next(g for g in m.groups() if g))
                data_vals.append(x)
            inf.stdin_send = True
            inf.traits.add("download_stdout")
        elif n in ("scp", "sftp", "rsync"):
            opts, pos = _parse_opts(a, "iPoFcSlJe" if n != "rsync" else "eB", {"--exclude", "--include", "--rsh", "--filter"})
            if len(pos) >= 2 and self._remote_dest(pos):
                files += pos[:-1]
                url = _first_url([pos[-1]]) or pos[-1].split(":")[0].split("@")[-1]
        elif n in ("nc", "ncat", "netcat", "socat", "telnet", "ssh", "openssl", "mail", "mailx", "sendmail", "mutt", "ftp", "tftp"):
            pos = [x for x in a if not x.startswith("-")]
            url = pos[0] if pos and n not in ("openssl",) else None
            if n == "ssh":
                opts, pos = _parse_opts(a, "bcDEeFIiJLlmOoPpQRSWw", set())
                url = pos[0] if pos else None
            inf.stdin_send = True
            if n == "mutt":
                files += [a[i + 1] for i, x in enumerate(a[:-1]) if x == "-a"]
        elif n == "aws" and a[:1] == ["s3"] and len(a) > 2 and a[1] in ("cp", "sync", "mv"):
            pos = [x for x in a[2:] if not x.startswith("-")]
            if pos and pos[-1].startswith("s3://"):
                files += [p for p in pos[:-1] if not p.startswith("s3://")]
                url = "Amazon S3 (" + pos[-1] + ")"
        elif n == "gsutil" and "cp" in a:
            pos = [x for x in a if not x.startswith("-") and x != "cp"]
            if pos and pos[-1].startswith("gs://"):
                files += [p for p in pos[:-1] if not p.startswith("gs://")]
                url = "Google Cloud Storage"
        elif n == "rclone" and a[:1] and a[0] in ("copy", "sync", "copyto", "move"):
            pos = [x for x in a[1:] if not x.startswith("-")]
            if len(pos) >= 2 and ":" in pos[-1]:
                files += pos[:-1]
                url = pos[-1].split(":")[0]
        elif n == "gh" and a[:2] == ["gist", "create"]:
            files += [x for x in a[2:] if not x.startswith("-")]
            url = "a public GitHub Gist"
        for op, tgt in c.redirects:
            if op == "<" and inf.stdin_send:
                files.append(tgt)
        host = _host(url) if url and "://" in (url or "") or (url and DOMAINISH.match(url or "")) else url
        inf.host = host
        if host:
            inf.traits.add("host=" + host)
        local = bool(host and LOCAL_HOST.match(host))
        where = host or "another computer"
        for f in files:
            if f in ("-", "/dev/stdin", ""):
                inf.stdin_send = True
                continue
            full = self.expand_path(f)
            if _is_secret(full) or full.startswith(os.path.join(HOME, ".ssh")) or os.path.normpath(full) in self.tainted_files:
                self.add("shell.exfil_secret", CRITICAL, "exfiltration", f"Uploads your credential file {f} to {where}.", raw)
            elif local:
                continue
            elif self.mentioned(host) or self.mentioned(f):
                self.add("shell.upload_file", LOW, "exfiltration", f"Sends the local file {f} to {where}.", raw)
            else:
                self.add("shell.upload_file", MEDIUM, "exfiltration", f"Sends the local file {f} to {where}.", raw)
        bad_sub = [t for _, _, _, t in sub_info if t & {"secret_read", "env_dump"}]
        if self.var_payload_traits(" ".join(c.words[1:])) & {"secret_read", "env_dump"}:
            bad_sub.append({"secret_read"})
        if bad_sub:
            self.add("shell.exfil_secret", CRITICAL, "exfiltration",
                     f"Sends your secret keys or environment variables to {where}.", raw)
        elif sub_info and n in DOWNLOADERS and not local and any(idx >= 0 for _, idx, _, _ in sub_info):
            self.add("shell.cmd_output_sent", LOW, "exfiltration", f"Sends the output of another command to {where}.", raw)
        if not local and not self.mentioned(host):
            for v in data_vals:
                m = SECRET_VAR.search(v)
                if m:
                    self.add("shell.exfil_env_secret", HIGH, "exfiltration",
                             f"Sends the secret value ${m.group(1)} to {where}.", raw)
                    break

    def install(self, n: str, a: list[str], raw: str) -> None:
        if not a:
            return
        sub = a[0]
        items: list[str] | None = None
        if n in ("npm", "pnpm", "yarn", "bun") and sub in ("install", "i", "add", "isntall", "ci"):
            items = a[1:]
        elif n == "pip" and sub in ("install", "download"):
            items = a[1:]
        elif n == "uv" and (sub == "add" or a[:2] in (["pip", "install"], ["tool", "install"])):
            items = a[2:] if sub in ("pip", "tool") else a[1:]
        elif n in ("poetry", "pipenv", "pipx", "gem", "cargo", "go", "brew", "composer", "deno") and sub in ("add", "install", "get", "require"):
            items = a[1:]
        if n in ("npm", "pnpm", "yarn", "cargo", "gem", "twine", "poetry", "uv", "bun") and (sub in ("publish", "push") or n == "twine" and sub == "upload"):
            sev = LOW if re.search(r"publish|release|upload", self.task) else MEDIUM
            self.add("shell.publish", sev, "exfiltration", "Publishes this code as a package anyone on the internet can download.", raw)
        if n in ("npm", "pnpm", "yarn") and sub == "unpublish":
            self.add("shell.unpublish", HIGH, "destructive", "Removes a published package from the public registry.", raw)
        if items is None:
            return
        i = 0
        while i < len(items):
            x = items[i]
            val = None
            if x in ("-i", "--index-url", "--extra-index-url", "--registry", "--trusted-host", "-f", "--find-links",
                     "--source", "--git", "--index"):
                val = items[i + 1] if i + 1 < len(items) else None
                i += 1
            elif "=" in x and x.split("=", 1)[0] in ("--index-url", "--extra-index-url", "--registry", "--trusted-host",
                                                     "--find-links", "--git", "--index"):
                val = x.split("=", 1)[1]
            if val:
                h = _host(val)
                if h and h not in OFFICIAL_REGISTRIES and not self.mentioned(val) and not LOCAL_HOST.match(h or ""):
                    if x.startswith("--git"):
                        self.add("shell.install_from_url", MEDIUM, "network",
                                 f"Installs code straight from {val} instead of the normal package registry.", raw)
                    else:
                        self.add("shell.install_custom_registry", MEDIUM, "network",
                                 f"Installs packages from an unofficial package server ({h}).", raw)
            elif URLISH.search(x) or re.search(r"@\s*(?:git\+)?https?://", x):
                url = x.split("@", 1)[1].strip() if re.search(r"@\s*(?:git\+)?https?://", x) and not URLISH.search(x) else x
                if not self.mentioned(url) and not self.mentioned(re.sub(r"^(git\+)?\w+://", "", url).split("#")[0].rstrip("/").removesuffix(".git").split("/", 1)[-1]):
                    self.add("shell.install_from_url", MEDIUM, "network",
                             f"Installs code straight from a web link ({_clip(url, 60)}) instead of the normal package registry.", raw)
            i += 1


CONFUSABLE_KEYS = {chr(k) for k in CONFUSABLE}


def analyze_shell(command: str, session: Session) -> list[Finding]:
    try:
        if not isinstance(command, str) or not command.strip():
            return []
        a = _Analyzer(session)
        a.text(command, 0)
        return a.result()
    except Exception as e:  # never raise: a broken analyzer must not crash the guard
        return [Finding(rule="shell.analyzer_error", severity=MEDIUM, category="general",
                        message="Tripwire could not fully check this command, so it is asking to be safe.",
                        evidence=_clip(f"{type(e).__name__}: {e}"))]
