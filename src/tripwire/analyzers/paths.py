"""Which file paths hold secrets or keep a machine running."""

from __future__ import annotations

import os
import re

# Reading these is how credentials leak.
SECRET_PATHS = re.compile(
    r"(^|/)(\.ssh(/|$)|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$|\.aws/|\.gnupg/|\.netrc$|\.npmrc$|\.pypirc$|"
    r"\.docker/config\.json$|\.kube/config$|\.config/gcloud/|\.git-credentials$|\.env(\.[\w-]+)?$|"
    r"credentials(\.json)?$|secrets?\.(ya?ml|json|toml)$|\.pem$|\.key$|\.p12$|keychain|\.bash_history$|\.zsh_history$|"
    # CLI token stores: GitHub CLI and hub, Terraform Cloud, 1Password CLI, Azure, Vault, Postgres, Cargo, rclone, boto
    r"\.config/gh/|\.config/hub$|\.terraform\.d/credentials|\.config/op/|\.op/|\.azure/|\.vault-token$|\.pgpass$|"
    r"\.my\.cnf$|\.cargo/credentials|\.config/rclone/rclone\.conf$|\.boto$|\.s3cfg$|\.claude/\.credentials\.json$|"
    # Tripwire's own state (audit key, API token, pin key, learned rules, settings): reading it lets an agent forge the log
    r"\.tripwire(/|$)|"
    r"Library/Application Support/Google/Chrome/.*/(Login Data|Cookies)|\.mozilla/.*/(logins\.json|key4\.db)|/etc/shadow$|/etc/sudoers)",
    re.I,
)

# Writing these changes what runs on the machine next time (persistence).
PERSISTENCE_PATHS = re.compile(
    r"(^|/)(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|\.ssh/authorized_keys|\.ssh/config|"
    r"Library/LaunchAgents/|Library/LaunchDaemons/|/etc/cron|/var/spool/cron|crontab|/etc/systemd/|"
    r"\.config/autostart/|\.git/hooks/|\.claude/settings[\w.-]{0,40}\.json|\.tripwire/|\.vscode/settings\.json|\.cursor/)",
    re.I,
)

SYSTEM_PATHS = re.compile(r"^(/etc|/usr|/bin|/sbin|/boot|/System|/Library|/var|/private/etc|/opt)(/|$)")


def expand(path: str, cwd: str | None = None) -> str:
    p = os.path.expanduser(os.path.expandvars(path))
    if not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


GLOB_CHARS = re.compile(r"[*?\[\]{}]")
# Names a glob like ".env*" or "**/id_*" could pick up.
SECRET_SAMPLES = (".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials", "credentials.json",
                  ".npmrc", ".pypirc", ".netrc", ".git-credentials", "secrets.yaml", "secrets.json", "server.pem", "server.key")


def is_secret(path: str) -> bool:
    if path.endswith((".env.example", ".env.sample", ".env.template", ".pub", "/known_hosts")):
        return False  # public keys and templates hold nothing secret
    if SECRET_PATHS.search(path):
        return True
    if GLOB_CHARS.search(path):
        import fnmatch
        base = path.rsplit("/", 1)[-1]
        if re.fullmatch(r"\*\.[\w.-]{1,32}", base):  # "*.json" is any json file; "*.pem" is any key file
            return bool(SECRET_PATHS.search("x" + base[1:]))
        if base and any(fnmatch.fnmatch(sample, base) for sample in SECRET_SAMPLES) and base not in ("*", "**", "*.*"):
            return True
        return bool(SECRET_PATHS.search(GLOB_CHARS.sub("", path)))
    return False


def is_persistence(path: str) -> bool:
    return bool(PERSISTENCE_PATHS.search(path))


def is_system(path: str) -> bool:
    return bool(SYSTEM_PATHS.match(path))
