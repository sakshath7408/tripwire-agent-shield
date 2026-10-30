"""Which file paths hold secrets or keep a machine running."""

from __future__ import annotations

import os
import re

# Reading these is how credentials leak.
SECRET_PATHS = re.compile(
    r"(^|/)(\.ssh(/|$)|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$|\.aws/|\.gnupg/|\.netrc$|\.npmrc$|\.pypirc$|"
    r"\.docker/config\.json$|\.kube/config$|\.config/gcloud/|\.git-credentials$|\.env(\.[\w-]+)?$|"
    r"credentials(\.json)?$|secrets?\.(ya?ml|json|toml)$|\.pem$|\.key$|\.p12$|keychain|\.bash_history$|\.zsh_history$|"
    r"Library/Application Support/Google/Chrome/.*/(Login Data|Cookies)|\.mozilla/.*/(logins\.json|key4\.db)|/etc/shadow$|/etc/sudoers)",
    re.I,
)

# Writing these changes what runs on the machine next time (persistence).
PERSISTENCE_PATHS = re.compile(
    r"(^|/)(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|\.ssh/authorized_keys|\.ssh/config|"
    r"Library/LaunchAgents/|Library/LaunchDaemons/|/etc/cron|/var/spool/cron|crontab|/etc/systemd/|"
    r"\.config/autostart/|\.git/hooks/|\.claude/settings(\.local)?\.json|\.vscode/settings\.json|\.cursor/)",
    re.I,
)

SYSTEM_PATHS = re.compile(r"^(/etc|/usr|/bin|/sbin|/boot|/System|/Library|/var|/private/etc|/opt)(/|$)")


def expand(path: str, cwd: str | None = None) -> str:
    p = os.path.expanduser(os.path.expandvars(path))
    if not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def is_secret(path: str) -> bool:
    return bool(SECRET_PATHS.search(path)) and not path.endswith((".env.example", ".env.sample", ".env.template"))


def is_persistence(path: str) -> bool:
    return bool(PERSISTENCE_PATHS.search(path))


def is_system(path: str) -> bool:
    return bool(SYSTEM_PATHS.match(path))
