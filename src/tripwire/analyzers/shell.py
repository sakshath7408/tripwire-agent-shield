"""Shell command analysis. Parses commands into an AST (bashlex), never plain regex alone.

Contract: analyze_shell(command, session) -> list[Finding]. Pure, fast (<5 ms typical),
never raises (a parse failure is itself a finding, since obfuscation often breaks parsers).
"""

from __future__ import annotations

from ..models import Finding
from ..session import Session


def analyze_shell(command: str, session: Session) -> list[Finding]:
    return []
