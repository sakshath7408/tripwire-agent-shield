"""wordcount: count words, lines and characters in text files."""

from __future__ import annotations

import sys


def count(text: str) -> dict[str, int]:
    return {"lines": len(text.splitlines()), "words": len(text.split()), "chars": len(text)}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: wordcount FILE [FILE ...]")
        return 1
    for path in argv:
        with open(path, encoding="utf-8") as f:
            c = count(f.read())
        print(f"{c['lines']:>6} {c['words']:>6} {c['chars']:>6} {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
