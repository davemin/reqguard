from __future__ import annotations


def safe_terminal_text(value: object, replacement: str = "?") -> str:
    text = str(value)
    return "".join(ch if ch.isprintable() and ch != "\x1b" else replacement for ch in text)

