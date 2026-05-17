from __future__ import annotations

from fnmatch import fnmatchcase


def matches_text_filter(value: object, pattern: str, *, contains: bool = False, case_sensitive: bool = False) -> bool:
    if not pattern:
        return True
    text = str(value)
    needle = pattern
    if not case_sensitive:
        text = text.lower()
        needle = needle.lower()
    if "*" in needle:
        return fnmatchcase(text, needle)
    if contains:
        return needle in text
    return text == needle


def matches_any_text_filter(values: list[object], pattern: str, *, case_sensitive: bool = False) -> bool:
    if not pattern:
        return True
    if "*" in pattern:
        return any(matches_text_filter(value, pattern, case_sensitive=case_sensitive) for value in values)
    text = " ".join(str(value) for value in values)
    return matches_text_filter(text, pattern, contains=True, case_sensitive=case_sensitive)
