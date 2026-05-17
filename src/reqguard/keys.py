from __future__ import annotations

import curses


SHIFT_UP_KEYS = {getattr(curses, "KEY_SR", -1)}
SHIFT_DOWN_KEYS = {getattr(curses, "KEY_SF", -1)}


def is_shift_up(key: int) -> bool:
    return key in SHIFT_UP_KEYS


def is_shift_down(key: int) -> bool:
    return key in SHIFT_DOWN_KEYS
