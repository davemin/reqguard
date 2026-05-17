from __future__ import annotations

import curses


KEY_TIMEOUT_MS = 150
ESC_SEQUENCE_TIMEOUT_MS = 80
SHIFT_UP = -10001
SHIFT_DOWN = -10002

_ESC = 27
_NO_KEY = -1
_XTERM_SHIFT_UP = (_ESC, ord("["), ord("1"), ord(";"), ord("2"), ord("A"))
_XTERM_SHIFT_DOWN = (_ESC, ord("["), ord("1"), ord(";"), ord("2"), ord("B"))
_RXVT_SHIFT_UP = (_ESC, ord("["), ord("a"))
_RXVT_SHIFT_DOWN = (_ESC, ord("["), ord("b"))
_SS3_SHIFT_UP = (_ESC, ord("O"), ord("2"), ord("A"))
_SS3_SHIFT_DOWN = (_ESC, ord("O"), ord("2"), ord("B"))
SHIFT_UP_SEQUENCES = {_XTERM_SHIFT_UP, _RXVT_SHIFT_UP, _SS3_SHIFT_UP}
SHIFT_DOWN_SEQUENCES = {_XTERM_SHIFT_DOWN, _RXVT_SHIFT_DOWN, _SS3_SHIFT_DOWN}
SHIFT_UP_KEYS = {SHIFT_UP, getattr(curses, "KEY_SR", -1)}
SHIFT_DOWN_KEYS = {SHIFT_DOWN, getattr(curses, "KEY_SF", -1)}


def read_key(stdscr: curses.window) -> int:
    key = stdscr.getch()
    if key != _ESC:
        return key

    sequence = [key]
    stdscr.timeout(ESC_SEQUENCE_TIMEOUT_MS)
    try:
        max_sequence_len = max(len(sequence) for sequence in SHIFT_UP_SEQUENCES | SHIFT_DOWN_SEQUENCES)
        for _ in range(max_sequence_len - 1):
            next_key = stdscr.getch()
            if next_key == _NO_KEY:
                break
            sequence.append(next_key)
            parsed = shift_arrow_from_sequence(sequence)
            if parsed is not None:
                return parsed
        return key
    finally:
        stdscr.timeout(KEY_TIMEOUT_MS)


def shift_arrow_from_sequence(sequence: list[int] | tuple[int, ...]) -> int | None:
    normalized = tuple(sequence)
    if normalized in SHIFT_UP_SEQUENCES:
        return SHIFT_UP
    if normalized in SHIFT_DOWN_SEQUENCES:
        return SHIFT_DOWN
    return None


def is_shift_up(key: int) -> bool:
    return key in SHIFT_UP_KEYS


def is_shift_down(key: int) -> bool:
    return key in SHIFT_DOWN_KEYS
