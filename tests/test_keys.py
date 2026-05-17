import curses

from reqguard.keys import SHIFT_DOWN, SHIFT_UP, is_shift_down, is_shift_up, read_key, shift_arrow_from_sequence


class FakeWindow:
    def __init__(self, keys: list[int]) -> None:
        self.keys = keys
        self.timeouts: list[int] = []

    def getch(self) -> int:
        return self.keys.pop(0) if self.keys else -1

    def timeout(self, value: int) -> None:
        self.timeouts.append(value)


def test_shift_arrow_key_detection_accepts_xterm_arrow_sequences():
    assert shift_arrow_from_sequence([27, ord("["), ord("1"), ord(";"), ord("2"), ord("A")]) == SHIFT_UP
    assert shift_arrow_from_sequence([27, ord("["), ord("1"), ord(";"), ord("2"), ord("B")]) == SHIFT_DOWN


def test_shift_arrow_key_detection_accepts_rxvt_and_ss3_sequences():
    assert shift_arrow_from_sequence([27, ord("["), ord("a")]) == SHIFT_UP
    assert shift_arrow_from_sequence([27, ord("["), ord("b")]) == SHIFT_DOWN
    assert shift_arrow_from_sequence([27, ord("O"), ord("2"), ord("A")]) == SHIFT_UP
    assert shift_arrow_from_sequence([27, ord("O"), ord("2"), ord("B")]) == SHIFT_DOWN


def test_read_key_normalizes_shift_arrow_up_and_down_sequences():
    assert read_key(FakeWindow([27, ord("["), ord("1"), ord(";"), ord("2"), ord("A")])) == SHIFT_UP
    assert read_key(FakeWindow([27, ord("["), ord("1"), ord(";"), ord("2"), ord("B")])) == SHIFT_DOWN


def test_shift_arrow_key_detection_keeps_curses_fallbacks():
    assert is_shift_up(curses.KEY_SR)
    assert is_shift_down(curses.KEY_SF)
    assert not is_shift_up(curses.KEY_UP)
    assert not is_shift_down(curses.KEY_DOWN)


def test_page_up_and_page_down_do_not_count_as_shift_arrows():
    assert not is_shift_up(curses.KEY_PPAGE)
    assert not is_shift_down(curses.KEY_NPAGE)


def test_raw_page_up_and_page_down_sequences_are_not_shift_arrows():
    assert read_key(FakeWindow([27, ord("["), ord("5"), ord("~")])) == 27
    assert read_key(FakeWindow([27, ord("["), ord("6"), ord("~")])) == 27
