import curses

from reqguard.keys import is_shift_down, is_shift_up


def test_shift_arrow_key_detection_uses_curses_codes():
    assert is_shift_up(curses.KEY_SR)
    assert is_shift_down(curses.KEY_SF)
    assert not is_shift_up(curses.KEY_UP)
    assert not is_shift_down(curses.KEY_DOWN)
