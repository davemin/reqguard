from reqguard.viewport import scroll_start_index


def test_scroll_start_keeps_selected_row_visible_with_uniform_rows():
    row_heights = [1] * 10

    assert scroll_start_index(row_heights, selected_index=0, available_rows=5) == 0
    assert scroll_start_index(row_heights, selected_index=4, available_rows=5) == 0
    assert scroll_start_index(row_heights, selected_index=5, available_rows=5) == 1
    assert scroll_start_index(row_heights, selected_index=9, available_rows=5) == 5


def test_scroll_start_accounts_for_expanded_rows_before_selection():
    row_heights = [4, 1, 1, 1]

    assert scroll_start_index(row_heights, selected_index=1, available_rows=3) == 1


def test_scroll_start_keeps_oversized_selected_row_at_top():
    row_heights = [1, 8, 1]

    assert scroll_start_index(row_heights, selected_index=1, available_rows=3) == 1


def test_scroll_start_handles_empty_or_unusable_viewport():
    assert scroll_start_index([], selected_index=5, available_rows=5) == 0
    assert scroll_start_index([1, 1], selected_index=1, available_rows=0) == 0
