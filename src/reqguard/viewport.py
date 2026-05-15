from __future__ import annotations


def scroll_start_index(row_heights: list[int], selected_index: int, available_rows: int) -> int:
    if not row_heights or available_rows <= 0:
        return 0

    selected_index = max(0, min(selected_index, len(row_heights) - 1))
    start_index = 0
    visible_height = 0

    for index, height in enumerate(row_heights):
        row_height = max(1, height)
        if index <= selected_index:
            visible_height += row_height
            while visible_height > available_rows and start_index < selected_index:
                visible_height -= max(1, row_heights[start_index])
                start_index += 1
        else:
            break

    return start_index
