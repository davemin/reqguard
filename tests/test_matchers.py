from reqguard.matchers import matches_any_text_filter, matches_text_filter


def test_matches_text_filter_uses_exact_match_without_wildcard():
    assert matches_text_filter("192.189.1.10", "192.189.1.10")
    assert not matches_text_filter("192.189.1.10", "192.189")


def test_matches_text_filter_supports_wildcard_patterns():
    assert matches_text_filter("192.189.1.10", "192.189.*")
    assert matches_text_filter("/api/v1/login", "/api/*/login")
    assert not matches_text_filter("192.188.1.10", "192.189.*")


def test_matches_text_filter_preserves_contains_mode_without_wildcard():
    assert matches_text_filter("/admin/login", "login", contains=True)
    assert not matches_text_filter("/admin/login", "logout", contains=True)


def test_matches_any_text_filter_applies_wildcard_to_individual_fields():
    assert matches_any_text_filter(["192.189.1.10", "scanner.example"], "192.189.*")
    assert matches_any_text_filter(["192.189.1.10", "scanner.example"], "scanner.*")
    assert not matches_any_text_filter(["192.188.1.10", "client.example"], "192.189.*")
