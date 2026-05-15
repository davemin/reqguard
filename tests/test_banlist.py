from reqguard.banlist import BanList


def test_add_and_remove_ban(tmp_path):
    banlist = BanList(tmp_path / "bans.json")

    entry = banlist.add("203.0.113.10", "test")

    assert entry.ip == "203.0.113.10"
    assert banlist.contains("203.0.113.10")
    assert banlist.load()["203.0.113.10"].reason == "test"
    assert banlist.remove("203.0.113.10") is True
    assert banlist.contains("203.0.113.10") is False


def test_banlist_persists_port_scoped_bans(tmp_path):
    banlist = BanList(tmp_path / "bans.json")

    entry = banlist.add("203.0.113.10", "web", ports=(80, 443))

    assert entry.ports == (80, 443)
    assert banlist.load()["203.0.113.10"].ports == (80, 443)
