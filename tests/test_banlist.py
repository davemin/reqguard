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


def test_banlist_add_many_and_remove_many(tmp_path):
    banlist = BanList(tmp_path / "bans.json")

    entries = banlist.add_many(
        [
            ("203.0.113.10", "scanner", None),
            ("198.51.100.2", "web scanner", (80, 443)),
        ]
    )

    assert [entry.ip for entry in entries] == ["203.0.113.10", "198.51.100.2"]
    assert set(banlist.load()) == {"203.0.113.10", "198.51.100.2"}
    assert banlist.load()["198.51.100.2"].ports == (80, 443)

    assert banlist.remove_many(["203.0.113.10", "192.0.2.1"]) == 1
    assert set(banlist.load()) == {"198.51.100.2"}
