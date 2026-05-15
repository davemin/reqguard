from reqguard.procnet import parse_address, parse_ipv4, parse_ipv6


def test_parse_ipv4_proc_format():
    assert parse_ipv4("0100007F") == "127.0.0.1"
    assert parse_address("3500007F:1F90", ipv6=False) == ("127.0.0.53", 8080)


def test_parse_ipv6_proc_format():
    assert parse_ipv6("00000000000000000000000001000000") == "::1"

