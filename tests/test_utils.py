import pytest
from sniffer.protocols.utils import Mac, IP


@pytest.mark.parametrize(
    "ip_arg, address, result",
    [
        (b"192.168.0.1", IP(b"192.168.0.1"), True),
        (b"192.168.0.1", IP(b"123123123123.168.0.1"), False),
        (b"\n\x00\x00\t", "10.0.0.9", True),
        (b"\n\x00\x00\t", "10.1.0.9", False),
    ],
)
def test_ip(ip_arg, address, result):
    actual = IP(ip_arg) == address
    print(IP(ip_arg))
    assert actual == result


@pytest.mark.parametrize(
    "mac_arg, address, result",
    [
        (b"A8:1E:84:8B:16:E2", Mac(b"A8:1E:84:8B:16:E2"), True),
        (b"A8:1E:dsadasda:8B:16:E2", Mac(b"A8:1E:84:8B:16:E2"), False),
        (b"\xa8\x1e\x84\x8b\x16\xe2", "A8:1E:84:8B:16:E2", True),
        (b"\xa8\x1e\x35\x8b\x16\xe2", "A8:1E:84:8B:16:E2", False),
    ],
)
def test_mac(mac_arg, address, result):
    actual = Mac(mac_arg) == address
    print(Mac(mac_arg))
    assert actual == result
