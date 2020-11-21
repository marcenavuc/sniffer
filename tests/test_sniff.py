from unittest import mock
from sniffer import Sniffer


def test_sniff(fake_recvfrom):
    with mock.patch("socket.socket") as fake_socket:
        fake_socket.return_value.recvfrom.return_value = fake_recvfrom

        sniffer = Sniffer(count_of_packets=1)
        sniffer.start()

        assert sniffer.raw_packets[0] == fake_recvfrom[0]

