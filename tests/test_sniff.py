from queue import Queue
from unittest import mock
from sniffer import Sniffer


def test_sniff(fake_recv):
    with mock.patch("socket.socket") as fake_socket:
        fake_socket.return_value.recv.return_value = fake_recv
        sniffer = Sniffer(count_of_packets=1, validate_packets=True)
        sniffer.start()

        assert sniffer.raw_packets.get() == fake_recv
