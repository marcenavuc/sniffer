from sniffer.protocols.tcp import TCP
from sniffer.protocols.frame import EthernetFrame
from sniffer.protocols.ipv4 import IPv4


def test_tcp():
    tcp = TCP(b'\xcfz\x01\xbb+\t:?\xb78\\k\x83\xb78[\x16\xd2xb78[\x16\x88\x01'
              b'\x03\x01\x01\x05\n\xb78[\x16\xb78\\k'
              )
    assert 53114 == tcp.source_port
    assert 443 == tcp.target_port
    assert 722025023 == tcp.sequence_number
    assert 3073924203 == tcp.acknowledgement_number
    assert 1 == tcp.urg
    assert 1 == tcp.ack
    assert 1 == tcp.psh
    assert 0 == tcp.rst
    assert 0 == tcp.syn
    assert 0 == tcp.fin
    assert 14427 == tcp.window_size
    assert 30818 == tcp.urg_pointer


def test_frame():
    frame = EthernetFrame(
        b'\n\xfb\xecX\xb7_\xa4\xca\xa0}\xa6}\x08\x00E\x00\x00(\xab\x7f@'
        b'\x004\x06o\xce]'
    )
    assert 'A4:CA:A0:7D:A6:7D' == frame.source_mac
    assert '0A:FB:EC:58:B7:5F' == frame.destination_mac
    assert 'IPv4' == frame.ether_type
    assert '45000028ab7f400034066fce5d' == frame.data.hex()


def test_ipv4():
    packet = IPv4(
        b'E(\x00(\x88\x1e@\x00:\x06\x1e\tW\xf0\x81\x83\xc0\xa8\x00e\x01'
        b'\xbb\xfd\xad\x9c\x8a@\xddD\x05'
    )
    assert packet.version == 4
    assert packet.header_len == 20
    assert packet.id == 34846
    assert packet.flags == 2
    assert packet.offset == 0
    assert packet.time_to_live == 58
    assert packet.protocol == 6
    assert packet.target_ip == '192.168.0.101'
    assert packet.source_ip == '87.240.129.131'
    assert packet.data.hex() == '01bbfdad9c8a40dd4405'
