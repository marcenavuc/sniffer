from sniffer.protocols.tcp import TCP
from sniffer.protocols.frame import EthernetFrame
from sniffer.protocols.ipv4 import IPv4


def test_tcp():
    tcp = TCP.from_bytes(b'\xcfz\x01\xbb+\t:?\xb78\\k\x83\xb78[\x16\xd2xb78['
                         b'\x16\x88\x01\x03\x01\x01\x05\n\xb78[\x16\xb78\\k')
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


def test_frame(fake_recv):
    frame = EthernetFrame.from_bytes(fake_recv)
    print(frame)
    assert 'A8:1E:84:8B:16:E2' == frame.source_mac
    assert 'E0:91:F5:CD:F1:2E' == frame.destination_mac
    assert 'IPv4' == frame.ether_type


def test_ipv4():
    packet = IPv4.from_bytes(
        b'E\x00\x004\x04;@\x007\x06Q\xceW\xf0\x8b\xc2\n\x00\x00\t\x01\xbb\x99'
        b'\xf8\xb0\xe8X\xaf\xd3('
        b'M\x8c\x80\x10\x00@x\xac\x00\x00\x01\x01\x08\n}T\x8f\xf7\xea\x97R1 '
    )
    assert packet.version == 4
    assert packet.header_len == 20
    assert packet.target_ip == "10.0.0.9"
    assert packet.source_ip == "87.240.139.194"
