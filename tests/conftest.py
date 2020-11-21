from pytest import fixture
from sniffer import PCAPWriter
import os


@fixture(scope="session")
def pcap_writer():
    pcap_wr = PCAPWriter("test.pcap").open()
    yield pcap_wr
    pcap_wr.close()
    os.remove("test.pcap")


@fixture(scope="session")
def fake_recvfrom():
    return (b'5\x827\xe7\x8f\15T\x92XO&\x10\x07\xb4\x1c\xfbW\xaa\xb7;' \
           b'\x84<>\x8d\xc8\xed>\x0e\xd4\xdc\xd1\xd3\xa6k\xc9\xeb2\xd98' \
           b'\xc9\xc2\xb8w\x82V\xc2\x94\xf3\x12\x08\x12*N', None)
