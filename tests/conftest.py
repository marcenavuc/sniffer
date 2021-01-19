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
def fake_recv():
    return b'\xe0\x91\xf5\xcd\xf1.\xa8\x1e\x84\x8b\x16\xe2\x08\x00E\x00\x004' \
           b'\x9f\xf6@\x00@\x06\xc9\\\n\x00\x00\t\xb2\xed\x14{' \
           b'\xa7\xaa\x01\xbb\x1c\x02v\r\xbc\xa1\xfc\xc7\x80\x10\x01\xf5\xd1' \
           b'\x97\x00\x00\x01\x01\x08\n<\xb3\x02\xb8\x90&\x1aN '

