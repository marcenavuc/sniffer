from unittest import mock


def test_dump_frame(pcap_writer):

    with mock.patch("time.time", lambda: 0):
        pcap_writer.dump_frame_to_pcap(
            b".\xf3F\x89\xff\x19\xac\x84\xc6\x94\xbd\xdc\x08\x00Ep\x00("
            b"\xb5\xbb@\x005\x06;\xe5\xb2\x8d\xe0$\xc0\xa8\x00e@\x9e\xcf"
            b"\x13\xc5\xca\x86\xda\x1a\xe6\xff\x8cP\x10\xff\xff\xe5J\x00"
        )
        pcap_writer.close()
        with open("test.pcap", "rb") as file:
            assert (
                file.read().hex() == "d4c3b2a1020004005046000000000000ffff"
                "000001000000000000000000000035000000350000002ef34689ff19"
                "ac84c694bddc080045700028b5bb400035063be5b28de024c0a80065"
                "409ecf13c5ca86da1ae6ff8c5010ffffe54a00"
            )
