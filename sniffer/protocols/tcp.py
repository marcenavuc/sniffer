import struct
from dataclasses import dataclass

import hexdump

from sniffer.protocols import Protocol


@dataclass
class TCP(Protocol):
    source_port: int
    target_port: int
    sequence_number: int
    acknowledgement_number: int
    urg: int
    ack: int
    psh: int
    rst: int
    syn: int
    fin: int
    window_size: int
    urg_pointer: int
    data: str
    raw: bytes

    @classmethod
    def from_bytes(cls, raw_segment: bytes):
        (
            source_port,
            target_port,
            sequence_number,
            acknowledgement_number,
        ) = struct.unpack("!HHLL", raw_segment[:12])
        flags = raw_segment[14]
        urg = (flags & 32) >> 5
        ack = (flags & 16) >> 4
        psh = (flags & 8) >> 3
        rst = (flags & 4) >> 2
        syn = (flags & 2) >> 1
        fin = flags & 1
        window_size = int.from_bytes(raw_segment[14:16], byteorder="big")
        urg_pointer = int.from_bytes(raw_segment[18:20], byteorder="big")
        data = hexdump.hexdump(raw_segment[24:], "return")
        raw = raw_segment
        return cls(
            source_port,
            target_port,
            sequence_number,
            acknowledgement_number,
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
            window_size,
            urg_pointer,
            data,
            raw,
        )

    def __str__(self):
        return (
            "TCP Segment: Source port: {} Target port: {} Sequence: {} "
            "Acknowledgement: {} Flags: URG: {} ACK: {} PSH: {} RST: {} "
            "SYN: {} FIN: {} Window size: {} URG pointer: {}"
            "\nData: \n{}".format(
                self.source_port,
                self.target_port,
                self.sequence_number,
                self.acknowledgement_number,
                self.urg,
                self.ack,
                self.psh,
                self.rst,
                self.syn,
                self.fin,
                self.window_size,
                self.urg_pointer,
                self.data,
            )
        )

    @property
    def is_valid(self):
        bytes_packet = self.raw
        if len(self.raw) % 2 != 0:
            bytes_packet += b"\x00"
        return not self.get_checksum(bytes_packet)
