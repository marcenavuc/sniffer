import struct
from dataclasses import dataclass

import hexdump

from sniffer.protocols import Protocol


@dataclass
class UDP(Protocol):
    source_port: int
    target_port: int
    size: int
    data: str
    raw: bytes

    @classmethod
    def from_bytes(cls, raw_bytes: bytes):
        source_port, target_port, size = struct.unpack("!HHH", raw_bytes[:6])
        data = hexdump.hexdump(raw_bytes[8:], "return")
        raw = raw_bytes
        return cls(source_port, target_port, size, data, raw)

    def __str__(self):
        return "Source: {}, Target: {}, Size: {},\nData: {}".format(
            self.source_port, self.target_port, self.size, self.data
        )

    @property
    def is_valid(self):
        bytes_packet = self.raw
        if len(self.raw) % 2 != 0:
            bytes_packet += b"\x00"
        return not self.get_checksum(bytes_packet)
