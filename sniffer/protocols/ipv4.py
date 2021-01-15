import struct
from dataclasses import dataclass

from sniffer.protocols import Protocol, TCP, UDP


@dataclass
class IPv4(Protocol):
    version: int
    header_len: int
    packet_size: int
    id: int
    flags: int
    offset: int
    time_to_live: int
    protocol: int
    source_ip: str
    target_ip: str
    data: bytes

    def __post_init__(self):
        if self.protocol == 6:
            self.segment = TCP.from_bytes(self.data)
        if self.protocol == 17:
            self.segment = UDP.from_bytes(self.data)

    @classmethod
    def from_bytes(cls, raw_bytes: bytes):
        version_header_len = raw_bytes[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        packet_size = int.from_bytes(raw_bytes[2:4], byteorder='big')
        id = int.from_bytes(raw_bytes[4:6], byteorder='big')
        flags_offset = int.from_bytes(raw_bytes[6:8], byteorder='big')
        flags = flags_offset >> 13
        offset = (flags_offset & 127) * 3
        time_to_live, protocol = struct.unpack('!BB', raw_bytes[8:10])
        source_ip = cls.ipv4(raw_bytes[12:16])
        target_ip = cls.ipv4(raw_bytes[16:20])
        data = raw_bytes[header_len:]
        return cls(version, header_len, packet_size, id, flags, offset,
                   time_to_live, protocol, source_ip, target_ip, data)

    @staticmethod
    def ipv4(address: bytes) -> str:
        return '.'.join(map(str, address))

    def __str__(self):
        return "IPv4 Packet: Header_lenght: {}, Protocol: {}, Target: {}, " \
               "Source: {}\n{}".format(
            self.header_len, self.protocol, self.target_ip, self.source_ip,
            self.segment
        )
