from dataclasses import dataclass

from sniffer.protocols import Protocol, IPv4
from sniffer.protocols.utils import Mac


@dataclass
class EthernetFrame(Protocol):
    destination_mac: Mac
    source_mac: Mac
    ether_type: str
    data: bytes
    ether_types = {
        "0800": "IPv4",
    }

    def __post_init__(self):
        if self.ether_type == "IPv4":
            self.ip = IPv4.from_bytes(self.data)

    @classmethod
    def from_bytes(cls, raw_bytes: bytes):
        destination_mac = Mac(raw_bytes[0:6])
        source_mac = Mac(raw_bytes[6:12])
        ether_type = cls.ether_types.get(raw_bytes[12:14].hex())
        data = raw_bytes[14:]
        return cls(destination_mac, source_mac, ether_type, data)

    @staticmethod
    def format_mac(address: bytes) -> str:
        bytes_str = list(map("{:02x}".format, address))
        return ":".join(bytes_str).upper()

    def __str__(self):
        return "Source MAC: {}, Target MAC: {}, Protocol: {}\n{}".format(
            self.source_mac, self.destination_mac, self.ether_type, self.ip
        )
