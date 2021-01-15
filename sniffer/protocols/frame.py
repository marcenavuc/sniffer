from dataclasses import dataclass

from sniffer.protocols import Protocol


@dataclass
class EthernetFrame(Protocol):
    destination_mac: str
    source_mac: str
    ether_type: str
    data: bytes
    ether_types = {
        '0800': 'IPv4',
    }

    @classmethod
    def from_bytes(cls, raw_bytes: bytes):
        destination_mac = cls.format_mac(raw_bytes[0:6])
        source_mac = cls.format_mac(raw_bytes[6:12])
        ether_type = cls.ether_types.get(raw_bytes[12:14].hex())
        data = raw_bytes[14:]
        return cls(destination_mac, source_mac, ether_type, data)

    @staticmethod
    def format_mac(address: bytes) -> str:
        bytes_str = list(map('{:02x}'.format, address))
        return ':'.join(bytes_str).upper()

    def __str__(self):
        return "Source MAC: {}, Target MAC: {}, Protocol: {}".format(
            self.source_mac, self.destination_mac, self.ether_type
        )
