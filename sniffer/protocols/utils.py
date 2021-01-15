from dataclasses import dataclass


@dataclass
class Mac:
    raw_mac: bytes

    def __str__(self) -> str:
        bytes_str = list(map('{:02x}'.format, self.raw_mac))
        return ':'.join(bytes_str).upper()


@dataclass
class Ip:
    address: bytes

    def __str__(self) -> str:
        return '.'.join(map(str, self.address))
