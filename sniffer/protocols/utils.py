from dataclasses import dataclass


@dataclass
class Mac:
    raw_mac: bytes

    def __str__(self) -> str:
        bytes_str = list(map("{:02x}".format, self.raw_mac))
        return ":".join(bytes_str).upper()

    def __eq__(self, other):
        if isinstance(other, Mac):
            return self.raw_mac == other.raw_mac
        return self.__str__() == other


@dataclass
class IP:
    address: bytes

    def __str__(self) -> str:
        return ".".join(map(str, self.address))

    def __eq__(self, other):
        if isinstance(other, IP):
            return self.address == other.address
        return self.__str__() == other
