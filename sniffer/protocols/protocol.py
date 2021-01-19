from abc import ABC, abstractmethod


class Protocol(ABC):
    @classmethod
    @abstractmethod
    def from_bytes(cls, raw_bytes: bytes):
        pass

    @abstractmethod
    def __str__(self):
        return str(self.__dict__)

    @staticmethod
    def get_checksum(msg: bytes) -> int:
        checksum = 0
        for i in range(0, len(msg), 2):
            part = (msg[i] << 8) + (msg[i + 1])
            checksum += part
        checksum = (checksum >> 16) + (checksum & 0xFFFF)

        return checksum ^ 0xFFFF
