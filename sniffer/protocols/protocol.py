from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List


# @dataclass
class Protocol(ABC):
    # childs: List["Protocol"] = field(default_factory=list)

    @classmethod
    @abstractmethod
    def from_bytes(cls, raw_bytes: bytes):
        pass

    @abstractmethod
    def __str__(self):
        return str(self.__dict__)
