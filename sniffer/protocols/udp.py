import struct

import hexdump


class UDP:

    def __init__(self, raw_segment: bytes):
        self.source_port, self.target_port, self.size = struct.unpack(
            "!HHH", raw_segment[:6]
        )
        self.data = hexdump.hexdump(raw_segment[8:], "return")

    def __str__(self):
        return "Source: {}, Target: {}, Size: {},\nData: {}".format(
            self.source_port, self.target_port, self.size, self.data
        )
