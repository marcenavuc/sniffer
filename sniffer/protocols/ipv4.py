import struct


class IPv4:

    def __init__(self, raw_packet: bytes):
        version_header_len = raw_packet[0]
        self.version = version_header_len >> 4
        self.header_len = (version_header_len & 15) * 4
        self.packet_size = int.from_bytes(raw_packet[2:4], byteorder='big')
        self.id = int.from_bytes(raw_packet[4:6], byteorder='big')
        flags_offset = int.from_bytes(raw_packet[6:8], byteorder='big')
        self.flags = flags_offset >> 13
        self.offset = (flags_offset & 127) * 3
        self.time_to_live, self.protocol = struct.unpack('! B B', raw_packet[8:10])
        self.source_ip = self.ipv4(raw_packet[12:16])
        self.target_ip = self.ipv4(raw_packet[16:20])
        self.data = raw_packet[self.header_len:]

    @staticmethod
    def ipv4(address: bytes) -> str:
        return '.'.join(map(str, address))

    def __str__(self):
        return "IPv4 Packet: Header_lenght: {}, Protocol: {}, Target: {}, " \
               "Source: {}".format(
            self.header_len, self.protocol, self.target_ip, self.source_ip
        )
