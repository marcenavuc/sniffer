import struct
import hexdump


class TCP:
    """
    https://ru.wikipedia.org/wiki/Transmission_Control_Protocol
    """

    def __init__(self, raw_segment: bytes):
        self.source_port, self.target_port, self.sequence_number, \
        self.acknowledgement_number = struct.unpack('!HHLL', raw_segment[:12])
        flags = raw_segment[14]
        self.urg = (flags & 32) >> 5
        self.ack = (flags & 16) >> 4
        self.psh = (flags & 8) >> 3
        self.rst = (flags & 4) >> 2
        self.syn = (flags & 2) >> 1
        self.fin = (flags & 1)
        self.window_size = int.from_bytes(raw_segment[14:16], byteorder='big')
        self.urg_pointer = int.from_bytes(raw_segment[18:20], byteorder='big')
        self.data = hexdump.hexdump(raw_segment[24:], 'return')

    def __str__(self):
        return 'TCP Segment: Source port: {} Target port: {} Sequence: {} ' \
               'Acknowledgement: {} Flags: URG: {} ACK: {} PSH: {} RST: {} ' \
               'SYN: {} FIN: {} Window size: {} URG pointer: {} \nData: \n{}' \
            .format(
            self.source_port, self.target_port, self.sequence_number,
            self.acknowledgement_number, self.urg, self.ack, self.psh,
            self.rst, self.syn, self.fin, self.window_size, self.urg_pointer,
            self.data
        )
