import socket

from sniffer.frame import EthernetFrame
from sniffer.packets import IPv4, Packet
from sniffer.pcap import PCAPWriter
from sniffer.segments.tcp import TCP


class Sniffer:
    def __init__(self, write_to_pcap=True):
        self.sock = socket.socket(socket.AF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.ntohs(0x0003))
        self.collected_packets = []

        self.write_to_pcap = write_to_pcap
        self.pcap_writer = PCAPWriter("traffic.pcap").open()

        self.is_end = False

    def start(self):
        try:
            self.sniff()
        except Exception as e:
            self.is_end = True
        finally:
            self.sock.close()

    def sniff(self):
        while not self.is_end:
            raw_bytes = self.sock.recvfrom(65565)[0]
            frame = EthernetFrame(raw_bytes)
            print(frame)

            if frame.ether_type == "IPv4":
                packet = IPv4(frame.data)
                print(packet)

                self.check_packet(raw_bytes, packet)

                if packet.protocol == 6:
                    segment = TCP(packet.data)
                    print(segment)
        self.close()

    def check_packet(self, raw_frame: bytes, packet: Packet):
        self.collected_packets.append(packet)
        if self.write_to_pcap:
            self.pcap_writer.dump_frame_to_pcap(raw_frame)

    def close(self):
        self.is_end = True
        self.pcap_writer.close()
