import logging
import socket
from queue import Queue
from threading import Event

from sniffer.protocols import EthernetFrame, IPv4, TCP, UDP

logger = logging.getLogger(__name__)


class Sniffer:
    def __init__(
        self,
        count_of_packets=10,
        udp=True,
        tcp=True,
        ips=[],
        macs=[],
        validate_packets=False,
    ):
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
        )
        self.validate_packets = validate_packets
        self.udp = udp
        self.tcp = tcp
        self.ips = ips
        self.macs = macs
        self.raw_packets = Queue()
        self.count_of_packets = count_of_packets
        self.is_end = False
        logger.debug("Sniffer was initialized")

    def thread_start(self, packets: Queue, event: Event):
        while not event.is_set():
            self.start(packets)

    def start(self, packets: Queue = None):
        logger.debug("sniffer was started")
        try:
            while not self.is_end \
                    and self.raw_packets.qsize() < self.count_of_packets:
                result = self.sniff()
                if result and packets:
                    packets.put(result[0])
            self.close()
        except KeyboardInterrupt:
            logger.info("Closing sniffer")
        except Exception as e:
            logger.error("Something went wrong", e)
        finally:
            self.close()

    def sniff(self):
        raw_frame: bytes = self.sock.recv(65565)
        packet = EthernetFrame.from_bytes(raw_frame)
        if self.validate_packets and not self.validate_check_sum(packet):
            logger.info("This packet is corrupted")
        if self.filter_packet(packet):
            logger.info(packet)
            self.raw_packets.put(raw_frame)
            return raw_frame, packet

    def filter_packet(self, packet: EthernetFrame):
        if packet.source_mac in self.macs \
                or packet.destination_mac in self.macs:
            return True
        ipv4: IPv4 = packet.ip
        if ipv4.source_ip in self.ips or ipv4.target_ip in self.ips:
            return True
        segment = ipv4.segment
        return (
            self.tcp
            and isinstance(segment, TCP)
            or self.udp
            and isinstance(segment, UDP)
        )

    @staticmethod
    def validate_check_sum(packet: EthernetFrame):
        return packet.ip.is_valid and packet.ip.segment.is_valid

    def close(self):
        self.is_end = True
        self.sock.close()
        logger.debug("Sniffer was closed")
