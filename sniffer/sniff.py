import logging
import socket

from sniffer.frame import EthernetFrame
from sniffer.packets import IPv4
from sniffer.segments.tcp import TCP


logger = logging.getLogger(__name__)


class Sniffer:
    def __init__(self, count_of_packets=10):
        self.sock = socket.socket(socket.AF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.ntohs(0x0003))
        self.raw_packets = []
        self.count_of_packets = count_of_packets

        self.is_end = False
        logger.debug("Sniffer was initialized")

    def start(self):
        logger.debug("sniffer was started")
        try:
            self.sniff()
        except Exception as e:
            logger.error("Fuck! Something went wrong", e)
        finally:
            self.close()

    def sniff(self):
        while not self.is_end and len(self.raw_packets) < self.count_of_packets:
            raw_frame: bytes = self.sock.recvfrom(65565)[0]
            self.raw_packets.append(raw_frame)
            frame = EthernetFrame(raw_frame)
            logger.info(frame)

            if frame.ether_type == "IPv4":
                packet = IPv4(frame.data)
                logger.info(packet)

                if packet.protocol == 6:
                    segment = TCP(packet.data)
                    logger.info(segment)
        self.close()

    def close(self):
        self.is_end = True
        self.sock.close()
        logger.debug("Sniffer was closed")
