import logging
import socket
from queue import Queue
from threading import Event

from sniffer.protocols import EthernetFrame

logger = logging.getLogger(__name__)


class Sniffer:
    def __init__(self, count_of_packets=10, udp=True, tcp=True,
                 ips=[], macs=[]):
        self.sock = socket.socket(socket.AF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.ntohs(0x0003))
        self.raw_packets = Queue()
        self.count_of_packets = count_of_packets
        self.is_end = False
        logger.debug("Sniffer was initialized")

    def thread_start(self, packets: Queue, event: Event):
        while not event.is_set():
            self.start(packets)

    def start(self, packets: Queue):
        logger.debug("sniffer was started")
        try:
            while not self.is_end and self.raw_packets.qsize() < self.count_of_packets:
                packets.put(self.sniff()[0])
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
        logger.info(packet)
        self.raw_packets.put(raw_frame)
        return raw_frame, packet

    def close(self):
        self.is_end = True
        self.sock.close()
        logger.debug("Sniffer was closed")
