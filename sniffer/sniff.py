import logging
import socket
import asyncio
from queue import Queue

from sniffer.protocols import EthernetFrame
from sniffer.protocols import IPv4
from sniffer.protocols import TCP
from sniffer.protocols import UDP

logger = logging.getLogger(__name__)


class Sniffer:
    def __init__(self, count_of_packets=10, udp=True, tcp=True, ip=True,
                 ips=[], macs=[]):
        self.sock = socket.socket(socket.AF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.ntohs(0x0003))
        self.raw_packets = Queue()
        self.count_of_packets = count_of_packets
        self.loop = asyncio.get_event_loop()
        self.is_end = False
        logger.debug("Sniffer was initialized")

    def start(self):
        logger.debug("sniffer was started")
        try:
            self.loop.run_until_complete(self.sniff())
        except Exception as e:
            logger.error("Something went wrong", e)
        finally:
            self.close()

    async def sniff(self):
        while not self.is_end and self.raw_packets.qsize() < self.count_of_packets:
            raw_frame: bytes = await self.loop.sock_recv(self.sock, 65565)
            self.raw_packets.put(raw_frame)
            frame = EthernetFrame.from_bytes(raw_frame)
            logger.info(frame)

            if frame.ether_type == "IPv4":
                packet = IPv4.from_bytes(frame.data)
                logger.info(packet)

                if packet.protocol == 6:
                    segment = TCP.from_bytes(packet.data)
                if packet.protocol == 17:
                    segment = UDP.from_bytes(packet.data)
                logger.info(segment)
        self.close()

    def close(self):
        self.is_end = True
        self.sock.close()
        logger.debug("Sniffer was closed")
