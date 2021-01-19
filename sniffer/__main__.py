import logging
import threading
import concurrent.futures
import sys
import os
from queue import Queue

from sniffer import Sniffer
from sniffer import parser
from sniffer import PCAPWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s ",
    handlers=[
        logging.FileHandler(os.path.abspath("debug.txt")),
        logging.StreamHandler(sys.stdout),
    ],
)

args = parser.parse_args()
event = threading.Event()
packets_queue = Queue()

sniffer = Sniffer(
    count_of_packets=args.count,
    ips=args.ips,
    macs=args.macs,
    tcp=args.notcp,
    udp=args.noudp,
    validate_packets=args.validate,
)

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    executor.submit(sniffer.thread_start, packets_queue, event)
    if not args.nopcap:
        pcap_writer = PCAPWriter(args.file)
        executor.submit(pcap_writer.dump_frame_to_pcap, packets_queue, event)
    event.set()
