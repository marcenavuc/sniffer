import logging
import sys

from sniffer import Sniffer
from sniffer import parser
from sniffer import PCAPWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s ",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler(sys.stdout),
    ]
)

args = parser.parse_args().__dict__

sniffer = Sniffer(count_of_packets=args.get("count"))
sniffer.start()
if args.get("p"):
    with PCAPWriter("sniffer.pcap") as pcap_writer:
        for raw_frame in sniffer.raw_packets:
            pcap_writer.dump_frame_to_pcap(raw_frame)
