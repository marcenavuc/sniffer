from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument(
    "--nopcap", "-np", help="don't save pcap file", action="store_false"
)
parser.add_argument(
    "--count", help="how many packets should be collected", default=10, type=int
)
parser.add_argument(
    "--file", "-f", help="set path to pcap file", default="sniffer.pcap"
)
parser.add_argument("--noudp", "-nu", help="exclude udp", action="store_false")
parser.add_argument("--notcp", "-", help="exclude tcp", action="store_false")
parser.add_argument(
    "--macs", "-m", help="include only this mac address", default=[], nargs="+"
)
parser.add_argument(
    "--ips", "-i", help="include only this ip address", default=[], nargs="+"
)
parser.add_argument(
    "--validate",
    "-v",
    action="store_true",
    help="if it's set, sniffer will validate packets",
)
