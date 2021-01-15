from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-p", help="don't save pcap file", action="store_false")
parser.add_argument("-v", help="print traffic", action="store_true")
parser.add_argument("--count", help="how many packets should be collected",
                    default=10, type=int)
