class EthernetFrame:
    ether_types = {
        '0800': 'IPv4',
    }

    def __init__(self, raw_bytes: bytes):
        self.destination_mac = self.format_mac(raw_bytes[0:6])
        self.source_mac = self.format_mac(raw_bytes[6:12])
        self.ether_type = self.ether_types.get(raw_bytes[12:14].hex())
        self.data = raw_bytes[14:]

    @staticmethod
    def format_mac(address: bytes) -> str:
        bytes_str = list(map('{:02x}'.format, address))
        return ':'.join(bytes_str).upper()

    def __str__(self):
        return "Source MAC: {}, Target MAC: {}, Protocol: {}".format(
            self.source_mac, self.destination_mac, self.ether_type
        )
