from ctypes import c_ubyte, c_uint16

from protocols import BaseProtocol


class Ethernet(BaseProtocol):      # IEEE 802.3 standard
    _fields_ = [
        ("mac_dst", c_ubyte * 6),  # Destination MAC address
        ("mac_src", c_ubyte * 6),  # Source MAC address
        ("eth_type", c_uint16)     # EtherType
    ]
    header_len = 14
    # The EtherType can be extended in future
    ether_types = {
        "0x0800": "IPv4",
        "0x0806": "ARP",
        "0x86dd": "IPv6"
    }

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.dest = self.addr_array_to_hdwr(self.mac_dst)
        self.source = self.addr_array_to_hdwr(self.mac_src)
        self.type = self.hex_format(self.eth_type, 6)
        # Get encapsulated protocol
        self.encapsulated_proto = self.ether_types.get(self.type, None)
