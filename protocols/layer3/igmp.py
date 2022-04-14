from ctypes import c_ubyte, c_uint8, c_uint16

from protocols import BaseProtocol


class IGMP(BaseProtocol):               # IETF RFC 1112
    _fields_ = [
        ("type", c_uint8),              # IGMP message type
        ("max_res_time", c_uint8),      # Max Respond Time
        ("chksum", c_uint16),           # Header checksum
        ("grp_addr", c_ubyte * 4)       # Group Address
    ]
    header_len = 8
    igmp_types = {
        "0x11": "Membership Query",
        "0x12": "IGMPv1 Membership Report",
        "0x16": "IGMPv2 Membership Report",
        "0x22": "IGMPv3 Membership Report",
        "0x17": "Leave Group"
    }

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.igmp_type = self.hex_format(self.type, 4)
        # Get gcmp type
        self.type_txt = self.icmp_types.get(self.igmp_type, None)
