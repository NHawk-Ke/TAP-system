from ctypes import c_ubyte, c_uint8, c_uint16

from protocols import BaseProtocol


class ICMP(BaseProtocol):       # IETF RFC 792
    _fields_ = [
        ("type", c_uint8),      # Control message type
        ("code", c_uint8),      # Control message subtype
        ("chksum", c_uint16),   # Header checksum
        ("rest", c_ubyte * 4)   # Rest of header (contents vary)
    ]
    header_len = 8
    # The icmp_types can be extended in future
    icmp_types = {
        0: "REPLY",
        8: "REQUEST"
    }

    def __init__(self, packet: bytes):
        super().__init__(packet)
        # Get icmp type
        self.type_txt = self.icmp_types.get(self.type, None)
