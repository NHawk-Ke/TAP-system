from ctypes import c_ubyte, c_uint8, c_uint16, c_uint32
from socket import inet_ntop, AF_INET, AF_INET6

from protocols import BaseProtocol


class IPv4(BaseProtocol):          # IETF RFC 791
    _fields_ = [
        ("version", c_uint8, 4),   # Protocol version
        ("ihl", c_uint8, 4),       # Internet header length
        ("dscp", c_uint8, 6),      # Differentiated services code point
        ("ecn", c_uint8, 2),       # Explicit congestion notification
        ("len", c_uint16),         # Total packet length
        ("id", c_uint16),          # Identification
        ("flags", c_uint16, 3),    # Fragmentation control flags
        ("offset", c_uint16, 13),  # Fragment offset
        ("ttl", c_uint8),          # Time to live
        ("proto", c_uint8),        # Encapsulated protocol
        ("chksum", c_uint16),      # Header checksum
        ("src", c_ubyte * 4),      # Source address
        ("dst", c_ubyte * 4)       # Destination address
    ]
    header_len = 20
    # The proto_types can be extended in future
    proto_types = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP"
    }
    dscp_types = {
        48: "CS6",
        46: "EF",
        40: "CS5",
        34: "AF41",
        36: "AF42",
        38: "AF43",
        32: "CS4",
        26: "AF31",
        28: "AF32",
        30: "AF33",
        24: "CS3",
        18: "AF21",
        20: "AF22",
        22: "AF23",
        16: "CS2",
        10: "AF11",
        12: "AF12",
        14: "AF13",
        0: "DF",
        8: "CS1"
    }

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.source = inet_ntop(AF_INET, self.src)
        self.dest = inet_ntop(AF_INET, self.dst)
        # Get encapsulated protocol
        self.encapsulated_proto = self.proto_types.get(self.proto, None)
        self.dscp_name = self.dscp_types.get(self.dscp, f"Unknown({self.dscp})")

    def filter_src(self, config: dict):
        return self.filter_str_value(self.source, **config)

    def filter_dst(self, config: dict):
        return self.filter_str_value(self.dest, **config)


class IPv6(BaseProtocol):           # IETF RFC 2460 / 8200
    _fields_ = [
        ("version", c_uint32, 4),   # Protocol version
        ("tclass", c_uint32, 8),    # Traffic class
        ("flabel", c_uint32, 20),   # Flow label
        ("payload_len", c_uint16),  # Payload length
        ("next_header", c_uint8),   # Type of next header
        ("hop_limit", c_uint8),     # Hop limit (replaces IPv4 TTL)
        ("src", c_ubyte * 16),      # Source address
        ("dst", c_ubyte * 16)       # Destination address
    ]
    header_len = 40

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.source = inet_ntop(AF_INET6, self.src)
        self.dest = inet_ntop(AF_INET6, self.dst)
