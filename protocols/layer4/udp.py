from ctypes import c_uint16

from protocols import BaseProtocol


class UDP(BaseProtocol):      # IETF RFC 768
    _fields_ = [
        ("sport", c_uint16),  # Source port
        ("dport", c_uint16),  # Destination port
        ("len", c_uint16),    # Header length
        ("chksum", c_uint16)  # Header checksum
    ]
    header_len = 8

    def __init__(self, packet: bytes):
        super().__init__(packet)
