from ctypes import c_uint16, c_uint32

from protocols import BaseProtocol


class TCP(BaseProtocol):            # IETF RFC 793
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("seq", c_uint32),          # Sequence number
        ("ack", c_uint32),          # Acknowledgement number
        ("offset", c_uint16, 4),    # Data offset
        ("reserved", c_uint16, 3),  # Reserved field
        ("flags", c_uint16, 9),     # TCP flag codes
        ("window", c_uint16),       # Size of the receive window
        ("chksum", c_uint16),       # TCP header checksum
        ("urg", c_uint16),          # Urgent pointer
    ]
    header_len = 32

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.flag_hex = self.hex_format(self.flags, 5)
        self.flag_txt = self.translate_flags()

    def translate_flags(self):
        f_names = ["NS", "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"]
        f_bits = format(self.flags, "09b")
        return " ".join(f_names[idx] for idx, v in enumerate(f_bits) if v == "1")

    def filter_sport(self, config: dict):
        return self.filter_int_value(self.sport, **config)

    def filter_dport(self, config: dict):
        return self.filter_int_value(self.dport, **config)
