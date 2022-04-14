from ctypes import BigEndianStructure, create_string_buffer, sizeof


class BaseProtocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, packet):
        return cls.from_buffer_copy(packet)

    def __init__(self, *args):
        super().__init__()
        self.encapsulated_proto = None

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @staticmethod
    def addr_array_to_hdwr(address: str) -> str:
        """
        Converts a c_ubyte array of 6 bytes to IEEE 802 MAC address.
        Ex: From b"\xceP\x9a\xcc\x8c\x9d" to "ce:50:9a:cc:8c:9d"
        """
        return ":".join(format(octet, "02x") for octet in bytes(address))

    @staticmethod
    def hex_format(value: int, str_length: int) -> str:
        """
        Fills a hex value with zeroes to the left for compliance with
        the presentation of codes used in Internet protocols.
        Ex: From "0x800" to "0x0800"
        """
        return format(value, "#0{}x".format(str_length))

    @staticmethod
    def filter_int_value(value: int, **kwargs):
        """
        Filter the packet value based on the config file
        :param value: The packet value
        :param kwargs: configuration for that field
        :return: True if packet should be filtered out
        """
        support_operations = [("gt", '>'), ("lt", '<'), ("eq", '==')]
        for opr, sym in support_operations:
            filter_value = kwargs.get(opr, None)
            if isinstance(filter_value, int):
                if not eval(f"{value} {sym} {filter_value}"):
                    return True
        return False

    @staticmethod
    def filter_str_value(value: str, **kwargs):
        """
        Filter the packet value based on the config file
        :param value: The packet value
        :param kwargs: configuration for that field
        :return: True if packet should be filtered out
        """
        support_operations = [("contains", 'in'), ("eq", '==')]
        for opr, sym in support_operations:
            filter_value = kwargs.get(opr, None)
            if isinstance(filter_value, str):
                if not eval(f"'{value}' {sym} '{filter_value}'"):
                    return True
        support_operations = ["startswith", 'endswith']
        for func in support_operations:
            filter_value = kwargs.get(func, None)
            if isinstance(filter_value, str):
                if not eval(f"'{value}'.{func}('{filter_value}')"):
                    return True
        return False
