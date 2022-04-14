import time
import sys
from abc import ABC, abstractmethod


class OutputMethod(ABC):
    """
    Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the PacketSniffer class.
    """

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass


class OutputToScreen(OutputMethod):
    def __init__(self, subject, output_file=None):
        super().__init__(subject)
        self.packet = None
        self.formatter = subject.formatter
        self.publisher = subject.publisher
        self.info_log = ""
        self.file = output_file if output_file else sys.stdout
        self.packet_status_format = "TCP : {TCP}   UDP : {UDP}   "
        self.packet_status_format += "ICMP : {ICMP}   IGMP : {IGMP}   "
        self.packet_status_format += "Others : {others}   Total : {total}\r"
        self.packet_type_count = {
            "ICMP": 0,
            "IGMP": 0,
            "TCP": 0,
            "UDP": 0,
            "others": 0,
            "total": 0
        }

    def update(self, packet):
        self.packet = packet
        self.packet_type_count["total"] += 1
        if not self._filter_packet():
            self._display_output_header()
            self._display_packet_info()
            if self.formatter.display_data:
                self._display_packet_raw_data()
            self._publish()
        self._display_capture_status()

    def _filter_packet(self):
        """
        Filter the packet based on the configuration file
        :return: True if the packet is filtered out
        """
        for proto in self.packet.protocol_queue:
            config = self.formatter.proto_filter_cfg[proto.lower()]
            for field, field_cfg in config.items():
                if getattr(getattr(self.packet, proto.lower()), f"filter_{field}",
                           lambda _: False)(field_cfg):
                    return True
        return False

    def _display_output_header(self):
        local_time = time.strftime("%H:%M:%S", time.localtime())
        self._append_output(f"[>] Packet #{self.packet.packet_num} at {local_time}:\n")

    def _display_packet_info(self):
        self._append_output("{0}{1:*>26} {2:*<31}\n".format(
            self.formatter.indent, self.packet.protocol_queue[-1], "Packet"
        ))
        for proto in self.packet.protocol_queue:
            getattr(self, f"_display_{proto.lower()}_data", lambda: None)()

    def _display_packet_raw_data(self):
        self._append_output("{: >38}\n".format("Data Dump:"))
        start = 0
        for proto in self.packet.protocol_queue:
            self._append_output(f"{self.formatter.indent}{proto} Header:\n")
            proto_header = getattr(self.packet, proto.lower(), None)
            if proto_header:
                header_len = getattr(proto_header, "header_len", 0)
                self._display_packet_contents(start, header_len)
                start += header_len
            else:
                break
        self._append_output(f"{self.formatter.indent}Data Payload:\n")
        self._display_packet_contents(start)

    def _display_packet_contents(self, start, length=None):
        if length:
            process_data = self.packet.data[start:start+length]
        elif length is None:
            process_data = self.packet.data[start:]
        else:
            return
        data = ''
        tmp = ''
        for i, c in enumerate(process_data):
            if i != 0 and i % 16 == 0:
                data += f"{self.formatter.indent * 2}{tmp}\n"
                tmp = ""

            if 32 <= c <= 128:
                tmp += chr(c)
            else:
                tmp += '.'

            if i % 16 == 0:
                data += f"   {self.formatter.indent}"
            data += " {:02X}".format(c)

            if i == len(process_data) - 1:
                data += "   " * (15 - i % 16) + f"{self.formatter.indent * 2}{tmp}"
        self._append_output(data + '\n')

    def _display_capture_status(self):
        print(self.packet_status_format.format(**self.packet_type_count), end="")

    def _append_output(self, content):
        self.info_log += content

    def _publish(self):
        # print(self.info_log, file=self.file)
        self.publisher.publish_packet(self.info_log)
        self.info_log = ''

    def _display_arp_data(self):
        self._append_output(self.formatter.display_msg['arp'].format(
            **{
                "htype": self.packet.arp.htype,
                "protocol": self.packet.arp.protocol,
                "hlen": self.packet.arp.hlen,
                "plen": self.packet.arp.plen,
                "oper": self.packet.arp.oper,
                "source_hdwr": self.packet.arp.source_hdwr,
                "target_hdwr": self.packet.arp.target_hdwr,
                "source_proto": self.packet.arp.source_proto,
                "target_proto": self.packet.arp.target_proto
            })
        )

    def _display_ethernet_data(self):
        self._append_output(self.formatter.display_msg['ethernet'].format(
            **{
                "src": self.packet.ethernet.source,
                "dst": self.packet.ethernet.dest,
                "proto": self.packet.ethernet.encapsulated_proto
            })
        )

    def _display_ipv4_data(self):
        proto = self.packet.ipv4.encapsulated_proto
        self._append_output(self.formatter.display_msg['ipv4'].format(
            **{
                "version": self.packet.ipv4.version,
                "header_len": self.packet.ipv4.header_len,
                "dscp": self.packet.ipv4.dscp_name,
                "ecn": self.packet.ipv4.ecn,
                "len": self.packet.ipv4.len,
                "id": self.packet.ipv4.id,
                "flags": self.packet.ipv4.flags,
                "offset": self.packet.ipv4.offset,
                "ttl": self.packet.ipv4.ttl,
                "proto": proto,
                "chksum": self.packet.ipv4.chksum,
                "src": self.packet.ipv4.source,
                "dst": self.packet.ipv4.dest
            })
        )
        if proto is None:
            self.packet_type_count["others"] += 1
        else:
            self.packet_type_count[proto] += 1

    def _display_ipv6_data(self):
        self._append_output(self.formatter.display_msg['ipv6'].format(
            **{
                "version": self.packet.ipv6.version,
                "tclass": self.packet.ipv6.tclass,
                "flabel": self.packet.ipv6.flabel,
                "payload_len": self.packet.ipv6.payload_len,
                "next_header": self.packet.ipv6.next_header,
                "hop_limit": self.packet.ipv6.hop_limit,
                "source": self.packet.ipv6.source,
                "dest": self.packet.ipv6.dest
            })
        )

    def _display_icmp_data(self):
        self._append_output(self.formatter.display_msg['icmp'].format(
            **{
                "type": self.packet.icmp.type_txt,
                "code": self.packet.icmp.code,
                "chksum": self.packet.icmp.chksum
            })
        )

    def _display_igmp_data(self):
        self._append_output(self.formatter.display_msg['igmp'].format(
            **{
                "type": self.packet.igmp.type_txt,
                "max_res_time": self.packet.igmp.max_res_time,
                "chksum": self.packet.igmp.chksum,
                "grp_addr": self.packet.igmp.grp_addr
            })
        )

    def _display_tcp_data(self):
        self._append_output(self.formatter.display_msg['tcp'].format(
            **{
                "src": self.packet.tcp.sport,
                "dst": self.packet.tcp.dport,
                "seq": self.packet.tcp.seq,
                "ack": self.packet.tcp.ack,
                "flags": self.packet.tcp.flag_txt,
                "win": self.packet.tcp.window,
                "chksum": self.packet.tcp.chksum,
                "urg": self.packet.tcp.urg
            })
        )

    def _display_udp_data(self):
        self._append_output(self.formatter.display_msg['udp'].format(
            **{
                "src": self.packet.udp.sport,
                "dst": self.packet.udp.dport,
                "seq": self.packet.udp.len,
                "chksum": self.packet.udp.chksum
            })
        )
