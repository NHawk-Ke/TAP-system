from collections import OrderedDict


indent = " " * 4  # Basic indentation level
protocol_fmt_msg = OrderedDict({
    "ARP": [
        ("htype", indent * 2 + "|-Hardware Type            : {htype}\n"),
        ("ptype", indent * 2 + "|-Protocol Type            : {protocol}\n"),
        ("hlen", indent * 2 + "|-Hardware Address Length  : {hlen}\n"),
        ("plen", indent * 2 + "|-Protocol Address Length  : {plen}\n"),
        ("operation", indent * 2 + "|-Operation                : {oper}\n"),
        ("sha", indent * 2 + "|-Sender Hardware Address  : {source_hdwr}\n"),
        ("spa", indent * 2 + "|-Sender Protocol Address  : {target_hdwr}\n"),
        ("tha", indent * 2 + "|-Target Hardware Address  : {source_proto}\n"),
        ("tpa", indent * 2 + "|-Target Protocol Address  : {target_proto}\n"),
    ],
    "Ethernet": [
        ("mac_src", indent * 2 + "|-Source MAC Address      : {src}\n"),
        ("mac_dst", indent * 2 + "|-Destination MAC Address : {dst}\n"),
        ("eth_type", indent * 2 + "|-EtherType               : {proto}\n"),
    ],
    "IPv4": [
        ("version", indent * 2 + "|-IP Version                   : {version}\n"),
        ("ihl", indent * 2 + "|-IP Header Length             : {header_len} Bytes\n"),
        ("dscp", indent * 2 + "|-DSCP                         : {dscp}\n"),
        ("ecn", indent * 2 + "|-ECN                          : {ecn}\n"),
        ("tot_len", indent * 2 + "|-Total Packet Length          : {len}\n"),
        ("id", indent * 2 + "|-Identification               : {id}\n"),
        ("flags", indent * 2 + "|-Fragmentation Control Flags  : {flags}\n"),
        ("offset", indent * 2 + "|-Fragment Offset              : {offset}\n"),
        ("ttl", indent * 2 + "|-TTL                          : {ttl}\n"),
        ("proto", indent * 2 + "|-Protocol                     : {proto}\n"),
        ("checksum", indent * 2 + "|-Checksum                     : {chksum}\n"),
        ("src", indent * 2 + "|-Source IP                    : {src}\n"),
        ("dst", indent * 2 + "|-Destination IP               : {dst}\n"),
    ],
    "IPv6": [
        ("version", indent * 2 + "|-IP Version             : {version}\n"),
        ("tclass", indent * 2 + "|-Traffic Class          : {tclass}\n"),
        ("flabel", indent * 2 + "|-Flow Label             : {flabel}\n"),
        ("payload_len", indent * 2 + "|-Payload Length         : {payload_len}\n"),
        ("next_header", indent * 2 + "|-Type Of Next Header    : {next_header}\n"),
        ("hop_limit", indent * 2 + "|-Hop Limit              : {hop_limit}\n"),
        ("src", indent * 2 + "|-Source Address         : {source}\n"),
        ("dst", indent * 2 + "|-Destination Address    : {dest}\n"),
    ],
    "ICMP": [
        ("type", indent * 2 + "|-Type       : {type}\n"),
        ("code", indent * 2 + "|-Code       : {code}\n"),
        ("checksum", indent * 2 + "|-Checksum   : {chksum}\n"),
    ],
    "IGMP": [
        ("type", indent * 2 + "|-IGMP Message Type    : {type}\n"),
        ("max_res_time", indent * 2 + "|-Max Response Time    : {max_res_time}\n"),
        ("checksum", indent * 2 + "|-Checksum             : {chksum}\n"),
        ("grp_addr", indent * 2 + "|-Group Address        : {grp_addr}\n"),
    ],
    "TCP": [
        ("sport", indent * 2 + "|-Source Port             : {src}\n"),
        ("dport", indent * 2 + "|-Destination Port        : {dst}\n"),
        ("seq", indent * 2 + "|-Sequence Number         : {seq}\n"),
        ("ack", indent * 2 + "|-Acknowledgement Number  : {ack}\n"),
        ("flags", indent * 2 + "|-Flags                   : {flags}\n"),
        ("window", indent * 2 + "|-Window                  : {win}\n"),
        ("checksum", indent * 2 + "|-Checksum                : {chksum}\n"),
        ("urg", indent * 2 + "|-Urgent Pointer          : {urg}\n"),
    ],
    "UDP": [
        ("sport", indent * 2 + "|-Source Port       : {src}\n"),
        ("dport", indent * 2 + "|-Destination Port  : {dst}\n"),
        ("checksum", indent * 2 + "|-UDP Checksum      : {chksum}\n"),
    ],
})


class Formatter:
    def __init__(self, config_json):
        self.interface = config_json.get('interface', None)
        self.display_data = config_json.get('display_data', False)
        self.filter_string = config_json.get('BPF', None)
        self.display_msg = {}
        self.proto_filter_cfg = {}
        self.indent = indent

        self._parse_config(config_json)

    @property
    def _header_format(self):
        return self.indent + "{0} Header\n"

    def _parse_config(self, config_json: dict):
        proto_configs = config_json.get("protocols", {})
        for proto, fields in protocol_fmt_msg.items():
            self.display_msg[proto.lower()] = self._header_format.format(proto)
            self.proto_filter_cfg[proto.lower()] = {}
            proto_config = proto_configs.get(proto, {})
            for field, msg in fields:
                cfg = proto_config.get(field, {})
                if cfg.pop("display", False):
                    self.display_msg[proto.lower()] += msg
                if cfg:
                    self.proto_filter_cfg[proto.lower()][field] = cfg
