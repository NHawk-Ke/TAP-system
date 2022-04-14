import itertools
import json
from ctypes import create_string_buffer, addressof
from socket import AF_PACKET, SOCK_RAW, ntohs, socket, if_nameindex, SOL_SOCKET
from struct import pack
from typing import Generator
import subprocess

import protocols
from args import get_parser
from output import OutputToScreen
from publisher import PacketPublisher


class Decoder:
    def __init__(self, interface: str, filter_str: str):
        """Decodes packets incoming from a given interface.
        :param interface: Interface from which packets will be captured
            and decoded.
        :param filter_str: A Berkeley Packet Filter string that filter the string from the start
        """
        self._interface = interface
        self.data = None
        self.filter = filter_str
        self.protocol_queue = ["Ethernet"]

    def execute(self) -> Generator:
        """
        Yields a decoded packet as an instance of Protocol.
        """
        with socket(AF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            # Generate BPF filter bytecode from tcpdump and attach to socket
            if self.filter:
                cmd = f"sudo tcpdump -ddd '{self.filter}'"
                tcpdump = subprocess.check_output(cmd, shell=True)
                bytecode = [pack('HBBI', *[int(x) for x in args.split(' ')])
                            for args in tcpdump.decode('utf-8').split('\n')[1:-1]]
                filters = b''.join(bytecode)
                b = create_string_buffer(filters)
                mem_addr_of_filters = addressof(b)
                fprog = pack('HL', len(bytecode), mem_addr_of_filters)
                sock.setsockopt(SOL_SOCKET, 26, fprog)

            if self._interface is not None:
                sock.bind((self._interface, 0))
            for self.packet_num in itertools.count(1):
                raw_packet = sock.recv(65536)
                start = 0
                for proto in self.protocol_queue:
                    proto_class = getattr(protocols, proto)
                    end = start + proto_class.header_len
                    protocol = proto_class(raw_packet[start:end])
                    setattr(self, proto.lower(), protocol)
                    if protocol.encapsulated_proto is None:
                        break
                    self.protocol_queue.append(protocol.encapsulated_proto)
                    start = end
                self.data = raw_packet[end:]
                yield self
                del self.protocol_queue[1:]


class PacketSniffer:
    def __init__(self, config_file):
        """
        Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods.
        :param config_file: Interface from which packets will be captured
            and decoded.
        """
        self._observers = list()
        config = json.load(config_file)
        self.formatter = protocols.Formatter(config)
        self.publisher = PacketPublisher(config.get("publish"))
        config_file.close()
        self._decoder = Decoder(self.formatter.interface, self.formatter.filter_string)

    def register(self, observer) -> None:
        """
        Register an observer for processing/output of decoded
        packets.
        """
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """
        Send a decoded packet to all registered observers.
        """
        [observer.update(*args, **kwargs) for observer in self._observers]

    def execute(self, file=None) -> None:
        OutputToScreen(subject=self, output_file=file)
        try:
            print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
                  "data. Press Ctrl-C to abort...\n")
            [self._notify_all(packet) for packet in self._decoder.execute()]
        except KeyboardInterrupt:
            print("\nStopping publisher...")
            self.publisher.loop_stop()
            print("Publisher stopped")
            raise SystemExit("\nAborting packet capture...")
        print()


if __name__ == "__main__":
    parser = get_parser()
    input_args = parser.parse_args()
    if input_args.list_interfaces:
        print("Available interfaces to listen on:")
        print(f"    {[interface for i, interface in if_nameindex()]}")
    elif input_args.config_file:
        PacketSniffer(input_args.config_file).execute(input_args.output_file)
    else:
        parser.print_help()
