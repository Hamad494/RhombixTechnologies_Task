

import argparse
import os
import socket
import struct
import sys
import textwrap
import time
from collections import Counter

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded",
}

KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt",
}


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_to_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def service(port: int) -> str:
    return KNOWN_PORTS.get(port, "")


def payload_preview(data: bytes, limit: int = 64) -> str:
    """Return printable ASCII preview of payload."""
    chunk = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return text + ("..." if len(data) > limit else "")


def hex_dump(data: bytes, limit: int = 48) -> str:
    chunk = data[:limit]
    return " ".join(f"{b:02x}" for b in chunk) + (" ..." if len(data) > limit else "")


# ----------------------------------------------------------------------
# Packet parsers
# ----------------------------------------------------------------------
def parse_ethernet(data: bytes):
    dest, src, proto = struct.unpack("!6s6sH", data[:14])
    return mac_to_str(dest), mac_to_str(src), proto, data[14:]


def parse_ipv4(data: bytes):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    tos, total_len, ident, flags_frag, ttl, proto, checksum, src, dst = \
        struct.unpack("!BHHHBBH4s4s", data[1:20])
    return {
        "version": version,
        "header_len": ihl,
        "tos": tos,
        "total_len": total_len,
        "id": ident,
        "flags": flags_frag >> 13,
        "frag_offset": flags_frag & 0x1FFF,
        "ttl": ttl,
        "proto": proto,
        "checksum": checksum,
        "src": ip_to_str(src),
        "dst": ip_to_str(dst),
    }, data[ihl:total_len] if total_len else data[ihl:]


def parse_tcp(data: bytes):
    (src_port, dst_port, seq, ack, offset_flags,
     window, checksum, urg) = struct.unpack("!HHLLHHHH", data[:20])
    offset = (offset_flags >> 12) * 4
    flag_bits = offset_flags & 0x3F
    names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
    flags = [n for i, n in enumerate(names) if flag_bits & (1 << i)]
    return {
        "src_port": src_port, "dst_port": dst_port,
        "seq": seq, "ack": ack, "window": window,
        "flags": ",".join(flags) or "-",
    }, data[offset:]


def parse_udp(data: bytes):
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return {"src_port": src_port, "dst_port": dst_port, "length": length}, data[8:]


def parse_icmp(data: bytes):
    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
    return {"type": icmp_type, "code": code,
            "desc": ICMP_TYPES.get(icmp_type, "Other")}, data[4:]


# ----------------------------------------------------------------------
# Sniffer
# ----------------------------------------------------------------------
class Sniffer:
    def __init__(self, proto_filter=None, port_filter=None,
                 count=0, outfile=None, show_payload=True, host=None):
        self.host = host
        self.proto_filter = proto_filter
        self.port_filter = port_filter
        self.count = count
        self.show_payload = show_payload
        self.outfile = open(outfile, "a", encoding="utf-8") if outfile else None
        self.stats = Counter()
        self.captured = 0
        self.start = time.time()
        self.sock = None
        self.is_windows = os.name == "nt"

    # -- output ---------------------------------------------------------
    def out(self, text=""):
        print(text)
        if self.outfile:
            self.outfile.write(text + "\n")

    # -- socket ---------------------------------------------------------
    @staticmethod
    def detect_ip():
        """Find the IP of the adapter that actually reaches the internet."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))   # UDP connect: sends no data
            return s.getsockname()[0]
        except OSError:
            return socket.gethostbyname(socket.gethostname())
        finally:
            s.close()

    def open_socket(self):
        try:
            if self.is_windows:
                host = self.host or self.detect_ip()
                print(f"[*] Listening on interface IP: {host}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                          socket.IPPROTO_IP)
                self.sock.bind((host, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # 0x0003 = ETH_P_ALL (capture every protocol)
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                          socket.ntohs(0x0003))
        except PermissionError:
            sys.exit("[!] Permission denied. Run as root (sudo) / Administrator.")
        except AttributeError:
            sys.exit("[!] Raw packet capture is not supported on this OS "
                     "(macOS needs scapy/pcap).")

    # -- filters --------------------------------------------------------
    def passes_filter(self, proto_name, sport, dport):
        if self.proto_filter and proto_name.lower() != self.proto_filter:
            return False
        if self.port_filter and self.port_filter not in (sport, dport):
            return False
        return True

    # -- main handling --------------------------------------------------
    def handle(self, raw: bytes):
        eth_info = None
        if self.is_windows:
            ip_data = raw
        else:
            dest_mac, src_mac, eth_proto, ip_data = parse_ethernet(raw)
            eth_info = (dest_mac, src_mac, eth_proto)
            if eth_proto != 0x0800:          # only IPv4 decoded here
                self.stats["Non-IPv4"] += 1
                return

        if len(ip_data) < 20:
            return
        ip, body = parse_ipv4(ip_data)
        proto_name = PROTOCOLS.get(ip["proto"], f"Other({ip['proto']})")

        sport = dport = None
        transport = None
        payload = b""

        try:
            if ip["proto"] == 6 and len(body) >= 20:
                transport, payload = parse_tcp(body)
                sport, dport = transport["src_port"], transport["dst_port"]
            elif ip["proto"] == 17 and len(body) >= 8:
                transport, payload = parse_udp(body)
                sport, dport = transport["src_port"], transport["dst_port"]
            elif ip["proto"] == 1 and len(body) >= 4:
                transport, payload = parse_icmp(body)
        except struct.error:
            return

        if not self.passes_filter(proto_name, sport, dport):
            return

        self.captured += 1
        self.stats[proto_name] += 1
        self.display(eth_info, ip, proto_name, transport, payload)

    def display(self, eth, ip, proto_name, transport, payload):
        stamp = time.strftime("%H:%M:%S")
        self.out("=" * 72)
        self.out(f"Packet #{self.captured}  [{stamp}]  {proto_name}")
        if eth:
            self.out(f"  Ethernet : {eth[1]} -> {eth[0]}  (type 0x{eth[2]:04x})")
        self.out(f"  IPv4     : {ip['src']} -> {ip['dst']}  "
                 f"TTL={ip['ttl']}  Len={ip['total_len']}  ID={ip['id']}")

        if proto_name == "TCP":
            t = transport
            self.out(f"  TCP      : {t['src_port']}{self._svc(t['src_port'])} -> "
                     f"{t['dst_port']}{self._svc(t['dst_port'])}  Flags=[{t['flags']}]")
            self.out(f"             Seq={t['seq']}  Ack={t['ack']}  Win={t['window']}")
        elif proto_name == "UDP":
            t = transport
            self.out(f"  UDP      : {t['src_port']}{self._svc(t['src_port'])} -> "
                     f"{t['dst_port']}{self._svc(t['dst_port'])}  Len={t['length']}")
        elif proto_name == "ICMP":
            t = transport
            self.out(f"  ICMP     : Type={t['type']} ({t['desc']})  Code={t['code']}")

        if self.show_payload and payload:
            self.out(f"  Payload  : {len(payload)} bytes")
            self.out(f"    ASCII  : {payload_preview(payload)}")
            self.out(f"    HEX    : {hex_dump(payload)}")
            first = payload[:8]
            if first.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"HEAD ")):
                line = payload.split(b"\r\n")[0].decode(errors="replace")
                self.out(f"    HTTP   : {line}")

    @staticmethod
    def _svc(port):
        name = service(port)
        return f" ({name})" if name else ""

    # -- run ------------------------------------------------------------
    def run(self):
        self.open_socket()
        self.out("[*] Sniffer started. Press Ctrl+C to stop.\n")
        try:
            while self.count == 0 or self.captured < self.count:
                raw, _ = self.sock.recvfrom(65535)
                self.handle(raw)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        if self.is_windows and self.sock:
            try:
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        if self.sock:
            self.sock.close()

        elapsed = time.time() - self.start
        self.out("\n" + "#" * 72)
        self.out("CAPTURE SUMMARY")
        self.out(f"  Duration       : {elapsed:.1f} s")
        self.out(f"  Packets shown  : {self.captured}")
        for name, n in self.stats.most_common():
            self.out(f"  {name:<14} : {n}")
        self.out("#" * 72)
        if self.outfile:
            self.outfile.close()


# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Basic Network Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 network_sniffer.py -c 30
              sudo python3 network_sniffer.py -p tcp --port 80
        """))
    ap.add_argument("-c", "--count", type=int, default=0,
                    help="number of packets to capture (0 = unlimited)")
    ap.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp"],
                    help="filter by protocol")
    ap.add_argument("--port", type=int, help="filter by source/destination port")
    ap.add_argument("-o", "--output", help="also save output to this file")
    ap.add_argument("-i", "--interface-ip",
                    help="(Windows) IP of the adapter to sniff, e.g. 192.168.1.5")
    ap.add_argument("--no-payload", action="store_true",
                    help="hide payload data")
    args = ap.parse_args()

    Sniffer(proto_filter=args.protocol, port_filter=args.port,
            count=args.count, outfile=args.output,
            show_payload=not args.no_payload,
            host=args.interface_ip).run()


if __name__ == "__main__":
    main()
