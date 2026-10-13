#!/usr/bin/env python3
"""Find out what PlayOnline on a PS2 tries to talk to.

Point the PS2's primary DNS at the computer running this script. Every DNS
lookup is logged and, by default, answered with this computer's IP, so the PS2
connects here instead of to Square Enix's (long gone) PS2 servers. Every
connection is logged, hex-dumped, checked for TLS/HTTP, and saved under
captures/ so the protocol can be studied later.

Standard library only. Python 3.8+.
"""

import argparse
import asyncio
import collections
import datetime
import fnmatch
import functools
import logging
import pathlib
import socket
import struct
import sys

# Web/mail ports PlayOnline used on PC, plus the login/lobby/map ports that
# LandSandBoat listens on (settings/default/network.lua).
DEFAULT_TCP_PORTS = [25, 80, 110, 443, 51220, 54001, 54002, 54230, 54231]
DEFAULT_UDP_PORTS = [54230]

MAX_CAPTURE_BYTES = 256 * 1024
LOG_DUMP_BYTES = 256

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

TLS_VERSIONS = {0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0",
                0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

# The suites a 2000s-era embedded SSL stack is likely to offer.
CIPHER_SUITES = {
    0x0001: "RSA_WITH_NULL_MD5",
    0x0002: "RSA_WITH_NULL_SHA",
    0x0003: "RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "RSA_WITH_RC4_128_MD5",
    0x0005: "RSA_WITH_RC4_128_SHA",
    0x0006: "RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "RSA_WITH_DES_CBC_SHA",
    0x000A: "RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "RSA_WITH_AES_128_CBC_SHA",
    0x0033: "DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "RSA_WITH_AES_256_CBC_SHA",
    0x0039: "DHE_RSA_WITH_AES_256_CBC_SHA",
    0x00FF: "EMPTY_RENEGOTIATION_INFO_SCSV",
}

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ")

log = logging.getLogger("ps2_recon")


# --- DNS ---------------------------------------------------------------------

class DNSError(ValueError):
    pass


DNSQuestion = collections.namedtuple("DNSQuestion", "txid flags name qtype qclass raw")


def read_name(data, offset):
    """Decode a (possibly compressed) DNS name. Returns (name, offset after it)."""
    labels = []
    end = None
    hops = 0
    while True:
        if offset >= len(data):
            raise DNSError("name runs past end of packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            if hops > 16:
                raise DNSError("compression pointer loop")
            continue
        if length & 0xC0:
            raise DNSError("unsupported label type")
        offset += 1
        if length == 0:
            break
        label = data[offset:offset + length]
        if len(label) != length:
            raise DNSError("label runs past end of packet")
        labels.append(label.decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), end if end is not None else offset


def parse_query(data):
    if len(data) < 12:
        raise DNSError("packet shorter than a DNS header")
    txid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if flags & 0x8000:
        raise DNSError("packet is a response, not a query")
    if qdcount < 1:
        raise DNSError("query has no question")
    name, offset = read_name(data, 12)
    if offset + 4 > len(data):
        raise DNSError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return DNSQuestion(txid, flags, name, qtype, qclass, data[12:offset + 4])


def build_response(question, ip=None, rcode=0, ttl=60):
    """Answer `question`. An A/IN question gets `ip`; anything else gets no records."""
    flags = 0x8000 | (question.flags & 0x7900) | 0x0080 | rcode  # QR, opcode, RD, RA
    answer = b""
    if ip is not None and question.qtype == 1 and question.qclass == 1:
        answer = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(ip)
    header = struct.pack("!HHHHHH", question.txid, flags, 1, 1 if answer else 0, 0, 0)
    return header + question.raw + answer


def answer_ips(response):
    """IPv4 addresses in the answer section of a DNS response."""
    try:
        qdcount, ancount = struct.unpack("!HH", response[4:8])
        offset = 12
        for _ in range(qdcount):
            offset = read_name(response, offset)[1] + 4
        ips = []
        for _ in range(ancount):
            offset = read_name(response, offset)[1]
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlength == 4:
                ips.append(socket.inet_ntoa(response[offset:offset + 4]))
            offset += rdlength
        return ips
    except (DNSError, struct.error, OSError):
        return []


def should_redirect(name, patterns):
    name = name.lower().rstrip(".")
    return any(fnmatch.fnmatchcase(name, pattern.lower()) for pattern in patterns)


async def query_upstream(data, upstream, timeout=3.0):
    loop = asyncio.get_running_loop()
    reply = loop.create_future()

    class Client(asyncio.DatagramProtocol):
        def datagram_received(self, packet, addr):
            if not reply.done():
                reply.set_result(packet)

        def error_received(self, exc):
            if not reply.done():
                reply.set_exception(exc)

    transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=upstream)
    try:
        transport.sendto(data)
        return await asyncio.wait_for(reply, timeout)
    finally:
        transport.close()


class DNSServer(asyncio.DatagramProtocol):
    def __init__(self, recorder, answer_ip, redirect_patterns, upstream):
        self.recorder = recorder
        self.answer_ip = answer_ip
        self.redirect_patterns = redirect_patterns
        self.upstream = upstream
        self.transport = None
        self.pending = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            question = parse_query(data)
        except DNSError as exc:
            log.warning("DNS: unparseable packet from %s (%s)", addr[0], exc)
            return
        qtype = QTYPE_NAMES.get(question.qtype, str(question.qtype))
        self.recorder.saw_hostname(question.name)
        if should_redirect(question.name, self.redirect_patterns):
            log.info("DNS: %s asked for %s %s -> answering %s",
                     addr[0], qtype, question.name, self.answer_ip)
            self.transport.sendto(build_response(question, self.answer_ip), addr)
        else:
            task = asyncio.ensure_future(self.forward(data, question, qtype, addr))
            self.pending.add(task)
            task.add_done_callback(self.pending.discard)

    async def forward(self, data, question, qtype, addr):
        try:
            response = await query_upstream(data, self.upstream)
        except (OSError, asyncio.TimeoutError) as exc:
            log.warning("DNS: upstream failed for %s (%r)", question.name, exc)
            response = build_response(question, rcode=2)  # SERVFAIL
        else:
            ips = answer_ips(response)
            log.info("DNS: %s asked for %s %s -> forwarded, real answer: %s",
                     addr[0], qtype, question.name, ", ".join(ips) or "(none)")
        self.transport.sendto(response, addr)


# --- Payload analysis --------------------------------------------------------

def hexdump(data, limit=LOG_DUMP_BYTES):
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  |{text}|")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes (full data in the .bin file)")
    return "\n".join(lines)


def parse_client_hello(data):
    """Describe a TLS/SSL ClientHello, or return None if `data` isn't one."""
    try:
        if (len(data) >= 11 and data[0] & 0x80 and data[2] == 0x01 and data[3] in (0x00, 0x03)
                and 9 <= ((data[0] & 0x7F) << 8 | data[1]) <= len(data) - 2):
            # SSLv2-format hello, still sent by some early-2000s SSL stacks.
            version, specs_len = struct.unpack("!HH", data[3:7])
            return {"format": "SSLv2-compatible", "version": version,
                    "cipher_count": specs_len // 3, "ciphers": [], "sni": None}
        if len(data) < 9 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return None
        hello = data[9:9 + int.from_bytes(data[6:9], "big")]
        version = struct.unpack("!H", hello[0:2])[0]
        pos = 34  # version + 32-byte random
        pos += 1 + hello[pos]  # session id
        suites_len = struct.unpack("!H", hello[pos:pos + 2])[0]
        pos += 2
        ciphers = [struct.unpack("!H", hello[i:i + 2])[0] for i in range(pos, pos + suites_len, 2)]
        pos += suites_len
        pos += 1 + hello[pos]  # compression methods
        sni = None
        if pos + 2 <= len(hello):
            end = pos + 2 + struct.unpack("!H", hello[pos:pos + 2])[0]
            pos += 2
            while pos + 4 <= end:
                ext_type, ext_len = struct.unpack("!HH", hello[pos:pos + 4])
                ext = hello[pos + 4:pos + 4 + ext_len]
                pos += 4 + ext_len
                if ext_type == 0 and len(ext) >= 5 and ext[2] == 0:
                    name_len = struct.unpack("!H", ext[3:5])[0]
                    sni = ext[5:5 + name_len].decode("ascii", errors="replace")
        return {"format": "TLS", "version": version, "cipher_count": len(ciphers),
                "ciphers": ciphers, "sni": sni}
    except (IndexError, struct.error):
        return None


def describe_payload(data):
    """One-line guess at what protocol `data` is."""
    hello = parse_client_hello(data)
    if hello:
        version = TLS_VERSIONS.get(hello["version"], f"0x{hello['version']:04x}")
        ciphers = ", ".join(CIPHER_SUITES.get(c, f"0x{c:04x}") for c in hello["ciphers"])
        return (f"{hello['format']} ClientHello: {version}, SNI={hello['sni'] or '(none)'}, "
                f"{hello['cipher_count']} cipher suites" + (f": {ciphers}" if ciphers else ""))
    if data.startswith(HTTP_METHODS):
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        host = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("host:")), "?")
        return f"HTTP request: {head[0]} (Host: {host})"
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if printable == len(data):
        return f"Plain text, {len(data)} bytes: {data[:80].decode('ascii')!r}"
    return f"Unrecognised binary protocol, {len(data)} bytes"


# --- Recording ---------------------------------------------------------------

class Recorder:
    def __init__(self, session_dir):
        self.session_dir = pathlib.Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.hostnames = collections.Counter()
        self.tcp_ports = collections.Counter()
        self.udp_ports = collections.Counter()
        self.findings = []
        self._counter = 0

    def saw_hostname(self, name):
        self.hostnames[name.lower().rstrip(".")] += 1

    def save(self, kind, port, peer, data):
        self._counter += 1
        path = self.session_dir / f"{self._counter:04d}-{kind}-{port}-{peer.replace(':', '_')}.bin"
        path.write_bytes(bytes(data))
        return path

    def summary(self):
        lines = ["", "=== Summary ===", f"Captures: {self.session_dir}"]
        lines.append("Hostnames looked up:" if self.hostnames else "No DNS lookups seen.")
        lines += [f"  {name} (x{count})" for name, count in self.hostnames.most_common()]
        for label, ports in (("TCP", self.tcp_ports), ("UDP", self.udp_ports)):
            if ports:
                lines.append(f"{label} ports contacted: " +
                             ", ".join(f"{p} (x{n})" for p, n in sorted(ports.items())))
        if self.findings:
            lines.append("What was sent:")
            lines += [f"  {finding}" for finding in self.findings]
        return "\n".join(lines)


async def handle_tcp(recorder, port, idle_timeout, reader, writer):
    peer = writer.get_extra_info("peername")[0]
    recorder.tcp_ports[port] += 1
    log.info("TCP %d: connection from %s", port, peer)
    data = bytearray()
    try:
        while len(data) < MAX_CAPTURE_BYTES:
            chunk = await asyncio.wait_for(reader.read(4096), idle_timeout)
            if not chunk:
                break
            data += chunk
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
    if not data:
        finding = (f"TCP {port}: client sent nothing in {idle_timeout:g}s "
                   "(the server probably has to speak first)")
        log.info(finding)
    else:
        path = recorder.save("tcp", port, peer, data)
        finding = f"TCP {port}: {describe_payload(bytes(data))}"
        log.info("%s\n%s\nsaved to %s", finding, hexdump(data), path)
    recorder.findings.append(finding)


class UDPLogger(asyncio.DatagramProtocol):
    def __init__(self, recorder, port):
        self.recorder = recorder
        self.port = port

    def datagram_received(self, data, addr):
        self.recorder.udp_ports[self.port] += 1
        path = self.recorder.save("udp", self.port, addr[0], data)
        finding = f"UDP {self.port}: {describe_payload(data)}"
        self.recorder.findings.append(finding)
        log.info("%s from %s\n%s\nsaved to %s", finding, addr[0], hexdump(data), path)


# --- Startup -----------------------------------------------------------------

def guess_lan_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # no packet is sent; this just picks a route
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def parse_host_port(value, default_port):
    host, sep, port = value.rpartition(":")
    return (host, int(port)) if sep else (value, default_port)


async def start_services(args, recorder):
    """Open every listener we can. Returns the servers/transports to close later."""
    loop = asyncio.get_running_loop()
    opened = []
    redirect = [] if args.forward_all else args.redirect
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSServer(recorder, args.ip, redirect, parse_host_port(args.upstream, 53)),
            local_addr=(args.bind, args.dns_port))
        opened.append(transport)
        log.info("DNS listening on %s:%d (answering with %s)", args.bind, args.dns_port, args.ip)
    except OSError as exc:
        log.error("Could not listen for DNS on port %d: %s", args.dns_port, exc)
        log.error("Port 53 needs admin/root (sudo on Linux/macOS), and nothing else may be using it.")
    for port in args.tcp:
        try:
            server = await asyncio.start_server(
                functools.partial(handle_tcp, recorder, port, args.idle_timeout), args.bind, port)
            opened.append(server)
        except OSError as exc:
            log.warning("Skipping TCP %d: %s", port, exc)
    for port in args.udp:
        try:
            transport, _ = await loop.create_datagram_endpoint(
                functools.partial(UDPLogger, recorder, port), local_addr=(args.bind, port))
            opened.append(transport)
        except OSError as exc:
            log.warning("Skipping UDP %d: %s", port, exc)
    return opened


async def serve(args, recorder):
    opened = await start_services(args, recorder)
    if not opened:
        raise SystemExit("Nothing could be opened; see the errors above.")
    log.info("Ready. Set the PS2's primary DNS to %s, then start PlayOnline. Ctrl+C to stop.", args.ip)
    try:
        await asyncio.Event().wait()
    finally:
        for item in opened:
            item.close()


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ip", default=guess_lan_ip(),
                        help="IP to hand out in DNS answers; this computer's LAN IP (default: %(default)s)")
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: %(default)s)")
    parser.add_argument("--dns-port", type=int, default=53, help="default: %(default)s")
    parser.add_argument("--redirect", action="append", metavar="GLOB",
                        help="only answer hostnames matching GLOB with --ip, forward the rest "
                             "(repeatable; default: redirect every hostname)")
    parser.add_argument("--forward-all", action="store_true",
                        help="redirect nothing; just log lookups and the real answers")
    parser.add_argument("--upstream", default="1.1.1.1",
                        help="DNS server for forwarded lookups, host[:port] (default: %(default)s)")
    parser.add_argument("--tcp", type=int, nargs="*", default=DEFAULT_TCP_PORTS, metavar="PORT",
                        help="TCP ports to listen on (default: %(default)s)")
    parser.add_argument("--udp", type=int, nargs="*", default=DEFAULT_UDP_PORTS, metavar="PORT",
                        help="UDP ports to listen on (default: %(default)s)")
    parser.add_argument("--idle-timeout", type=float, default=5.0,
                        help="seconds to wait for more data before closing a connection (default: %(default)s)")
    parser.add_argument("--captures", default="captures", help="output folder (default: %(default)s)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.redirect = args.redirect or ["*"]
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    recorder = Recorder(pathlib.Path(args.captures) / stamp)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(recorder.session_dir / "recon.log", encoding="utf-8")])
    try:
        asyncio.run(serve(args, recorder))
    except KeyboardInterrupt:
        pass
    summary = recorder.summary()
    log.info(summary)
    (recorder.session_dir / "summary.txt").write_text(summary + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
