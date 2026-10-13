import argparse
import asyncio
import pathlib
import socket
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))

import ps2_recon  # noqa: E402


def dns_query(name, qtype=1, txid=0x1234):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def real_client_hello(server_name="pol.example.net"):
    """The first bytes a real TLS client sends, produced by Python's ssl module."""
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    conn = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        conn.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DNSTests(unittest.TestCase):
    def test_parse_query(self):
        q = ps2_recon.parse_query(dns_query("lobby.playonline.com"))
        self.assertEqual((q.txid, q.name, q.qtype, q.qclass), (0x1234, "lobby.playonline.com", 1, 1))

    def test_a_response_points_at_our_ip(self):
        q = ps2_recon.parse_query(dns_query("lobby.playonline.com"))
        response = ps2_recon.build_response(q, "192.168.1.50")
        txid, flags, qd, an = struct.unpack("!HHHH", response[:8])
        self.assertEqual((txid, qd, an), (0x1234, 1, 1))
        self.assertTrue(flags & 0x8000)
        self.assertTrue(flags & 0x0100, "RD should be copied from the query")
        self.assertEqual(ps2_recon.answer_ips(response), ["192.168.1.50"])

    def test_non_a_query_gets_empty_answer(self):
        q = ps2_recon.parse_query(dns_query("lobby.playonline.com", qtype=28))
        response = ps2_recon.build_response(q, "192.168.1.50")
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)
        self.assertEqual(response[-4:], struct.pack("!HH", 28, 1))

    def test_compressed_name(self):
        packet = b"\x00" * 12 + b"\x03pol\x07example\x00" + b"\x05lobby\xc0\x0c"
        self.assertEqual(ps2_recon.read_name(packet, 25), ("lobby.pol.example", len(packet)))

    def test_compression_loop_is_rejected(self):
        with self.assertRaises(ps2_recon.DNSError):
            ps2_recon.read_name(b"\x00" * 12 + b"\xc0\x0c", 12)

    def test_garbage_is_rejected(self):
        for packet in (b"", b"\x00" * 11, dns_query("a.b")[:-3]):
            with self.assertRaises(ps2_recon.DNSError):
                ps2_recon.parse_query(packet)

    def test_redirect_globs(self):
        self.assertTrue(ps2_recon.should_redirect("Lobby.PlayOnline.com.", ["*.playonline.com"]))
        self.assertFalse(ps2_recon.should_redirect("example.org", ["*.playonline.com"]))
        self.assertTrue(ps2_recon.should_redirect("example.org", ["*"]))
        self.assertFalse(ps2_recon.should_redirect("example.org", []))


class PayloadTests(unittest.TestCase):
    def test_real_tls_client_hello(self):
        hello = ps2_recon.parse_client_hello(real_client_hello("pol.example.net"))
        self.assertEqual(hello["format"], "TLS")
        self.assertEqual(hello["sni"], "pol.example.net")
        self.assertGreater(hello["cipher_count"], 0)
        self.assertIn("SNI=pol.example.net", ps2_recon.describe_payload(real_client_hello("pol.example.net")))

    def test_minimal_ssl3_hello_without_extensions(self):
        body = struct.pack("!H", 0x0300) + b"\x00" * 32 + b"\x00" + struct.pack("!HHH", 4, 0x0004, 0x000A) + b"\x01\x00"
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x00" + struct.pack("!H", len(handshake)) + handshake
        summary = ps2_recon.describe_payload(record)
        self.assertIn("SSL 3.0", summary)
        self.assertIn("RSA_WITH_RC4_128_MD5", summary)
        self.assertIn("RSA_WITH_3DES_EDE_CBC_SHA", summary)

    def test_sslv2_format_hello(self):
        specs = b"\x01\x00\x80" * 3
        body = b"\x01" + struct.pack("!HHHH", 0x0300, len(specs), 0, 16) + specs + b"\x00" * 16
        record = bytes([0x80 | (len(body) >> 8), len(body) & 0xFF]) + body
        hello = ps2_recon.parse_client_hello(record)
        self.assertEqual((hello["format"], hello["version"], hello["cipher_count"]), ("SSLv2-compatible", 0x0300, 3))

    def test_binary_with_high_bit_is_not_sslv2(self):
        self.assertIsNone(ps2_recon.parse_client_hello(b"\x81\xff\x01\x22" + b"\x00" * 20))

    def test_http(self):
        summary = ps2_recon.describe_payload(b"GET /patch/ver.txt HTTP/1.0\r\nHost: patch.example\r\n\r\n")
        self.assertEqual(summary, "HTTP request: GET /patch/ver.txt HTTP/1.0 (Host: patch.example)")

    def test_unknown_binary(self):
        self.assertIn("binary", ps2_recon.describe_payload(b"\x00\x01\xfe\xff"))

    def test_truncated_tls_does_not_crash(self):
        hello = real_client_hello()
        for cut in range(len(hello)):
            ps2_recon.describe_payload(hello[:cut] or b"\x00")

    def test_hexdump(self):
        dump = ps2_recon.hexdump(b"PlayOnline\x00\x01" + b"A" * 300, limit=32)
        first = dump.splitlines()[0]
        self.assertTrue(first.startswith("00000000  50 6c 61 79"))
        self.assertTrue(first.endswith("|PlayOnline..AAAA|"))
        self.assertIn("280 more bytes", dump)


class FakeUpstream(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(ps2_recon.build_response(ps2_recon.parse_query(data), "203.0.113.7"), addr)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.recorder = ps2_recon.Recorder(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **overrides):
        values = dict(ip="10.0.0.5", bind="127.0.0.1", dns_port=free_port(socket.SOCK_DGRAM),
                      redirect=["*.playonline.com"], forward_all=False, upstream="127.0.0.1:1",
                      tcp=[free_port()], udp=[free_port(socket.SOCK_DGRAM)], idle_timeout=0.3)
        values.update(overrides)
        return argparse.Namespace(**values)

    async def dns_lookup(self, port, name):
        loop = asyncio.get_running_loop()
        reply = loop.create_future()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                reply.set_result(data)

        transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port))
        transport.sendto(dns_query(name))
        try:
            return await asyncio.wait_for(reply, 5)
        finally:
            transport.close()

    def test_full_session(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            upstream, _ = await loop.create_datagram_endpoint(FakeUpstream, local_addr=("127.0.0.1", 0))
            args = self.args(upstream="127.0.0.1:%d" % upstream.get_extra_info("sockname")[1])
            opened = await ps2_recon.start_services(args, self.recorder)
            try:
                redirected = await self.dns_lookup(args.dns_port, "lobby.playonline.com")
                forwarded = await self.dns_lookup(args.dns_port, "example.org")

                _, writer = await asyncio.open_connection("127.0.0.1", args.tcp[0])
                writer.write(real_client_hello("lobby.playonline.com"))
                await writer.drain()
                await asyncio.sleep(0.6)  # past idle_timeout, so the server closes and records it
                writer.close()

                _, silent = await asyncio.open_connection("127.0.0.1", args.tcp[0])
                await asyncio.sleep(0.6)
                silent.close()

                udp, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol, remote_addr=("127.0.0.1", args.udp[0]))
                udp.sendto(b"\x00\x01\x02\x03")
                await asyncio.sleep(0.2)
                udp.close()
            finally:
                for item in opened:
                    item.close()
                upstream.close()
            return redirected, forwarded

        redirected, forwarded = asyncio.run(scenario())
        self.assertEqual(ps2_recon.answer_ips(redirected), ["10.0.0.5"])
        self.assertEqual(ps2_recon.answer_ips(forwarded), ["203.0.113.7"])
        self.assertEqual(set(self.recorder.hostnames), {"lobby.playonline.com", "example.org"})
        self.assertEqual(len(list(pathlib.Path(self.tmp.name).glob("*-tcp-*.bin"))), 1)
        self.assertEqual(len(list(pathlib.Path(self.tmp.name).glob("*-udp-*.bin"))), 1)
        findings = "\n".join(self.recorder.findings)
        self.assertIn("SNI=lobby.playonline.com", findings)
        self.assertIn("client sent nothing", findings)
        summary = self.recorder.summary()
        self.assertIn("lobby.playonline.com (x1)", summary)
        self.assertIn("UDP ports contacted", summary)

    def test_upstream_down_returns_servfail(self):
        async def scenario():
            args = self.args(upstream="127.0.0.1:%d" % free_port(socket.SOCK_DGRAM))
            opened = await ps2_recon.start_services(args, self.recorder)
            try:
                return await self.dns_lookup(args.dns_port, "example.org")
            finally:
                for item in opened:
                    item.close()

        response = asyncio.run(scenario())
        self.assertEqual(struct.unpack("!H", response[2:4])[0] & 0x000F, 2)


if __name__ == "__main__":
    unittest.main()
