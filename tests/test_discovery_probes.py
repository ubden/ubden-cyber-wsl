"""mDNS / SSDP / LLDP parsers and their classification wiring."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import discovery_probes as DP
import device_inventory as D


def _name(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".") if l) + b"\x00"


class SsdpTests(unittest.TestCase):
    def test_header_parse(self):
        h = DP._parse_headers("HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 Roku/9.4\r\nST: roku:ecp\r\n\r\n")
        self.assertEqual(h["server"], "Linux UPnP/1.0 Roku/9.4")
        self.assertEqual(h["st"], "roku:ecp")


class MdnsTests(unittest.TestCase):
    def test_a_record_owner_is_hostname(self):
        pkt = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + \
            _name("PRINTER.local") + struct.pack(">HHIH", 1, 1, 120, 4) + bytes([10, 0, 0, 5])
        parsed = DP._parse_mdns(pkt)
        self.assertIn("PRINTER.local", parsed["hostnames"])
        self.assertIn("10.0.0.5", parsed["a_records"])

    def test_ptr_service(self):
        pkt = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + \
            _name("_services._dns-sd._udp.local") + struct.pack(">HHIH", 12, 1, 120, 0)
        # PTR rdata (a compressed name) — build one pointing to _ipp._tcp.local
        rdata = _name("_ipp._tcp.local")
        pkt = pkt[:-2] + struct.pack(">H", len(rdata)) + rdata
        parsed = DP._parse_mdns(pkt)
        self.assertTrue(any("_ipp._tcp" in s for s in parsed["services"]))


class LldpTests(unittest.TestCase):
    def test_tlv_parse(self):
        def tlv(t, v): return struct.pack(">H", (t << 9) | len(v)) + v
        frame = tlv(1, b"\x04" + bytes.fromhex("001122334455")) + tlv(2, b"\x05Gi0/1") + \
            tlv(5, b"SW-CORE") + tlv(6, b"Cisco IOS Software") + tlv(0, b"")
        info = DP._parse_lldp(frame)
        self.assertEqual(info["system_name"], "SW-CORE")
        self.assertEqual(info["port_id"], "Gi0/1")   # subtype byte stripped
        self.assertIn("Cisco", info["system_desc"])


class ClassifyWiringTests(unittest.TestCase):
    def test_mdns_ssdp_service_types_classify(self):
        k = lambda text: D.classify_device({"vendor": "", "ports": [], "text": text})["key"]
        self.assertEqual(k("_ipp._tcp.local"), "printer")
        self.assertEqual(k("_googlecast._tcp.local"), "iot")
        self.assertEqual(k("_apple-mobdev._tcp.local"), "mobile")
        self.assertEqual(k("Linux UPnP/1.0 Roku/9.4 roku:ecp"), "iot")


if __name__ == "__main__":
    unittest.main()
