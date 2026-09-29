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


class PcapLldpTests(unittest.TestCase):
    def test_pktmon_pcap_lldp_frame(self):
        def tlv(t, v): return struct.pack(">H", (t << 9) | len(v)) + v
        lldp = tlv(1, b"\x04" + bytes.fromhex("aabbccddeeff")) + tlv(2, b"\x05Gi1/1") + tlv(5, b"SW1") + tlv(0, b"")
        frame = bytes.fromhex("0180c200000e") + bytes.fromhex("aabbccddeeff") + b"\x88\xcc" + lldp
        gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        rec = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        out = DP._parse_pcap_lldp(gh + rec)
        self.assertIn("aabbccddeeff", out)
        self.assertEqual(out["aabbccddeeff"]["system_name"], "SW1")

    def test_pktmon_pcap_cdp_frame(self):
        def tlv(t, v): return struct.pack(">HH", t, 4 + len(v)) + v
        cdp = b"\x02\xb4\x00\x00" + tlv(0x0001, b"SW-CORE") + tlv(0x0005, b"Cisco IOS 15.2") + tlv(0x0006, b"WS-C2960") + tlv(0x0003, b"Gi0/1")
        frame = bytes.fromhex("01000ccccccc") + bytes.fromhex("aabbccddeeff") + struct.pack(">H", len(cdp) + 8) + b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
        gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        rec = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        out = DP._parse_pcap_lldp(gh + rec)
        self.assertIn("SW-CORE", out)
        self.assertEqual(out["SW-CORE"]["platform"], "WS-C2960")
        self.assertIn("Cisco IOS", out["SW-CORE"]["software"])


class ApplianceTests(unittest.TestCase):
    def test_webmin_and_fortigate(self):
        import appliance_probe as AP
        AP._fetch = lambda url, **k: ({"Server": "MiniServ/2.021"}, "") if url.endswith(":10000/") else (None, None)
        self.assertEqual(AP.webmin("10.0.0.1", {10000})["version"], "2.021")
        AP._fetch = lambda url, **k: (None, "<title>FortiGate</title> fgt_lang /remote/login FortiOS v7.2.4")
        fg = AP.fortigate("10.0.0.2", {443})
        self.assertEqual(fg["product"], "Fortinet FortiGate")
        self.assertEqual(fg["version"], "7.2.4")

    def test_ilo_idrac_qnap_synology(self):
        import appliance_probe as AP
        ilo_xml = ("<RIMP><HSI><SBSN>CZ21510CJD</SBSN><SPN>ProLiant DL380 Gen10</SPN></HSI>"
                   "<MP><PN>Integrated Lights-Out 5 (iLO 5)</PN><FWRI>2.44</FWRI></MP></RIMP>")
        AP._fetch = lambda url, **k: (None, ilo_xml) if "xmldata" in url else (None, None)
        ilo = AP.ilo("10.0.0.1", {443})
        self.assertEqual(ilo["version"], "2.44")
        self.assertEqual(ilo["server_model"], "ProLiant DL380 Gen10")
        AP._fetch = lambda url, **k: (None, '{"Attributes":{"FwVer":"6.10.00.00"}}') if "bmc/info" in url else (None, None)
        self.assertEqual(AP.idrac("10.0.0.2", {443})["version"], "6.10.00.00")
        AP._fetch = lambda url, **k: (None, "<QDocRoot><modelName>TS-464</modelName><version>5.1.2</version><build>20240101</build></QDocRoot>") if "authLogin" in url else (None, None)
        q = AP.qnap("10.0.0.3", {8080})
        self.assertEqual(q["version"], "5.1.2")
        self.assertEqual(q["build"], "20240101")
        AP._fetch = lambda url, **k: (None, '{"data":{"SYNO.API.Auth":{}}}') if "SYNO.API.Info" in url else (None, "<title>DSM 7.2-64570</title>")
        self.assertEqual(AP.synology("10.0.0.4", {5000})["version"], "7.2-64570")


class ClassifyWiringTests(unittest.TestCase):
    def test_mdns_ssdp_service_types_classify(self):
        k = lambda text: D.classify_device({"vendor": "", "ports": [], "text": text})["key"]
        self.assertEqual(k("_ipp._tcp.local"), "printer")
        self.assertEqual(k("_googlecast._tcp.local"), "iot")
        self.assertEqual(k("_apple-mobdev._tcp.local"), "mobile")
        self.assertEqual(k("Linux UPnP/1.0 Roku/9.4 roku:ecp"), "iot")


if __name__ == "__main__":
    unittest.main()
