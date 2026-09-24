"""Inventory classification must use authorized evidence and express uncertainty."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from device_inventory import build_inventory, vendor_for, classify
from tui import Console
import report_v2
from unittest.mock import patch


class DeviceInventoryTests(unittest.TestCase):
    def test_scope_mac_vendor_and_duplicate_proxy_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            raw=root/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            (root/'nmap-prefixes').write_text('001122 Example Printer Corp\n',encoding='utf-8')
            (raw/'nmap_cidr.xml').write_text('<nmaprun>'
                '<host><address addr="192.0.2.5" addrtype="ipv4"/><ports>'
                '<port portid="9100" protocol="tcp"><state state="open"/></port></ports></host>'
                '<host><address addr="192.0.2.37" addrtype="ipv4"/><ports/></host>'
                '<host><address addr="198.51.100.1" addrtype="ipv4"/><ports/></host>'
                '</nmaprun>',encoding='utf-8')
            meta={'targets':['192.0.2.0/24'],'exclusions':['192.0.2.7']}
            neighbours={'192.0.2.5':{'mac':'00:11:22:33:44:55','device':'eth0'},
                        '192.0.2.37':{'mac':'00:11:22:33:44:55','device':'eth0'},
                        '198.51.100.1':{'mac':'00:11:22:33:44:55','device':'eth0'}}
            result=build_inventory(root,meta,neighbours=neighbours,oui_paths=[root/'nmap-prefixes'])
            self.assertEqual(result['host_count'],2)
            self.assertEqual(result['mac_count'],2)
            one=result['devices'][0]
            self.assertEqual(one['vendor'],'Example Printer Corp')
            self.assertEqual(one['category'],'Yazıcı adayı')
            self.assertEqual(one['confidence'],'belirsiz')
            self.assertTrue(any('vekil ARP' in note for note in one['notices']))
            self.assertEqual(json.loads((root/'DEVICE_INVENTORY.json').read_text())['host_count'],2)

    def test_local_random_mac_not_trusted_as_ieee_vendor(self):
        vendor,source=vendor_for('02:11:22:33:44:55',{'021122':'Imaginary Co'})
        self.assertEqual(source,'local')
        self.assertNotEqual(vendor,'Imaginary Co')

    def test_snmp_sysdescr_adds_explicit_device_identity_signal(self):
        category,confidence,signals=classify('Bilinmiyor',[], 'Fortinet FortiOS 7.0')
        self.assertEqual(category,'Güvenlik cihazı adayı')
        self.assertEqual(confidence,'orta')
        self.assertTrue(any('SNMP sysDescr' in signal for signal in signals))

    def test_progress_uses_nmap_percentage_and_unknown_otherwise(self):
        self.assertEqual(Console.scan_progress('Connect Scan Timing: About 63.25% done; ETC: 14:20'),63.25)
        self.assertEqual(Console.scan_progress('<nmaprun><taskprogress task="SYN Stealth Scan" percent="48.70" remaining="20"/></nmaprun>'),48.7)
        self.assertIsNone(Console.scan_progress('No timing available'))

    def test_inventory_appears_in_html_and_both_pdfs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'engagement.json').write_text(json.dumps({'targets':['192.0.2.0/24'],
                'client':'Example','project':'Device QA','tester':'Tester','profile':'network','status':'completed'}))
            (root/'steps.json').write_text('[]')
            raw=root/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            (raw/'nmap_cidr.xml').write_text('<nmaprun><host>'
                '<address addr="192.0.2.5" addrtype="ipv4"/>'
                '<address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>'
                '<ports><port portid="22" protocol="tcp"><state state="open"/>'
                '<service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>')
            with patch.object(sys,'argv',['report_v2.py',str(root)]):
                report_v2.main()
            document=(root/'REPORT.html').read_text()
            self.assertIn('Cihaz ve MAC envanteri',document)
            self.assertIn('VMware',document)
            self.assertIn('href="DEVICE_INVENTORY.json"',document)
            self.assertTrue((root/'TEKNIK_RAPOR.pdf').stat().st_size>1000)
            self.assertTrue((root/'YONETICI_OZETI.pdf').stat().st_size>1000)


if __name__=='__main__':unittest.main()
