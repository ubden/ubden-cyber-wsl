"""CIDR discovery must limit subsequent service scans, including failure paths."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wizard
from report_v2 import read_data


class CidrDiscoveryTests(unittest.TestCase):
    META={'profile':'network','exclusions':[],'max_rate':20,'top_ports':100,'nuclei_templates':''}

    @staticmethod
    def fake_command(up, calls, fail=False):
        def run(name,argv,folder,events,timeout=900):
            calls.append((name,argv))
            if name=='discovery_hosts':
                if fail:
                    result={'step':name,'status':'timeout'}
                else:
                    xml=Path(argv[argv.index('-oX')+1])
                    xml.write_text('<nmaprun>'+''.join(
                        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>'
                        for ip in up)+'</nmaprun>')
                    result={'step':name,'status':'ok'}
            elif name in ('port_discovery','nmap_cidr'):
                Path(argv[argv.index('-oX')+1]).write_text('<nmaprun>'+''.join(
                    f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports/></host>'
                    for ip in up)+'</nmaprun>')
                result={'step':name,'status':'ok'}
            else:
                Path(argv[argv.index('-oX')+1]).write_text('<nmaprun/>')
                result={'step':name,'status':'ok'}
            events.append(result)
            return result
        return run

    def test_11_live_hosts_only_one_batched_service_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];calls=[]
            up=[f'192.0.2.{x}' for x in range(1,12)]
            with patch.object(wizard,'command',side_effect=self.fake_command(up,calls)), \
                    patch.object(wizard,'icmp_fallback',return_value=[]):
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual(len(calls),2)
            self.assertEqual([name for name,_ in calls],['discovery_hosts','port_discovery'])
            self.assertIn('-sS',calls[1][1]);self.assertNotIn('-sV',calls[1][1])
            self.assertIn('-sn',calls[0][1]);self.assertNotIn('-Pn',calls[0][1])
            self.assertIn('--disable-arp-ping',calls[0][1])
            self.assertIn('--discovery-ignore-rst',calls[0][1])
            self.assertIn('-Pn',calls[1][1]);self.assertIn('-iL',calls[1][1])
            live_file=Path(calls[1][1][calls[1][1].index('-iL')+1])
            self.assertEqual(live_file.read_text().splitlines(),up)
            path=root/'targets'/'192.0.2.0_24'/'raw'/'discovery_summary.json'
            summary=json.loads(path.read_text())
            self.assertEqual(summary['eligible_count'],254)
            self.assertEqual(summary['responding_count'],11)
            self.assertEqual(summary['unresponsive_count'],243)

    def test_cidr_open_ports_use_one_batched_audit_instead_of_per_host_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);calls=[];events=[]
            up=['192.0.2.5','192.0.2.37']
            baseline=self.fake_command(up,calls)
            def fake(name,argv,folder,events,timeout=900):
                if name not in ('port_discovery','nmap_cidr'):
                    return baseline(name,argv,folder,events,timeout)
                calls.append((name,argv))
                xml=Path(argv[argv.index('-oX')+1])
                xml.write_text('<nmaprun>'
                    '<host><address addr="192.0.2.5" addrtype="ipv4"/><ports>'
                    '<port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
                    '<host><address addr="192.0.2.37" addrtype="ipv4"/><ports>'
                    '<port protocol="tcp" portid="22"><state state="open"/></port></ports></host>'
                    '</nmaprun>')
                record={'step':name,'status':'ok'}
                events.append(record)
                return record
            with patch.object(wizard,'command',side_effect=fake), \
                    patch.object(wizard,'icmp_fallback',return_value=[]):
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual([name for name,_ in calls],['discovery_hosts','port_discovery','nmap_cidr','audit_cidr'])
            self.assertNotIn('-sV',calls[1][1]);self.assertIn('-sV',calls[2][1])
            self.assertEqual(Path(calls[2][1][calls[2][1].index('-iL')+1]).read_text().splitlines(),up)
            audit=calls[-1][1]
            self.assertEqual(audit[audit.index('-p')+1],'22,443')
            self.assertEqual(Path(audit[audit.index('-iL')+1]).read_text().splitlines(),up)

    def test_batched_nse_evidence_is_attributed_to_each_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw=root/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            (root/'engagement.json').write_text('{"targets":["192.0.2.0/24"]}')
            (raw/'audit_cidr.xml').write_text('<nmaprun><host><address addr="192.0.2.5"/>'
                '<ports><port><script id="ssl-enum-ciphers" output="TLSv1.0: enabled"/></port></ports></host>'
                '<host><address addr="192.0.2.37"/><ports><port>'
                '<script id="ssl-enum-ciphers" output="TLSv1.1: enabled"/></port></ports></host></nmaprun>')
            *_,findings,_=read_data(root)
            self.assertEqual({f['asset'] for f in findings},{'192.0.2.5','192.0.2.37'})

    def test_254_responses_still_use_one_rate_limited_service_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];calls=[]
            up=[f'192.0.2.{i}' for i in range(1,255)]
            with patch.object(wizard,'command',side_effect=self.fake_command(up,calls)), \
                    patch.object(wizard,'icmp_fallback',return_value=up), \
                    patch.object(wizard.UI,'say') as say:
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual([name for name,_ in calls],['discovery_hosts','port_discovery'])
            self.assertEqual(calls[-1][1][calls[-1][1].index('--max-rate')+1],'20')
            self.assertTrue(any('Bütün IP adresleri yanıt verdi' in call.args[0] for call in say.call_args_list))
            summary=json.loads((root/'targets'/'192.0.2.0_24'/'raw'/'discovery_summary.json').read_text())
            self.assertEqual(summary['nmap_responding_count'],254)
            self.assertEqual(summary['icmp_responding_count'],254)

    def test_254_discovered_only_one_open_host_gets_version_and_nse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);calls=[];events=[]
            up=[f'192.0.2.{i}' for i in range(1,255)]
            base=self.fake_command(up,calls)
            def fake(name,argv,folder,events,timeout=900):
                if name not in ('port_discovery','nmap_cidr'):
                    return base(name,argv,folder,events,timeout)
                calls.append((name,argv))
                Path(argv[argv.index('-oX')+1]).write_text('<nmaprun><host>'
                    '<address addr="192.0.2.37" addrtype="ipv4"/><ports><port portid="443" protocol="tcp">'
                    '<state state="open"/></port></ports></host></nmaprun>')
                row={'step':name,'status':'ok'};events.append(row);return row
            with patch.object(wizard,'command',side_effect=fake), \
                    patch.object(wizard,'icmp_fallback',return_value=up):
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual([name for name,_ in calls],
                             ['discovery_hosts','port_discovery','nmap_cidr','audit_cidr'])
            self.assertNotIn('-sV',calls[1][1])
            self.assertEqual(Path(calls[2][1][calls[2][1].index('-iL')+1]).read_text().splitlines(),
                             ['192.0.2.37'])
            self.assertEqual(Path(calls[3][1][calls[3][1].index('-iL')+1]).read_text().splitlines(),
                             ['192.0.2.37'])

    def test_full_cidr_timeout_budget_is_not_one_hour(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];timeouts=[]
            up=[f'192.0.2.{i}' for i in range(1,255)]
            normal=self.fake_command(up,[])
            def timed(name,argv,folder,events,timeout=900):
                timeouts.append((name,timeout,argv))
                return normal(name,argv,folder,events,timeout)
            meta=dict(self.META,top_ports=1000)
            with patch.object(wizard,'command',side_effect=timed), \
                    patch.object(wizard,'icmp_fallback',return_value=up):
                wizard.scan_target('192.0.2.0/24',meta,root,events)
            _,timeout,argv=next(item for item in timeouts if item[0]=='port_discovery')
            self.assertGreater(timeout,3600)
            self.assertNotIn('--host-timeout',argv)

    def test_no_response_or_failed_discovery_never_scans_all(self):
        for failed,expected in ((False,'no_hosts'),(True,'error')):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);events=[];calls=[]
                with patch.object(wizard,'command',side_effect=self.fake_command([],calls,failed)), \
                        patch.object(wizard,'icmp_fallback',return_value=[]):
                    wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
                self.assertEqual(len(calls),1)
                summary=json.loads((root/'targets'/'192.0.2.0_24'/'raw'/'discovery_summary.json').read_text())
                self.assertEqual(summary['status'],expected)
                self.assertEqual(summary['unresponsive_count'],None if failed else 254)

    def test_exclusion_not_probed_and_untrusted_discovery_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);calls=[];events=[]
            meta=dict(self.META,exclusions=['192.0.2.3'])
            with patch.object(wizard,'command',side_effect=self.fake_command(['192.0.2.3'],calls)), \
                    patch.object(wizard,'icmp_fallback',return_value=[]):
                wizard.scan_target('192.0.2.0/24',meta,root,events)
            self.assertEqual(len(calls),1)
            scope=(root/'targets'/'192.0.2.0_24'/'raw'/'discovery_targets.txt').read_text()
            self.assertNotIn('192.0.2.3\n',scope)
            self.assertEqual(events[-1]['status'],'error')

    def test_timeout_still_scans_ping_responsive_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];calls=[]
            up=['192.0.2.37']
            with patch.object(wizard,'command',side_effect=self.fake_command(up,calls,fail=True)), \
                    patch.object(wizard,'icmp_fallback',return_value=up) as ping:
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual([name for name,_ in calls],['discovery_hosts','port_discovery'])
            self.assertEqual(Path(calls[1][1][-1]).read_text().splitlines(),up)
            ping.assert_called_once()
            summary=json.loads((root/'targets'/'192.0.2.0_24'/'raw'/'discovery_summary.json').read_text())
            self.assertEqual(summary['status'],'partial')
            self.assertEqual(summary['responding_hosts'],up)
            self.assertTrue(summary['fallback_used'])

    def test_ping_supplements_partial_nmap_list_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];calls=[]
            with patch.object(wizard,'command',side_effect=self.fake_command(['192.0.2.5'],calls)), \
                    patch.object(wizard,'icmp_fallback',return_value=['192.0.2.5','192.0.2.37']):
                wizard.scan_target('192.0.2.0/24',dict(self.META),root,events)
            self.assertEqual(Path(calls[1][1][-1]).read_text().splitlines(),
                             ['192.0.2.5','192.0.2.37'])
            summary=json.loads((root/'targets'/'192.0.2.0_24'/'raw'/'discovery_summary.json').read_text())
            self.assertEqual(summary['responding_count'],2)

    def test_ping_fallback_uses_eligible_addresses_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);calls=[];events=[]
            meta=dict(self.META,exclusions=['192.0.2.37'])
            def ping(allowed,*args):
                self.assertNotIn('192.0.2.37',allowed)
                return ['192.0.2.5']
            with patch.object(wizard,'command',side_effect=self.fake_command([],calls,fail=True)), \
                    patch.object(wizard,'icmp_fallback',side_effect=ping):
                wizard.scan_target('192.0.2.0/24',meta,root,events)
            self.assertEqual(Path(calls[1][1][-1]).read_text().splitlines(),['192.0.2.5'])

    def test_local_ping_probe_marks_only_successful_address(self):
        from types import SimpleNamespace
        def simulated_ping(args,**kwargs):
            self.assertEqual(args[:5],['ping','-n','-c','1','-W'])
            self.assertEqual(args[-2],'-4')
            return SimpleNamespace(returncode=0 if args[-1]=='192.0.2.37' else 1)
        with patch.object(wizard.shutil,'which',return_value='/usr/bin/ping'), \
                patch.object(wizard.subprocess,'run',side_effect=simulated_ping):
            self.assertEqual(wizard.icmp_fallback(['192.0.2.5','192.0.2.37'],50,4),
                             ['192.0.2.37'])

    def test_explicit_single_ip_still_scans_without_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            calls=[];events=[]
            with patch.object(wizard,'command',side_effect=self.fake_command([],calls)):
                wizard.scan_target('192.0.2.42',dict(self.META),Path(directory),events)
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][0],'nmap_192.0.2.42')
            self.assertIn('-T3',calls[0][1])
            self.assertEqual(calls[0][1][calls[0][1].index('--host-timeout')+1],'5m')

    def test_batched_xml_keeps_each_hosts_services_separate_in_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw=root/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            xml=raw/'nmap_cidr.xml'
            xml.write_text('<nmaprun>'
                '<host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host>'
                '<host><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>'
                '</nmaprun>')
            ports=wizard.open_tcp_ports_by_host(xml,['192.0.2.1','192.0.2.2'])
            self.assertEqual(ports,{'192.0.2.1':[443],'192.0.2.2':[22]})
            (root/'engagement.json').write_text('{"targets":["192.0.2.0/24"]}')
            *_,hosts,findings,review=read_data(root)
            self.assertEqual({h['ip']:h['ports'][0]['port'] for h in hosts},
                             {'192.0.2.1':'443','192.0.2.2':'22'})


if __name__=='__main__': unittest.main()
