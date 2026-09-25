"""Targeted analyst handoff and passive enrichment regression tests."""
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from analyst_review import initial
from analyst_workplan import build_plan, markdown
from device_inventory import role_candidates
from ieee_registry import refresh
from sql_discovery import parse_response, discover


class AnalystWorkplanTests(unittest.TestCase):
    def test_observed_services_trigger_scoped_tasks_and_evidence_state(self):
        with TemporaryDirectory() as folder:
            root=Path(folder)
            meta={"targets":["192.0.2.0/28"],"exclusions":["192.0.2.9"],
                  "id":"DEMO","client":"Örnek","project":"Test","ad":{"mode":"joined"},
                  "host_snapshot":{"default_routes":[{"gateway":"192.0.2.1"}]}}
            inventory={"devices":[
                {"ip":"192.0.2.5","ports":[{"port":"445"},{"port":"88"},{"port":"389"}],
                 "confidence":"düşük","evidence":"targets/demo/raw/nmap.xml"},
                {"ip":"192.0.2.6","ports":[{"port":"1433"},{"port":"443"}],
                 "confidence":"orta","evidence":"targets/demo/raw/nmap.xml"},
                {"ip":"192.0.2.9","ports":[{"port":"1433"}],"confidence":"düşük"},
                {"ip":"198.51.100.7","ports":[{"port":"445"}],"confidence":"düşük"}]}
            review=initial()
            first=build_plan(root,meta,[],review,inventory,[])
            cards={task['case']:task for task in first['tasks']}
            for case in ('AD','AD-POLICY','SHARES','DATABASE','PATCH','AUTH','IDOR','PERIMETER'):
                self.assertIn(case,cards)
            self.assertEqual(cards['DATABASE']['targets'],['192.0.2.6'])
            self.assertNotIn('198.51.100.7',markdown(first))
            self.assertNotIn('192.0.2.9',markdown(first))
            self.assertIn('Get-ADDefaultDomainPasswordPolicy',markdown(first))
            self.assertIn('smb2-security-mode',markdown(first))
            self.assertNotIn('hydra ',markdown(first))
            proof=root/'proof.txt'
            proof.write_text('synthetic review',encoding='utf-8')
            item=next(row for row in review['cases'] if row['id']=='SHARES')
            item.update(state='test edildi',evidence='proof.txt',sha256=hashlib.sha256(proof.read_bytes()).hexdigest())
            done=build_plan(root,meta,[],review,inventory,[])
            self.assertEqual(next(row for row in done['tasks'] if row['case']=='SHARES')['status'],'tamamlandı')
            proof.write_text('changed',encoding='utf-8')
            changed=build_plan(root,meta,[],review,inventory,[])
            self.assertEqual(next(row for row in changed['tasks'] if row['case']=='SHARES')['status'],'kanıt eksik')

    def test_sql_browser_response_is_parsed_without_active_login(self):
        body=b'ServerName;SQL01;InstanceName;ERP;IsClustered;No;Version;16.0.1;tcp;51433;;'
        response=b'\x05'+len(body).to_bytes(2,'little')+body
        self.assertEqual(parse_response(response)[0]['tcp_port'],51433)
        self.assertEqual(parse_response(b'\x00'+response[1:]),[])

    def test_sql_discovery_one_query_per_address_and_recorded_summary(self):
        with TemporaryDirectory() as folder:
            raw=Path(folder)/'targets'/'scope'/'raw'
            raw.mkdir(parents=True)
            called=[]
            def fake(ip):
                called.append(ip)
                return {'ip':ip,'status':'ok','instances':[{'name':'ERP','tcp_port':51433}],
                        'response_sha256':'abc'}
            events=[]
            with patch('sql_discovery.query',side_effect=fake):
                discover(['192.0.2.5','192.0.2.5'],raw,events,250)
            self.assertEqual(called,['192.0.2.5'])
            self.assertEqual(events[0]['responding_count'],1)
            self.assertTrue((raw/'sql_browser_192.0.2.5.json').is_file())
            self.assertTrue((raw/'sql_browser_summary.json').is_file())

    def test_roles_require_independent_evidence(self):
        roles=role_candidates([{"port":"88"},{"port":"389"},{"port":"1433"}],"Unknown",True)
        names={item['role'] for item in roles}
        self.assertIn('Etki alanı denetleyicisi adayı',names)
        self.assertIn('SQL Server adayı',names)
        self.assertIn('Ağ geçidi',names)
        self.assertNotIn('Güvenlik duvarı ürünü adayı',names)

    def test_ieee_refresh_rejects_invalid_response_and_preserves_cache(self):
        with TemporaryDirectory() as folder:
            dest=Path(folder)
            existing=dest/'oui.csv'
            existing.write_text('cached',encoding='utf-8')
            class Response(io.BytesIO):
                def __enter__(self): return self
                def __exit__(self,*_): self.close()
            result=refresh(dest,opener=lambda url,timeout:Response(b'wrong,columns\n'))
            self.assertEqual(result['oui.csv']['status'],'unavailable')
            self.assertEqual(existing.read_text(encoding='utf-8'),'cached')
            self.assertTrue((dest/'SOURCE_MANIFEST.json').is_file())


if __name__=='__main__':
    unittest.main()
