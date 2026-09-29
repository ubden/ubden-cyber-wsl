"""Professional-report finding coverage: EOL, anon-FTP, telnet, SMB, AD policy.

Mirrors the finding types shown in reference Assos-style pentest reports. Each is
evidence-led: generated as a draft (taslak) observation from recorded evidence.
"""
import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import eol_data
import report_v2


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="172.16.0.2" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="1433"><state state="open"/>
    <service name="ms-sql-s" product="Microsoft SQL Server" version="2014" extrainfo="SP3"/></port>
  </ports>
 </host>
 <host>
  <address addr="10.0.0.20" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="443"><state state="open"/>
    <service name="https" product="VMware ESXi" version="6.7.0"/></port>
  </ports>
 </host>
</nmaprun>
"""

AUDIT_XML = ('<?xml version="1.0"?>\n<nmaprun>\n'
 '<host><address addr="10.0.11.59" addrtype="ipv4"/><ports>'
 '<port protocol="tcp" portid="21"><state state="open"/>'
 '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>'
 '<port protocol="tcp" portid="23"><state state="open"/>'
 '<script id="telnet-encryption" output="Telnet server does not support encryption"/></port>'
 '</ports>'
 '<hostscript>'
 '<script id="smb2-security-mode" output="Message signing enabled but not required"/>'
 '<script id="smb-enum-shares" output="  account_used: guest&#10;  \\\\10.0.0.5\\LOGOSQLBACKUP: &#10;    Type: STYPE_DISKTREE&#10;    Anonymous access: READ/WRITE&#10;    Current user access: READ/WRITE"/>'
 '</hostscript></host>\n</nmaprun>\n')

AD_JSON = {"status": "ok", "domain": "assospharma.local", "dc": "ASSOSPHARMA-DC",
           "password_policy": {"min_length": 6, "complexity_enabled": True, "lockout_threshold": 0},
           "machine_account_quota": 10,
           "domain_admins": {"group": "Domain Admins", "count": 9, "members": ["eset", "Administrator", "tsungur"]}}


def _run_dir(with_audit=True, with_ad=True):
    root = Path(tempfile.mkdtemp())
    (root / 'engagement.json').write_text(json.dumps({
        'targets': ['10.0.0.0/16'], 'client': 'Assos', 'project': 'QA',
        'tester': 'Tester', 'status': 'completed', 'profile': 'network'}), encoding='utf-8')
    raw = root / 'targets' / 'net' / 'raw'
    raw.mkdir(parents=True)
    (raw / 'nmap_net.xml').write_text(NMAP_XML, encoding='utf-8')
    if with_audit:
        (raw / 'audit_10.0.11.59.xml').write_text(AUDIT_XML, encoding='utf-8')
    if with_ad:
        (root / 'AD_ASSESSMENT.json').write_text(json.dumps(AD_JSON), encoding='utf-8')
    return root


class EolDatasetTests(unittest.TestCase):
    def test_esxi_and_mssql_past_eol_flagged(self):
        past = datetime.date(2026, 9, 28)
        self.assertEqual(eol_data.detect('VMware ESXi', '6.7.0', today=past)['name'], 'VMware ESXi')
        self.assertEqual(eol_data.detect('Microsoft SQL Server', '2014', today=past)['eol_date'], '2024-07-09')

    def test_supported_release_not_flagged(self):
        early = datetime.date(2020, 1, 1)
        self.assertIsNone(eol_data.detect('Microsoft SQL Server', '2019', today=early))
        self.assertIsNone(eol_data.detect('nginx', '1.24.0', today=early))

    def test_unknown_product_returns_none(self):
        self.assertIsNone(eol_data.detect('OpenSSH', '8.0'))
        self.assertIsNone(eol_data.detect('', ''))


class ReportFindingTests(unittest.TestCase):
    def _titles(self, root):
        *_, findings, _ = report_v2.read_data(root)
        return [f['title'] for f in findings]

    def test_eol_findings_from_nmap_versions(self):
        titles = self._titles(_run_dir(with_audit=False, with_ad=False))
        self.assertTrue(any('VMware ESXi' in t and 'EOL' in t for t in titles))
        self.assertTrue(any('SQL Server' in t and 'EOL' in t for t in titles))

    def test_nse_findings_ftp_telnet_smb(self):
        titles = self._titles(_run_dir(with_ad=False))
        self.assertIn('Anonim FTP erişimine izin veriliyor', titles)
        self.assertTrue(any('Telnet' in t and 'düz metin' in t for t in titles))
        self.assertIn('SMB ileti imzalama zorunlu değil', titles)
        self.assertIn('SMB paylaşımlarına erişilebiliyor', titles)

    def test_smb_share_finding_lists_writable_share(self):
        *_, findings, _ = report_v2.read_data(_run_dir(with_ad=False))
        share = next(f for f in findings if f['title'] == 'SMB paylaşımlarına erişilebiliyor')
        self.assertIn('LOGOSQLBACKUP', share['description'])
        self.assertIn('READ/WRITE', share['description'])

    def test_ad_policy_findings(self):
        titles = self._titles(_run_dir())
        self.assertTrue(any('minimum uzunluk' in t for t in titles))
        self.assertTrue(any('kilitleme eşiği' in t for t in titles))
        self.assertTrue(any('MachineAccountQuota' in t for t in titles))
        self.assertTrue(any('Domain Admin' in t for t in titles))

    def test_same_finding_across_hosts_is_grouped_with_affected_assets(self):
        # Two hosts each expose Telnet -> ONE grouped finding, not two cards.
        root = Path(tempfile.mkdtemp())
        (root / 'engagement.json').write_text(json.dumps({
            'targets': ['10.0.0.0/24'], 'client': 'C', 'project': 'P', 'tester': 'T',
            'status': 'completed', 'profile': 'network'}), encoding='utf-8')
        raw = root / 'targets' / 'net' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'nmap_net.xml').write_text(
            '<nmaprun>'
            '<host><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>'
            '<host><address addr="10.0.0.6" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>'
            '</nmaprun>', encoding='utf-8')
        *_, findings, _ = report_v2.read_data(root)
        telnet = [f for f in findings if 'Telnet' in f['title']]
        self.assertEqual(len(telnet), 1)  # grouped, not one per host
        assets = {telnet[0]['asset']} | set(telnet[0]['affected_assets'])
        self.assertEqual(assets, {'10.0.0.5:23', '10.0.0.6:23'})
        self.assertIn('2 varlıkta görüldü', telnet[0]['description'])

    def test_all_new_findings_are_drafts(self):
        _, _, _, findings, _ = report_v2.read_data(_run_dir())
        drafts = [f for f in findings if f['source'] == 'Otomatik gözlem']
        self.assertTrue(drafts)
        self.assertTrue(all(f['status'] == 'taslak' for f in drafts))


class SmbShareParserTests(unittest.TestCase):
    def test_only_readable_or_writable_shares_returned(self):
        output = ("  \\\\h\\PUBLIC: \n    Anonymous access: READ/WRITE\n"
                  "  \\\\h\\SECURE: \n    Anonymous access: <none>\n    Current user access: <none>\n")
        self.assertEqual(report_v2._parse_smb_shares(output), ['PUBLIC [READ/WRITE]'])


class AdAssessmentReadsTests(unittest.TestCase):
    """The read-only LDAP path populates password policy / MAQ / domain admins."""
    def test_inspect_collects_policy_maq_admins(self):
        import types
        from unittest.mock import patch
        import ad_assessment

        def entry(data):
            ns = {}
            for key, value in data.items():
                ns[key] = types.SimpleNamespace(
                    value=value, values=value if isinstance(value, list) else [value])
            holder = types.SimpleNamespace(**{})
            class E:
                def __contains__(self, k): return k in data
                def __getitem__(self, k): return ns[k]
            return E()

        sequence = [
            [entry({'rootDomainNamingContext': 'DC=example,DC=test'})],
            [entry({}), entry({})],          # users
            [entry({})],                     # groups
            [entry({}), entry({}), entry({})],  # computers
            [entry({'minPwdLength': 6, 'pwdProperties': 0, 'lockoutThreshold': 0,
                    'ms-DS-MachineAccountQuota': 10, 'objectSid': 'S-1-5-21-1-2-3'})],
            [entry({'member': ['CN=eset,CN=Users,DC=example,DC=test',
                               'CN=Administrator,CN=Users,DC=example,DC=test'],
                    'sAMAccountName': 'Domain Admins'})],
        ]

        class Conn:
            entries = []
            def __init__(self, *a, **k): pass
            def __enter__(self): return self
            def __exit__(self, *a): return None
            def search(self, *a, **k):
                self.entries = sequence.pop(0) if sequence else []
                return True

        fake = types.SimpleNamespace(BASE=0, NONE=0, Connection=Conn,
                                     Server=lambda *a, **k: 'srv', Tls=lambda *a, **k: 'tls')
        import sysvol_probe
        with patch.dict(sys.modules, {'ldap3': fake}), \
             patch.object(sysvol_probe, 'crawl', return_value={'status': 'skipped'}):
            result = ad_assessment.inspect('dc.example.test', 'example.test',
                                           'u@example.test', 'pw', '192.0.2.5')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['password_policy']['min_length'], 6)
        self.assertFalse(result['password_policy']['complexity_enabled'])
        self.assertEqual(result['password_policy']['lockout_threshold'], 0)
        self.assertEqual(result['machine_account_quota'], 10)
        self.assertEqual(result['domain_admins']['count'], 2)
        self.assertIn('eset', result['domain_admins']['members'])

    def test_collect_captures_names_and_membership(self):
        import types
        from unittest.mock import patch
        import ad_assessment

        class E:
            def __init__(self, d): self.d = d
            def __contains__(self, k): return k in self.d
            def __getitem__(self, k):
                v = self.d[k]
                return types.SimpleNamespace(value=v, values=v if isinstance(v, list) else [v])
        seq = [
            [E({'rootDomainNamingContext': 'DC=x'})],
            [E({'sAMAccountName': 'alice'}), E({'sAMAccountName': 'bob'})],
            [E({'sAMAccountName': 'Domain Admins'}), E({'sAMAccountName': 'HR'})],
            [E({'dNSHostName': 'PC1.x.local'}), E({'dNSHostName': 'PC2.x.local'})],
            [E({'minPwdLength': 7})],
            [E({'sAMAccountName': 'Domain Admins', 'member': ['CN=alice,CN=Users,DC=x']})],
            [E({'sAMAccountName': 'alice', 'displayName': 'Alice A',
                'memberOf': ['CN=HR,DC=x', 'CN=VPN Users,DC=x']})],
        ]

        class Conn:
            entries = []
            def search(self, *a, **k):
                self.entries = seq.pop(0) if seq else []
                return True
        with patch.dict(sys.modules, {'ldap3': types.SimpleNamespace(BASE=0)}):
            r = ad_assessment._collect(Conn(), 'DC=x', 'x.local', 'dc', 'alice@x.local')
        self.assertEqual(r['user_names'], ['alice', 'bob'])
        self.assertIn('HR', r['group_names'])
        self.assertEqual(r['computer_names'], ['PC1.x.local', 'PC2.x.local'])
        self.assertEqual(r['test_account_membership']['account'], 'alice')
        self.assertIn('VPN Users', r['test_account_membership']['groups'])

    def test_deep_enum_flags_kerberoast_groups_computers(self):
        import types, socket
        from datetime import datetime, timezone, timedelta
        from unittest.mock import patch
        import ad_assessment

        class E:
            def __init__(self, d): self.d = d
            def __contains__(self, k): return k in self.d
            def __getitem__(self, k):
                v = self.d[k]
                return types.SimpleNamespace(value=v, values=v if isinstance(v, list) else [v])

        now = datetime.now(timezone.utc)
        ft = lambda dt: int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1e7)
        users = [
            E({'sAMAccountName': 'svc_web', 'userAccountControl': 0x10200,
               'servicePrincipalName': ['HTTP/web'], 'adminCount': 1}),   # kerberoast + never-expires
            E({'sAMAccountName': 'joe', 'userAccountControl': 0x400200}),  # AS-REP roastable
            E({'sAMAccountName': 'guest', 'userAccountControl': 0x222}),   # disabled + passwd_notreqd
            E({'sAMAccountName': 'krbtgt', 'userAccountControl': 0x400200,
               'servicePrincipalName': ['kadmin/x']}),                     # must be excluded
        ]
        computers = [
            E({'sAMAccountName': 'DC01$', 'dNSHostName': 'dc01.x.local',
               'operatingSystem': 'Windows Server 2019 Standard',
               'lastLogonTimestamp': ft(now - timedelta(days=2))}),
            E({'sAMAccountName': 'OLD$', 'dNSHostName': 'old.x.local',
               'operatingSystem': 'Windows 7', 'lastLogonTimestamp': ft(now - timedelta(days=200))}),
        ]

        class Conn:
            entries = []
            def search(self, base, filt, **k):
                if 'objectClass=user' in filt:
                    self.entries = users
                elif 'cn=Enterprise Admins' in filt:
                    self.entries = [E({'member': ['CN=Administrator,CN=Users,DC=x']})]
                elif 'objectCategory=computer' in filt:
                    self.entries = computers
                else:
                    self.entries = []
                return True

        dns_map = {'dc01.x.local': '10.0.0.10', 'old.x.local': '10.0.0.9'}
        with patch.object(socket, 'gethostbyname', lambda h: dns_map[h]):
            out = ad_assessment._deep_enum(Conn(), 'DC=x')
        kerb = [k['account'] for k in out['kerberoastable']]
        self.assertIn('svc_web', kerb)
        self.assertNotIn('krbtgt', kerb)
        self.assertIn('joe', out['asrep_roastable'])
        self.assertNotIn('krbtgt', out['asrep_roastable'])
        self.assertIn('svc_web', out['risky_accounts']['password_never_expires'])
        self.assertIn('guest', out['risky_accounts']['disabled'])
        self.assertIn('guest', out['risky_accounts']['passwd_notreqd'])
        self.assertEqual(out['sensitive_groups']['Enterprise Admins'], ['Administrator'])
        self.assertEqual(out['computer_ip_map']['10.0.0.10'], 'dc01.x.local')
        self.assertIn('OLD', out['stale_computers'])
        self.assertNotIn('DC01', out['stale_computers'])
        self.assertEqual(out['computer_os_summary']['Windows Server 2019 Standard'], 1)

    def test_adcs_flags_esc1_when_low_priv_can_enroll(self):
        import types, struct, uuid, sys
        from unittest.mock import patch
        import ad_assessment
        # ESC1 security descriptor: Authenticated Users get Certificate-Enrollment control access.
        gid = uuid.UUID('0e10c968-78fb-11d2-90d4-00c04f79dc55').bytes_le
        sid = bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack('<I', 11)   # S-1-5-11
        body = struct.pack('<I', 0x100) + struct.pack('<I', 0x1) + gid + sid
        ace = bytes([0x05, 0x00]) + struct.pack('<H', 4 + len(body)) + body
        dacl = bytes([4, 0]) + struct.pack('<H', 8 + len(ace)) + struct.pack('<H', 1) + b'\x00\x00' + ace
        sd = bytes([1, 0]) + struct.pack('<H', 0x8004) + struct.pack('<I', 0) * 3 + struct.pack('<I', 20) + dacl

        class E:
            def __init__(self, d, raw=None): self.d = d; self._raw = raw or {}
            def __contains__(self, k): return k in self.d or k in self._raw
            def __getitem__(self, k):
                v = self.d.get(k)
                return types.SimpleNamespace(value=v, values=v if isinstance(v, list) else ([v] if k in self.d else []),
                                             raw_values=self._raw.get(k, []))

        ca = E({'cn': 'inventist-CA', 'dNSHostName': 'ca.x.local', 'certificateTemplates': ['ESC1Tmpl', 'User']})
        tmpl = E({'cn': 'ESC1Tmpl', 'msPKI-Certificate-Name-Flag': 0x1, 'msPKI-Enrollment-Flag': 0,
                  'msPKI-RA-Signature': 0, 'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2']},
                 raw={'nTSecurityDescriptor': [sd]})
        safe = E({'cn': 'User', 'msPKI-Certificate-Name-Flag': 0, 'msPKI-Enrollment-Flag': 0,
                  'msPKI-RA-Signature': 0, 'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2']},
                 raw={'nTSecurityDescriptor': [sd]})

        class Conn:
            entries = []
            def search(self, base, filt, **k):
                if 'pKIEnrollmentService' in filt: self.entries = [ca]
                elif 'pKICertificateTemplate' in filt: self.entries = [tmpl, safe]
                else: self.entries = []
                return True

        with patch.dict(sys.modules, {'ldap3': types.SimpleNamespace(SUBTREE='SUBTREE', BASE=0)}):
            out = ad_assessment._adcs(Conn(), 'CN=Configuration,DC=x', 'S-1-5-21-1-2-3')
        self.assertEqual(out['cas'][0]['name'], 'inventist-CA')
        escs = {(e['esc'], e['template']) for e in out['esc']}
        self.assertIn(('ESC1', 'ESC1Tmpl'), escs)
        self.assertNotIn(('ESC1', 'User'), escs)   # not SAN-free -> not ESC1

    def test_sysvol_cpassword_roundtrip(self):
        import base64, sysvol_probe
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
        except Exception:
            self.skipTest('cryptography unavailable')
        plain = 'P@ssw0rd!'
        padder = padding.PKCS7(128).padder()
        data = padder.update(plain.encode('utf-16-le')) + padder.finalize()
        enc = Cipher(algorithms.AES(sysvol_probe._GPP_KEY), modes.CBC(b'\x00' * 16)).encryptor()
        cpw = base64.b64encode(enc.update(data) + enc.finalize()).decode()
        self.assertEqual(sysvol_probe.decrypt_cpassword(cpw), plain)

    def test_gpo_ou_and_admin_groups(self):
        import types, sys
        from unittest.mock import patch
        import ad_assessment

        class E:
            def __init__(self, d): self.d = d
            def __contains__(self, k): return k in self.d
            def __getitem__(self, k):
                v = self.d.get(k)
                return types.SimpleNamespace(value=v, values=v if isinstance(v, list) else ([v] if k in self.d else []))

        guid = '{12345678-1234-1234-1234-123456789012}'
        ou_dn = 'OU=Users,DC=x'
        gpo = E({'cn': guid, 'displayName': 'Local Admin Policy'})
        ou = E({'ou': 'Users', 'distinguishedName': ou_dn,
                'gPLink': f'[LDAP://CN={guid},CN=Policies,CN=System,DC=x;0]'})
        grp = E({'sAMAccountName': 'LocalAdmin_Policy', 'description': 'yerel yönetici',
                 'member': ['CN=elektra,CN=Users,DC=x', 'CN=brasco,DC=x']})

        class Conn:
            entries = []
            def search(self, base, filt, search_scope=None, **k):
                if 'groupPolicyContainer' in filt: self.entries = [gpo]
                elif 'organizationalUnit' in filt: self.entries = [ou]
                elif 'objectClass=user' in filt and base == ou_dn:
                    self.entries = [E({'cn': 'a'}), E({'cn': 'b'}), E({'cn': 'c'})]
                elif filt == '(objectClass=group)': self.entries = [grp]
                else: self.entries = []
                return True

        with patch.dict(sys.modules, {'ldap3': types.SimpleNamespace(SUBTREE='s', LEVEL='l', BASE=0)}):
            out = ad_assessment._gpo_ou(Conn(), 'DC=x')
        self.assertEqual(out['gpos'][0]['name'], 'Local Admin Policy')
        self.assertIn(ou_dn, out['gpos'][0]['links'])
        self.assertEqual(out['ou_user_distribution'][0]['users'], 3)
        self.assertIn('LocalAdmin_Policy', out['admin_like_groups'])
        self.assertIn('elektra', out['admin_like_groups']['LocalAdmin_Policy']['members'])

    def test_account_acl_risk_detects_genericall_by_non_admin(self):
        import struct, types, sys
        from unittest.mock import patch
        import ad_assessment
        sid = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + b''.join(struct.pack('<I', x) for x in (21, 1, 2, 3, 1105))
        ace = bytes([0x00, 0x00]) + struct.pack('<H', 8 + len(sid)) + struct.pack('<I', 0x10000000) + sid
        dacl = bytes([4, 0]) + struct.pack('<H', 8 + len(ace)) + struct.pack('<H', 1) + b'\x00\x00' + ace
        sd = bytes([1, 0]) + struct.pack('<H', 0x8004) + struct.pack('<I', 0) * 3 + struct.pack('<I', 20) + dacl

        class E:
            def __init__(self, d, raw=None): self.d = d; self._raw = raw or {}
            def __contains__(self, k): return k in self.d or k in self._raw
            def __getitem__(self, k):
                v = self.d.get(k)
                return types.SimpleNamespace(value=v, values=v if isinstance(v, list) else ([v] if k in self.d else []),
                                             raw_values=self._raw.get(k, []))

        class Conn:
            entries = []
            def search(self, base, filt, search_scope=None, **k):
                if 'objectSid=' in filt:
                    self.entries = [E({'sAMAccountName': 'helpdesk', 'objectClass': ['user']})]
                elif filt == '(objectClass=*)':
                    self.entries = [E({}, raw={'nTSecurityDescriptor': [sd]})]
                else:
                    self.entries = []
                return True

        safe = ad_assessment._safe_sids('S-1-5-21-1-2-3')
        with patch.dict(sys.modules, {'ldap3': types.SimpleNamespace(BASE=0, SUBTREE='s')}):
            risks = ad_assessment._account_acl_risks(Conn(), 'CN=svc.da,DC=x', 'DC=x', safe, None, {})
        self.assertTrue(risks)
        self.assertEqual(risks[0]['principal'], 'helpdesk')
        self.assertIn('Tam kontrol', risks[0]['right'])
        # a safe principal (Domain Admins, -512) must NOT be flagged
        self.assertIn('S-1-5-21-1-2-3-512', safe)

    def test_falls_back_to_insecure_ldaps_when_strict_fails(self):
        import types
        from unittest.mock import patch
        import ad_assessment

        class E:
            def __init__(self, data): self._d = data
            def __contains__(self, k): return k in self._d
            def __getitem__(self, k): return types.SimpleNamespace(value=self._d[k])
        seq = [[E({'rootDomainNamingContext': 'DC=x'})], [E({})], [E({})], [E({})], [E({})], []]
        attempts = {"n": 0}

        class Conn:
            entries = []
            def __init__(self, *a, **k):
                attempts["n"] += 1
                if attempts["n"] == 1:  # LDAPS-strict cert handshake fails
                    raise RuntimeError("LDAPSocketOpenError")
            def search(self, *a, **k):
                self.entries = seq.pop(0) if seq else []
                return True
            def unbind(self): pass

        fake = types.SimpleNamespace(BASE=0, NONE=0, Connection=Conn,
                                     Server=lambda *a, **k: 's', Tls=lambda *a, **k: 't')
        import sysvol_probe
        with patch.dict(sys.modules, {'ldap3': fake}), \
             patch.object(sysvol_probe, 'crawl', return_value={'status': 'skipped'}):
            res = ad_assessment.inspect('dc.x.test', 'x.test', 'u', 'p', '192.0.2.5')
        self.assertEqual(res['status'], 'ok')
        self.assertEqual(res['transport'], 'ldaps_insecure')
        self.assertIn('security_warning', res)

    def test_plaintext_is_opt_in_only(self):
        import types
        from unittest.mock import patch
        import ad_assessment

        tried = []

        class Conn:
            entries = []
            def __init__(self, *a, **k):
                # Record the port so we can see which transports were attempted, then fail.
                raise RuntimeError("LDAPSocketOpenError")

        def server(host, **k):
            tried.append(k.get("port"))
            return "s"

        fake = types.SimpleNamespace(BASE=0, NONE=0, Connection=Conn, Server=server,
                                     Tls=lambda *a, **k: 't')
        with patch.dict(sys.modules, {'ldap3': fake}):
            res = ad_assessment.inspect('dc.x.test', 'x.test', 'u', 'p', '192.0.2.5')
        self.assertEqual(res['status'], 'error')
        self.assertEqual(len(tried), 3)  # ldaps_strict, ldaps_insecure, starttls — no plaintext
        tried.clear()
        with patch.dict(sys.modules, {'ldap3': fake}):
            ad_assessment.inspect('dc.x.test', 'x.test', 'u', 'p', '192.0.2.5', allow_plaintext=True)
        self.assertEqual(len(tried), 4)  # opt-in adds the plaintext mode


if __name__ == '__main__':
    unittest.main()
