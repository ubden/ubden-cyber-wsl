"""Passive device inventory for authorized UBDEN assessments.

Only previously authorized Nmap XML and the local kernel neighbour cache are
read. No secondary network scan, remote API request, or inferred remote MAC.
"""
from collections import Counter, defaultdict
import csv
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
from xml.etree import ElementTree as ET


VIRTUAL = {
    '005056':'VMware','000C29':'VMware','000569':'VMware',
    '00155D':'Microsoft Hyper-V','080027':'Oracle VirtualBox',
    '00163E':'Xen','525400':'QEMU/KVM','001C42':'Parallels',
}
# Fixed device taxonomy: stable key -> Turkish label, plus report display order.
CATEGORIES = {
    'firewall': 'Güvenlik duvarı / UTM', 'router': 'Yönlendirici / Modem',
    'switch': 'Anahtar (Switch)', 'ap': 'Kablosuz erişim noktası',
    'hypervisor': 'Sanallaştırma (Hypervisor)', 'server': 'Sunucu', 'pc': 'İstemci PC',
    'nas': 'Depolama (NAS)', 'printer': 'Yazıcı / MFP', 'camera': 'Kamera / DVR / NVR',
    'voip': 'IP telefon / Santral', 'db': 'Veritabanı sunucusu', 'mobile': 'Mobil cihaz',
    'iot': 'IoT / gömülü cihaz', 'ups': 'UPS / güç', 'unknown': 'Bilinmiyor',
}
CATEGORY_ORDER = ['firewall', 'router', 'switch', 'ap', 'hypervisor', 'server', 'db',
                  'nas', 'printer', 'camera', 'voip', 'pc', 'mobile', 'iot', 'ups', 'unknown']
CATEGORY_ICONS = {'firewall': '🛡️', 'router': '📶', 'switch': '🔀', 'ap': '📡',
                  'hypervisor': '🧫', 'server': '🖥️', 'pc': '💻', 'nas': '🗄️',
                  'printer': '🖨️', 'camera': '📷', 'voip': '☎️', 'db': '🗃️',
                  'mobile': '📱', 'iot': '🔌', 'ups': '🔋', 'unknown': '❔'}
# Weighted rules: (patterns, category_key, weight). Higher weight = stronger signal.
VENDOR_RULES = (
    (('fortinet', 'fortigate', 'palo alto', 'sonicwall', 'watchguard', 'sophos', 'check point', 'zscaler'), 'firewall', 60),
    (('hikvision', 'dahua', 'axis communications', 'vivotek', 'uniview', 'reolink', 'hanwha', 'avigilon', 'bosch security'), 'camera', 60),
    (('epson', 'brother', 'lexmark', 'ricoh', 'xerox', 'kyocera', 'konica', 'zebra', 'oki data', 'sato', 'seiko epson'), 'printer', 55),
    (('hewlett packard', 'hp inc'), 'printer', 32),
    (('synology', 'qnap', 'asustor', 'buffalo', 'drobo', 'western digital'), 'nas', 60),
    (('yealink', 'grandstream', 'polycom', 'snom', 'avaya', 'mitel', 'fanvil', 'gigaset'), 'voip', 55),
    (('vmware', 'nutanix'), 'hypervisor', 50),
    (('espressif', 'tuya', 'sonoff', 'shelly', 'xiaomi', 'sonos', 'nest', 'ring', 'ecobee', 'amazon technologies'), 'iot', 52),
    (('ubiquiti', 'ruckus', 'aruba', 'mikrotik', 'tp-link', 'tp link', 'd-link', 'zyxel', 'keenetic', 'netgear', 'tenda', 'totolink'), 'ap', 38),
    (('vantiva', 'technicolor', 'arris', 'sagemcom', 'sercomm', 'huawei technolog', 'zte', 'airties', 'avm', 'fritz'), 'router', 45),
    (('cisco', 'juniper', 'extreme networks', 'h3c', 'ruijie'), 'switch', 32),
    (('draytek',), 'router', 58),
    (('apc ', 'american power', 'eaton', 'tripp lite', 'cyberpower', 'riello', 'socomec'), 'ups', 60),
    (('raspberry pi', 'arduino'), 'iot', 28),
    # Laptop/desktop ODMs (build most business PCs) → İstemci PC. These are the OUI
    # vendors that otherwise leave a Windows endpoint "Bilinmiyor".
    (('pegatron', 'compal', 'quanta', 'wistron', 'inventec', 'clevo', 'lcfc', 'hefei',
      'liteon', 'lite-on', 'tongfang', 'mitac', 'elitegroup', 'asustek', 'micro-star',
      'gigabyte', 'framework computer', 'chongqing fugui', 'hongfujin', 'wingtech'), 'pc', 34),
    # Industrial / embedded PC makers → İstemci PC.
    (('jump industrielle', 'advantech', 'kontron', 'beckhoff', 'congatec', 'portwell', 'ibase'), 'pc', 30),
    (('intel corporate',), 'pc', 22),
    (('realtek',), 'pc', 14),
    (('microsoft',), 'pc', 18),
    (('apple',), 'mobile', 24),
    (('samsung elect', 'huawei device', 'oneplus', 'oppo mobile', 'vivo mobile', 'honor device',
      'motorola mobility', 'motorola (wuhan)', 'xiaomi comm', 'realme', 'nothing tech'), 'mobile', 35),
)
TEXT_RULES = (
    (('fortigate', 'fortios', 'pan-os', 'sonicos', 'sophos xg', 'sophos utm'), 'firewall', 75),
    (('esxi', 'vmware esx', 'vsphere'), 'hypervisor', 78),
    (('vcenter', 'vmware skyline', 'skyline health', 'photon os', 'vmware vcsa'), 'hypervisor', 60),
    (('draytek', 'vigor'), 'router', 60),
    (('proxmox',), 'hypervisor', 78),
    (('hyper-v', 'xenserver', 'citrix hypervisor'), 'hypervisor', 55),
    (('diskstation', 'synology', 'qnap', 'qts', 'truenas', 'freenas', 'openmediavault'), 'nas', 72),
    (('jetdirect', 'laserjet', 'officejet', 'deskjet', 'pixma', 'imageclass', 'workcentre', 'ecosys', 'bizhub', 'ipp', 'internet printing', 'cups'), 'printer', 70),
    (('routeros', 'mikrotik', 'edgeos', 'edgerouter', 'openwrt', 'dd-wrt', 'pfsense', 'opnsense'), 'router', 68),
    (('windows server',), 'server', 65),
    (('domain controller', 'active directory'), 'server', 55),
    (('ubuntu', 'debian', 'centos', 'red hat', 'rhel'), 'server', 22),
    (('windows 10', 'windows 11', 'windows 8', 'windows 7'), 'pc', 45),
    (('macos', 'mac os x', 'darwin'), 'pc', 40),
    (('dahua', 'hikvision', 'ipcam', 'ip camera', 'nvr', 'dvr', 'netsurveillance', 'onvif'), 'camera', 65),
    (('asterisk', 'freepbx', '3cx', 'sip', 'voip', 'pbx', 'issabel', 'elastix'), 'voip', 58),
    (('android',), 'mobile', 60),
    (('iphone', 'ipad'), 'mobile', 65),
    (('printer', 'print server'), 'printer', 48),
    (('camera', 'rtsp'), 'camera', 46),
    (('router', 'gateway', 'modem', 'residential gateway'), 'router', 34),
    (('access point', 'wireless ap'), 'ap', 34),
    (('webmin', 'miniserv', 'usermin'), 'server', 40),
    (('integrated lights-out', 'ilo', 'idrac', 'integrated dell remote', 'lifecycle controller', 'ipmi', 'baseboard management'), 'server', 50),
    (('nimble', '3par', 'primera', 'storeserv', 'msa storage', 'powervault', 'unity', 'powerstore', 'compellent', 'equallogic', 'storeonce'), 'nas', 55),
    (('smart-ups', 'battery'), 'ups', 42),
    # mDNS (Bonjour) service types and SSDP device/SERVER hints.
    (('_ipp._tcp', '_printer._tcp', '_pdl-datastream', '_scanner._tcp', '_uscan._tcp'), 'printer', 55),
    (('_googlecast._tcp', '_airplay._tcp', '_raop._tcp', '_spotify-connect', '_sonos._tcp', 'dial-multiscreen', 'roku:'), 'iot', 45),
    (('_apple-mobdev', '_companion-link', '_touch-able', '_homekit'), 'mobile', 40),
    (('_workstation._tcp', '_rdp._tcp', '_smb._tcp'), 'pc', 22),
    (('_afpovertcp', '_adisk._tcp', '_nfs._tcp', '_time-machine'), 'nas', 40),
    (('_sip._tcp', '_h323._tcp', '_sccp'), 'voip', 45),
    (('upnp', 'ssdp', 'rootdevice'), 'iot', 12),
)
PORT_RULES = (
    ((9100,), 'printer', 45), ((515,), 'printer', 40), ((631,), 'printer', 45),
    ((554,), 'camera', 40), ((37777, 37778), 'camera', 60), ((34567,), 'camera', 45),
    ((5060, 5061), 'voip', 55), ((2000, 2427), 'voip', 22), ((1720,), 'voip', 20),  # SIP / SCCP·MGCP / H.323
    ((902, 903), 'hypervisor', 55), ((8006,), 'hypervisor', 60), ((5480,), 'hypervisor', 30),
    ((1433,), 'db', 48), ((3306,), 'db', 45), ((5432,), 'db', 45), ((1521,), 'db', 45),
    ((27017,), 'db', 40), ((6379,), 'db', 32),
    ((88, 389, 636), 'server', 35), ((623,), 'server', 40), ((3268,), 'server', 35),
    ((5000, 5001), 'nas', 22), ((873,), 'nas', 20),
    ((1723,), 'router', 20), ((53,), 'router', 12), ((67, 68), 'router', 18), ((161,), 'switch', 10),
    ((5357,), 'pc', 24), ((5985, 5986), 'server', 26), ((135,), 'pc', 10),  # WSDAPI / WinRM / RPC = Windows
)
WINDOWS_PORTS = {135, 139, 445, 3389, 5357}
REVIEW_PORTS = {21: 'FTP', 23: 'Telnet', 161: 'SNMP', 445: 'SMB', 3389: 'RDP', 5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch'}


def _load_extra_rules():
    """Merge the optional, research-built classification library into the in-code rules.

    data/device_classification.json (produced by the web-research workflow) may hold
    {"rules":[{patterns,category,weight}], "port_rules":[{ports,category,weight}]}.
    Vendor/text rules are applied against BOTH the OUI vendor and the service/OS/web
    blob (a vendor name like "draytek" also shows up in banners). Additive + deduped;
    a missing or malformed file is ignored so classification always works offline."""
    path = Path(__file__).resolve().parent / 'data' / 'device_classification.json'
    extra_v, extra_t, extra_p = [], [], []
    try:
        lib = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return extra_v, extra_t, extra_p
    have_v = {(p, k) for p, k, _ in VENDOR_RULES}
    have_t = {(p, k) for p, k, _ in TEXT_RULES}
    for rule in lib.get('rules', []) if isinstance(lib.get('rules'), list) else []:
        try:
            pats = tuple(dict.fromkeys(str(x).lower().strip() for x in rule['patterns'] if str(x).strip()))
            key = str(rule['category'])
            weight = max(5, min(80, int(rule.get('weight', 30))))
        except (KeyError, TypeError, ValueError):
            continue
        if not pats or key not in CATEGORIES:
            continue
        if (pats, key) not in have_v:
            extra_v.append((pats, key, weight)); have_v.add((pats, key))
        if (pats, key) not in have_t:
            extra_t.append((pats, key, weight)); have_t.add((pats, key))
    for rule in lib.get('port_rules', []) if isinstance(lib.get('port_rules'), list) else []:
        try:
            ports = tuple(int(x) for x in rule['ports'])
            key = str(rule['category'])
            weight = max(5, min(80, int(rule.get('weight', 30))))
        except (KeyError, TypeError, ValueError):
            continue
        if ports and key in CATEGORIES:
            extra_p.append((ports, key, weight))
    return extra_v, extra_t, extra_p


_EXTRA_V, _EXTRA_T, _EXTRA_P = _load_extra_rules()
VENDOR_RULES = VENDOR_RULES + tuple(_EXTRA_V)
TEXT_RULES = TEXT_RULES + tuple(_EXTRA_T)
PORT_RULES = PORT_RULES + tuple(_EXTRA_P)
HEX=re.compile(r'^[0-9A-F]{12}$')


def normalize_mac(value):
    raw=re.sub(r'[^0-9A-Fa-f]', '', str(value or '')).upper()
    if not HEX.fullmatch(raw) or raw=='000000000000' or int(raw[:2],16)&1:
        return ''
    return ':'.join(raw[i:i+2] for i in range(0,12,2))


def oui_database(paths=None):
    """Use installed Nmap prefixes plus optional offline IEEE MA-L/M/S CSVs."""
    base=Path(__file__).resolve().parent/'data'/'ieee'
    paths=paths if paths is not None else [
        Path('/usr/share/nmap/nmap-mac-prefixes'),
        Path('/usr/share/ieee-data/oui.csv'),Path('/usr/share/ieee-data/mam.csv'),
        Path('/usr/share/ieee-data/oui36.csv'),
        base/'oui.csv',base/'mam.csv',base/'mas.csv']
    result={}
    sources=[]
    for path in map(Path,paths):
        if not path.is_file() or path.stat().st_size>45_000_000:
            continue
        try:
            if path.suffix.lower()=='.csv':
                with path.open(encoding='utf-8-sig',newline='') as handle:
                    for row in csv.DictReader(handle):
                        prefix=re.sub('[^0-9A-Fa-f]','',row.get('Assignment','')).upper()
                        vendor=(row.get('Organization Name') or '').strip()
                        if len(prefix) in (6,7,9) and vendor:
                            result[prefix]=vendor[:100]
            else:
                with path.open(encoding='utf-8',errors='replace') as handle:
                    for line in handle:
                        match=re.match(r'^([0-9A-Fa-f]{6})\s+(.+)$',line)
                        if match:
                            result[match.group(1).upper()]=match.group(2).strip()[:100]
            sources.append(str(path))
        except (OSError,UnicodeError,csv.Error):
            continue
    return result,sources


def vendor_for(mac,database):
    raw=mac.replace(':','')
    if raw.startswith('0242'):
        return 'Docker (yerel adres kalıbı)','pattern'
    if raw[:6] in VIRTUAL:
        return VIRTUAL[raw[:6]],'virtual_prefix'
    # Locally administered MACs cannot be reliably resolved from IEEE OUIs.
    if int(raw[:2],16)&2:
        return 'Yerel / rastgele MAC', 'local'
    for width in (9,7,6):
        if raw[:width] in database:
            return database[raw[:width]],f'OUI-{width*4}'
    return 'Bilinmiyor','unknown'


def neighbour_cache():
    if not shutil.which('ip'):
        return {},'iproute2 yüklü değil'
    try:
        process=subprocess.run(['ip','-j','neigh','show'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=4,check=False)
        if process.returncode:
            return {},f'ip neigh çıkış kodu {process.returncode}'
        mapping={}
        for item in json.loads(process.stdout):
            if not isinstance(item,dict) or 'FAILED' in item.get('state',[]) or 'INCOMPLETE' in item.get('state',[]):
                continue
            ip=item.get('dst','')
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            mac=normalize_mac(item.get('lladdr',''))
            if mac:
                mapping[ip]={'mac':mac,'device':str(item.get('dev',''))[:40]}
        return mapping,''
    except (OSError,subprocess.TimeoutExpired,ValueError,TypeError) as exc:
        return {},type(exc).__name__


def allowed_ips(root,meta):
    """Explicit addresses or scan time DNS resolutions, minus exclusions."""
    scopes=[]
    for target in meta.get('targets',[]):
        try:
            scopes.append(ipaddress.ip_network(target,strict=False))
        except ValueError:
            path=root/'targets'/re.sub(r'[^A-Za-z0-9._-]+','_',target)/'raw'/'dns_resolution.json'
            if path.is_file():
                try:
                    data=json.loads(path.read_text(encoding='utf-8'))
                    if data.get('host')==target:
                        scopes.extend(ipaddress.ip_network(addr,strict=False) for addr in data.get('addresses',[]))
                except (ValueError,TypeError,OSError):
                    continue
    exclusions=[]
    for raw in meta.get('exclusions',[]):
        try: exclusions.append(ipaddress.ip_network(raw,strict=False))
        except ValueError: pass
    def valid(ip):
        address=ipaddress.ip_address(ip)
        return any(address in network for network in scopes) and not any(address in network for network in exclusions)
    return valid


def _confidence_word(pct):
    if pct >= 80:
        return 'yüksek'
    if pct >= 55:
        return 'orta'
    if pct >= 30:
        return 'düşük'
    return 'belirsiz'


def classify_device(facts):
    """Weighted, multi-signal device classification with a 0-99 confidence score.

    facts keys (all optional): vendor, ports (list of dicts), snmp (sysDescr),
    text (precomputed blob), os (list of {name,accuracy}), gateway (bool),
    random_mac (bool). Returns {key, category, confidence, confidence_pct, evidence}.
    """
    vendor = facts.get('vendor') or ''
    ports = facts.get('ports') or []
    numbers = {int(p['port']) for p in ports if str(p.get('port', '')).isdigit()}
    vlower = vendor.lower()
    blob = (facts.get('text') or '').lower()
    scores = defaultdict(int)
    evidence = []

    def award(key, weight, why):
        scores[key] += weight
        evidence.append({'signal': why, 'weight': weight, 'category': key})

    for patterns, key, weight in VENDOR_RULES:
        if any(p in vlower for p in patterns):
            award(key, weight, f'Üretici (OUI): {vendor}')
            break
    for patterns, key, weight in TEXT_RULES:
        match = next((p for p in patterns if p in blob), None)
        if match:
            award(key, weight, f'Metin izi: "{match}"')
    for pset, key, weight in PORT_RULES:
        hit = [str(p) for p in pset if p in numbers]
        if hit:
            award(key, weight, f'Port {"/".join(hit)}')
    winhits = WINDOWS_PORTS & numbers
    if len(winhits) >= 2:
        award('pc', 35, f'Windows portları {sorted(winhits)}')
    elif 5357 in winhits:
        award('pc', 22, 'WSDAPI (5357) — Windows cihaz servisi')
    if 3389 in numbers:
        award('pc', 12, 'RDP (3389)')
    snmp = facts.get('snmp') or ''
    if snmp:
        match = next((p for patterns, key, weight in TEXT_RULES for p in patterns if p in snmp.lower()), None)
        if match:
            key = next(key for patterns, key, weight in TEXT_RULES if match in patterns)
            award(key, 60, f'SNMP sysDescr: "{match}"')
    for os_item in facts.get('os') or []:
        name = str(os_item.get('name', '')).lower()
        if 'windows' in name:
            award('server' if 'server' in name else 'pc', 22, f'OS: {os_item.get("name", "")[:40]}')
        elif any(x in name for x in ('linux', 'ubuntu', 'debian', 'unix')):
            award('server', 12, f'OS: {os_item.get("name", "")[:40]}')
    if facts.get('gateway'):
        award('router', 55, 'Varsayılan ağ geçidi')
        # A gateway exposing many management/service ports is a router-FIREWALL/UTM
        # (e.g. DrayTek Vigor with FTP+SSH+SMB+web), not a dumb modem.
        if len(numbers) >= 5 and ({21, 22, 443, 8443} & numbers):
            award('firewall', 30, 'Ağ geçidi + çok sayıda yönetim/servis portu (UTM/firewall adayı)')
    if vendor in VIRTUAL.values() or vendor.startswith('Docker'):
        award('hypervisor', 15, 'Sanallaştırma MAC öneki')
    if facts.get('random_mac') and not numbers:
        award('mobile', 30, 'Rastgele/yerel MAC ve açık port yok (gizlilik telefonu olası)')

    ordered_ev = [f'{e["signal"]} ({CATEGORIES.get(e["category"], e["category"])})'
                  for e in sorted(evidence, key=lambda e: -e['weight'])]
    if not scores:
        return {'key': 'unknown', 'category': CATEGORIES['unknown'], 'confidence': 'belirsiz',
                'confidence_pct': 10, 'evidence': []}
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    top_key, top = ranked[0]
    runner = ranked[1][1] if len(ranked) > 1 else 0
    margin = top - runner
    pct = max(5, min(99, int(top * 0.7 + margin * 0.5)))
    return {'key': top_key, 'category': CATEGORIES[top_key], 'confidence': _confidence_word(pct),
            'confidence_pct': pct, 'evidence': ordered_ev}


def classify(vendor, ports, snmp_description=''):
    """Backward-compatible 3-tuple wrapper over classify_device()."""
    product_text = ' '.join(str(p.get('product', '')) for p in ports)
    text = ' '.join([vendor, product_text, snmp_description])
    result = classify_device({'vendor': vendor, 'ports': ports, 'snmp': snmp_description, 'text': text})
    return result['category'], result['confidence'], result['evidence']


def role_candidates(ports, vendor, gateway=False):
    """Independent service roles; port-only matches remain candidates."""
    numbers={int(p['port']) for p in ports if str(p.get('port','')).isdigit()}
    product=' '.join(str(p.get('product','')) for p in ports).lower()
    roles=[]
    def add(name, reason, confidence='düşük'):
        roles.append({'role':name,'confidence':confidence,'reason':reason})
    if {88,389}.issubset(numbers) or {88,636}.issubset(numbers):
        add('Etki alanı denetleyicisi adayı','Kerberos ve LDAP/LDAPS portları birlikte görüldü','orta')
    if 1433 in numbers or 'microsoft sql server' in product or 'ms-sql' in product:
        add('SQL Server adayı','TDS/SQL servis izi görüldü')
    if numbers & {3306,5432,1521,27017,6379,9200}:
        add('Veritabanı veya veri servisi adayı','Veri servisi portu görüldü')
    if numbers & {139,445,2049}:
        add('Dosya/paylaşım sunucusu adayı','SMB veya NFS servisi görüldü')
    if numbers & {80,443,8080,8443}:
        add('Web veya yönetim arayüzü adayı','HTTP(S) portu görüldü')
    if 1723 in numbers:
        add('PPTP/VPN uç noktası adayı','TCP/1723 açık görüldü; tünel veya cihaz kimliği ayrıca doğrulanmalı')
    if gateway:
        add('Ağ geçidi','Windows varsayılan rota kaydı ile eşleşti','orta')
    explicit=' '.join([vendor,product]).lower()
    if any(label in explicit for label in ('fortinet','fortigate','palo alto','sonicwall','watchguard','sophos firewall')):
        add('Güvenlik duvarı ürünü adayı','Üretici/servis izi güvenlik duvarı markasıyla eşleşti')
    return roles


def _clean_name(value):
    """Drop control/replacement/non-printable chars so garbled bytes (e.g. from a
    NetBIOS/nbtstat name) never reach the report as U+FFFD (�)."""
    text=''.join(ch for ch in str(value or '') if ch.isprintable() and ch!='�')
    return text.strip()[:120]


def _ttl_hint(ttl):
    """Rough device family from an observed TTL (initial 64/128/255 minus a few hops)."""
    if not ttl:
        return ''
    if 100 <= ttl <= 128:
        return 'Windows ana bilgisayar (başlangıç TTL 128)'
    if 40 <= ttl <= 64:
        return 'Linux/Unix/gömülü cihaz (başlangıç TTL 64)'
    if ttl >= 200:
        return 'Ağ cihazı — yönlendirici/anahtar/yazıcı/telefon (başlangıç TTL 255)'
    return f'TTL={ttl}'


def _enrich_from_ad(devices, root):
    """Overlay AD computer facts (dNSHostName + OS) onto observed devices by IP. AD is an
    authoritative name source that works across subnets (LDAP + forward DNS), so it fills
    hostnames the L2/NBSTAT probes miss and refines PC-vs-server from the OS string. Only
    OBSERVED devices are touched — AD-only hosts are not invented here."""
    try:
        ad=json.loads((root/'AD_ASSESSMENT.json').read_text(encoding='utf-8-sig'))
    except (OSError,ValueError):
        return 0
    if not isinstance(ad,dict):
        return 0
    named=0
    for comp in ad.get('computers') or []:
        if not isinstance(comp,dict):
            continue
        ip=str(comp.get('ip') or '').strip()
        dev=devices.get(ip)
        if not dev:
            continue
        name=_clean_name(comp.get('dns') or comp.get('name') or '')
        if name:
            if not dev.get('display_name'):
                dev['display_name']=name; named+=1
            sig=f'AD bilgisayar adı: {name}'
            if sig not in dev.get('signals',[]):
                dev.setdefault('signals',[]).append(sig)
        os_name=str(comp.get('os') or '').strip()
        if os_name:
            osig=f'AD işletim sistemi: {os_name}'+(f" ({comp.get('os_version')})" if comp.get('os_version') else '')
            if osig not in dev.get('signals',[]):
                dev.setdefault('signals',[]).insert(0,osig)
            low=os_name.lower()
            if 'server' in low and dev.get('category_key') in ('pc','unknown'):
                dev['category'],dev['category_key']=CATEGORIES['server'],'server'
                dev['confidence'],dev['confidence_pct']='orta',max(int(dev.get('confidence_pct') or 0),82)
            elif ('windows 1' in low or 'windows 7' in low or 'windows 8' in low) and dev.get('category_key')=='unknown':
                dev['category'],dev['category_key']=CATEGORIES['pc'],'pc'
                dev['confidence'],dev['confidence_pct']='orta',max(int(dev.get('confidence_pct') or 0),80)
        if comp.get('stale'):
            note='AD: 90+ gündür oturum açmamış (bayat bilgisayar hesabı)'
            if note not in dev.get('notices',[]):
                dev.setdefault('notices',[]).append(note)
        dev['ad_joined']=True
    return named


def build_inventory(root,meta,neighbours=None,oui_paths=None):
    root=Path(root)
    permitted=allowed_ips(root,meta)
    vendors,sources=oui_database(oui_paths)
    if neighbours is None:
        neighbours,neighbour_error=neighbour_cache()
    else:
        neighbour_error=''
    devices={}
    errors=[]
    snapshot=meta.get('host_snapshot') if isinstance(meta.get('host_snapshot'),dict) else {}
    gateways={str(row.get('gateway')) for row in snapshot.get('default_routes',[])
              if isinstance(row,dict) and row.get('gateway')}
    # Ayni IP birden cok nmap_*.xml'de gorulebilir (kesif+surum, platform portlari,
    # NSE denetimi). Once ham gercekleri BIRLESTIR (MAC'i koru, portlari birlestir),
    # sonra tek seferde siniflandir; boylece MAC'siz bir dosya MAC'li olani ezmez.
    facts={}
    for path in sorted((root/'targets').glob('*/raw/nmap_*.xml')) if (root/'targets').exists() else []:
        try:
            tree=ET.parse(path)
        except (ET.ParseError,OSError) as exc:
            errors.append(f'{path.relative_to(root)}: {type(exc).__name__}')
            continue
        for host in tree.findall('./host'):
            ips=[a.get('addr','') for a in host.findall('./address') if a.get('addrtype') in ('ipv4','ipv6')]
            for ip in ips:
                try:
                    if not permitted(ip):
                        continue
                except ValueError:
                    continue
                entry=facts.setdefault(ip,{'ports':[],'seen':set(),'xml_mac':'','hostnames':[],
                                           'os_matches':[],'evidence':[],'raws':[]})
                for port in host.findall('./ports/port'):
                    state=port.find('state')
                    if state is None or state.get('state')!='open':
                        continue
                    key=(port.get('portid',''),port.get('protocol',''))
                    if key in entry['seen']:
                        continue
                    entry['seen'].add(key)
                    svc=port.find('service')
                    entry['ports'].append({'port':port.get('portid',''),'protocol':port.get('protocol',''),
                                  'service':svc.get('name','') if svc is not None else '',
                                  'product':svc.get('product','')[:100] if svc is not None else '',
                                  'version':svc.get('version','')[:70] if svc is not None else '',
                                  'extra_info':svc.get('extrainfo','')[:100] if svc is not None else ''})
                if not entry['xml_mac']:
                    entry['xml_mac']=next((normalize_mac(a.get('addr')) for a in host.findall('./address')
                                           if a.get('addrtype')=='mac'), '')
                if not entry['hostnames']:
                    entry['hostnames']=[name.get('name','')[:120] for name in host.findall('./hostnames/hostname')
                                        if name.get('name')][:5]
                if not entry['os_matches']:
                    entry['os_matches']=[{'name': item.get('name','')[:120], 'accuracy': item.get('accuracy','')}
                                         for item in host.findall('./os/osmatch')][:3]
                if not entry.get('ttl'):
                    st=host.find('status')
                    ttl=st.get('reason_ttl') if st is not None else None
                    if not ttl:
                        for p in host.findall('./ports/port'):
                            s=p.find('state')
                            if s is not None and s.get('reason_ttl'):
                                ttl=s.get('reason_ttl'); break
                    if ttl and str(ttl).isdigit() and int(ttl)>0:
                        entry['ttl']=int(ttl)
                rel=str(path.relative_to(root))
                if rel not in entry['evidence']:
                    entry['evidence'].append(rel)
                if path.parent not in entry['raws']:
                    entry['raws'].append(path.parent)
    for ip,entry in facts.items():
        ports=entry['ports']
        xml_mac=entry['xml_mac']
        neighbour=neighbours.get(ip,{})
        neighbour_mac=normalize_mac(neighbour.get('mac'))
        mac=xml_mac or neighbour_mac
        vendor,source=vendor_for(mac,vendors) if mac else ('Bilinmiyor','unavailable')
        snmp_description=''
        for rawdir in entry['raws']:
            snmp_path=rawdir/f'snmp_v1_public_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
            if snmp_path.is_file():
                try:
                    snmp_data=json.loads(snmp_path.read_text(encoding='utf-8'))
                    if (snmp_data.get('target')==ip and snmp_data.get('confirmed_response') is True
                            and snmp_data.get('version') in ('1', '2c') and snmp_data.get('community')=='public'):
                        snmp_description=str(snmp_data.get('sysDescr',''))[:160]
                        break
                except (ValueError,OSError,AttributeError):
                    pass
        # NetBIOS name/role/MAC from the stdlib NBSTAT probe, if present.
        netbios={}
        for rawdir in entry['raws']:
            nb_path=rawdir/f'netbios_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
            if nb_path.is_file():
                try:
                    nb=json.loads(nb_path.read_text(encoding='utf-8'))
                    if nb.get('target')==ip and nb.get('name'):
                        netbios=nb; break
                except (ValueError,OSError,AttributeError):
                    pass
        if not mac and netbios.get('mac'):
            nb_mac=normalize_mac(netbios.get('mac'))
            if nb_mac:
                mac=nb_mac; vendor,source=vendor_for(mac,vendors)
        # HTTP 'view-source' identity (web_identify): title/server/body → classifier blob.
        web_id={}
        for rawdir in entry['raws']:
            web_path=rawdir/f'web_id_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
            if web_path.is_file():
                try:
                    wd=json.loads(web_path.read_text(encoding='utf-8'))
                    if wd.get('target')==ip:
                        web_id=wd; break
                except (ValueError,OSError,AttributeError):
                    pass
        # mDNS (Bonjour) hostname/services + SSDP (UPnP) SERVER/device type + vSphere/appliance version.
        mdns={}; ssdp={}; vmware={}; appliance={}; netdev={}
        for rawdir in entry['raws']:
            if not mdns:
                mp=rawdir/f'mdns_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                if mp.is_file():
                    try:
                        md=json.loads(mp.read_text(encoding='utf-8'))
                        if md.get('target')==ip: mdns=md
                    except (ValueError,OSError,AttributeError): pass
            if not ssdp:
                sp=rawdir/f'ssdp_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                if sp.is_file():
                    try:
                        sd=json.loads(sp.read_text(encoding='utf-8'))
                        if sd.get('target')==ip: ssdp=sd
                    except (ValueError,OSError,AttributeError): pass
            if not vmware:
                vp=rawdir/f'vmware_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                if vp.is_file():
                    try:
                        vd=json.loads(vp.read_text(encoding='utf-8'))
                        if vd.get('target')==ip: vmware=vd
                    except (ValueError,OSError,AttributeError): pass
            if not appliance:
                ap=rawdir/f'appliance_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                if ap.is_file():
                    try:
                        ad=json.loads(ap.read_text(encoding='utf-8'))
                        if ad.get('target')==ip: appliance=ad
                    except (ValueError,OSError,AttributeError): pass
            if not netdev:
                np=rawdir/f'netdev_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                if np.is_file():
                    try:
                        nd=json.loads(np.read_text(encoding='utf-8'))
                        if nd.get('target')==ip: netdev=nd
                    except (ValueError,OSError,AttributeError): pass
        random_mac=bool(mac and int(mac.replace(':','')[:2],16)&2)
        blob=' '.join([vendor]
                      +[f"{p.get('service','')} {p.get('product','')} {p.get('version','')} {p.get('extra_info','')}" for p in ports]
                      +[snmp_description]+entry['hostnames']
                      +[mdns.get('hostname','')]+list(mdns.get('services') or [])
                      +[ssdp.get('server','')]+list(ssdp.get('devices') or [])
                      +[vmware.get('product',''),vmware.get('version','')]
                      +[(v or {}).get('product','') for k,v in appliance.items() if isinstance(v,dict)]
                      +[netdev.get('brand','')]
                      +[o.get('name','') for o in entry['os_matches']]
                      +[netbios.get('name',''),netbios.get('domain','')]
                      +[web_id.get('title',''),web_id.get('server',''),web_id.get('snippet','')])
        cls=classify_device({'vendor':vendor,'ports':ports,'snmp':snmp_description,'text':blob,
                             'os':entry['os_matches'],'gateway':ip in gateways,'random_mac':random_mac})
        category,confidence,signals=cls['category'],cls['confidence'],cls['evidence']
        # A network-device fingerprint (hit a specific brand mgmt endpoint) is authoritative.
        if netdev.get('category') in CATEGORIES and netdev.get('brand'):
            cls={**cls,'key':netdev['category'],'category':CATEGORIES[netdev['category']],
                 'confidence_pct':max(int(cls.get('confidence_pct') or 0),90)}
            category=CATEGORIES[netdev['category']]; confidence='yüksek'
            _nv=f" {netdev['version']}" if netdev.get('version') else ''
            signals=list(signals)+[f"Ağ cihazı parmak izi (kimliksiz): {netdev['brand']}{_nv}"]
        roles=role_candidates(ports,vendor,ip in gateways)
        nb_role=str(netbios.get('role','')).lower()
        if 'domain controller' in nb_role:
            roles.append({'role':'Etki alanı denetleyicisi adayı','confidence':'orta','reason':'NetBIOS ad tablosu (0x1B/0x1C)'})
        elif 'file server' in nb_role:
            roles.append({'role':'Dosya/paylaşım sunucusu adayı','confidence':'düşük','reason':'NetBIOS ad tablosu (0x20)'})
        if web_id.get('title'):
            signals=list(signals)+[f'Web kimliği (sayfa başlığı): "{web_id["title"][:80]}"'
                                   + (f' · Server: {web_id["server"]}' if web_id.get('server') else '')]
        elif web_id.get('server'):
            signals=list(signals)+[f'Web sunucusu: {web_id["server"]}']
        ttl_hint=_ttl_hint(entry.get('ttl'))
        if ttl_hint:
            signals=list(signals)+[f'TTL ipucu: {ttl_hint}']
        if mdns.get('hostname') or mdns.get('services'):
            signals=list(signals)+[('mDNS: '+(mdns.get('hostname','')+' '+' '.join((mdns.get('services') or [])[:4])).strip())]
        if ssdp.get('server') or ssdp.get('devices'):
            signals=list(signals)+[('SSDP: '+(ssdp.get('server','')+' '+' '.join((ssdp.get('devices') or [])[:3])).strip())]
        if vmware.get('product'):
            signals=list(signals)+[f"vSphere sürüm ifşası (kimliksiz): {vmware['product']}"+(f" build {vmware.get('build')}" if vmware.get('build') else '')]
        _APP_LABELS={'fortigate':'FortiGate','webmin':'Webmin','ilo':'HPE iLO','idrac':'Dell iDRAC','synology':'Synology','qnap':'QNAP'}
        for _ak,_av in appliance.items():
            if isinstance(_av,dict) and _av.get('product'):
                _ver=_av.get('version') or _av.get('build') or ''
                signals=list(signals)+[f"{_APP_LABELS.get(_ak,_ak)} (kimliksiz ifşa): {_av['product']}"+(f" {_ver}" if _ver else '')]
        # Display name: NetBIOS computer name > DNS hostname > web title (kısa/anlamlı) > (blank).
        clean_hostnames=[_clean_name(h) for h in entry['hostnames'] if _clean_name(h)]
        display_name=(_clean_name(netbios.get('name')) or _clean_name(mdns.get('hostname'))
                      or (clean_hostnames[0] if clean_hostnames else ''))
        if not display_name and web_id.get('title') and 2 <= len(web_id['title']) <= 40 \
                and web_id['title'].lower() not in ('login', 'sign in', 'home', 'index', 'welcome'):
            display_name=_clean_name(web_id['title'])
        notices=[]
        if xml_mac and neighbour_mac and xml_mac!=neighbour_mac:
            notices.append('Nmap MAC ve yerel komşu önbelleği uyuşmuyor; MAC doğrulanmalı')
        if random_mac:
            notices.append('Yerel/rastgele MAC: OUI fiziksel cihazı doğrulamaz')
        if not mac:
            notices.append('Uzak rota veya L2 komşuluk yok; MAC tespit edilmedi')
        review=[f'{REVIEW_PORTS[int(p["port"])]} ({p["port"]}) için erişim ve yapılandırmayı inceleyin'
                for p in ports if str(p['port']).isdigit() and int(p['port']) in REVIEW_PORTS]
        if snmp_description:
            review.append('SNMP/public ile kimlik bilgisi okunuyor; SNMPv3 ve erişim kısıtlarını değerlendirin')
        devices[ip]={'ip':ip,'mac':mac,
                     'mac_source':'nmap' if xml_mac else ('netbios' if netbios.get('mac') and mac else 'yerel komşu önbelleği' if mac else 'yok'),
                     'interface':neighbour.get('device','') if not xml_mac else '',
                     'vendor':vendor,'vendor_source':source,
                     'category':category,'category_key':cls['key'],
                     'confidence':confidence,'confidence_pct':cls['confidence_pct'],
                     'display_name':display_name,'netbios':netbios,'web_id':web_id,
                     'signals':signals,'ports':ports,'role_candidates':roles,
                     'hostnames':clean_hostnames,'os_matches':entry['os_matches'],
                     'review_notes':review,'notices':notices,'snmp_sysdescr':snmp_description,
                     'ttl':entry.get('ttl'),'os_ttl_hint':ttl_hint,
                     'evidence':'; '.join(entry['evidence'])}
    for path in sorted((root/'targets').glob('*/raw/sql_browser_*.json')) if (root/'targets').exists() else []:
        try:
            result=json.loads(path.read_text(encoding='utf-8'))
            ip=str(ipaddress.ip_address(result.get('ip','')))
            if result.get('status')!='ok' or not result.get('instances') or not permitted(ip):
                continue
        except (OSError,ValueError,TypeError,AttributeError):
            continue
        record=devices.get(ip)
        if record is None:
            record={'ip':ip,'mac':'','mac_source':'yok','interface':'','vendor':'Bilinmiyor',
                    'vendor_source':'unavailable','category':CATEGORIES['db'],'category_key':'db',
                    'confidence':'düşük','confidence_pct':30,'display_name':'','netbios':{},
                    'signals':[],'ports':[],'role_candidates':[],'hostnames':[],
                    'os_matches':[],'review_notes':[],'notices':['Uzak rota veya L2 komşuluk yok; MAC tespit edilmedi'],
                    'snmp_sysdescr':'','evidence':str(path.relative_to(root))}
            devices[ip]=record
        record['sql_instances']=[{'name':str(item.get('name',''))[:80],
                                  'tcp_port':item.get('tcp_port'),
                                  'version':str(item.get('version',''))[:50]}
                                 for item in result['instances'][:16] if isinstance(item,dict)]
        if not any(role.get('role')=='SQL Server adayı' for role in record['role_candidates']):
            record['role_candidates'].append({'role':'SQL Server adayı','confidence':'orta',
                'reason':'UDP/1434 SQL Browser yanıtında örnek adı görüldü'})
        record['signals'].append('SQL Browser örnek yanıtı: '+str(path.relative_to(root)))
    # The scanner's own machine is fully known locally — don't leave it "Bilinmiyor /
    # MAC görülmedi". Enrich any scanned device whose IP is one of our adapter IPs.
    host_name=str(snapshot.get('fqdn') or snapshot.get('host') or '')
    for adapter in snapshot.get('adapters',[]):
        if not isinstance(adapter,dict):
            continue
        amac=normalize_mac(adapter.get('mac',''))
        for item in adapter.get('addresses',[]):
            if not isinstance(item,dict):
                continue
            addr=str(item.get('address','')).split('%')[0]
            dev=devices.get(addr)
            if dev is None:
                continue
            if not dev.get('mac') and amac:
                dev['mac']=amac; dev['mac_source']='windows adaptör (yerel)'
                dev['vendor'],dev['vendor_source']=vendor_for(amac,vendors)
            if not dev.get('display_name') and host_name:
                dev['display_name']=host_name
            dev['notices']=[n for n in dev.get('notices',[]) if 'L2 komşuluk yok' not in n]
            note='Bu, taramayı yapan test makinesidir (yerel Windows adaptör kaydı).'
            if note not in dev['notices']:
                dev['notices'].append(note)
            if not any('test makinesi' in s.lower() for s in dev.get('signals',[])):
                dev.setdefault('signals',[]).insert(0,'Yerel test makinesi: '+(host_name or 'bu ana bilgisayar'))
            dev['is_scanner']=True
    local_addresses=[]
    selected=set(meta.get('selected_interfaces',[]))
    for adapter in snapshot.get('adapters',[]):
        if not isinstance(adapter,dict) or adapter.get('index') not in selected or str(adapter.get('status','')).lower()!='up':
            continue
        for item in adapter.get('addresses',[]):
            if not isinstance(item,dict):
                continue
            try:
                ip=str(ipaddress.ip_address(item.get('address','')))
                if not permitted(ip):
                    continue
            except (ValueError,TypeError):
                continue
            if any(row['ip']==ip for row in local_addresses):
                continue
            local_addresses.append({'ip':ip,'adapter':str(adapter.get('name',''))[:80],
                'interface_index':adapter['index'],
                'status':'servis taraması kanıtlı' if ip in devices else 'yalnız Windows adaptör kaydı; Kali erişimi doğrulanmadı',
                'evidence':'HOST_CAPABILITIES.json' if (root/'HOST_CAPABILITIES.json').is_file() else 'engagement.json'})
    ad_named=_enrich_from_ad(devices, root)
    duplicates=defaultdict(list)
    for device in devices.values():
        if device['mac']:
            duplicates[device['mac']].append(device['ip'])
    for mac,ips in duplicates.items():
        if len(ips)>1:
            for ip in ips:
                devices[ip]['notices'].append(f'Bu MAC {len(ips)} IP üzerinde görüldü; vekil ARP/NAT olası, eşleme doğrulanmalı')
                devices[ip]['confidence']='belirsiz'
    ordered=sorted(devices.values(),key=lambda row:ipaddress.ip_address(row['ip']))
    summary={'schema':1,'source':'UBDEN yerel cihaz envanteri',
             'host_count':len(ordered),'mac_count':sum(bool(row['mac']) for row in ordered),
             'named_count':sum(bool(row.get('display_name')) for row in ordered),
             'ad_joined_count':sum(bool(row.get('ad_joined')) for row in ordered),
             'ad_named_count':ad_named,
             'local_interface_addresses':local_addresses,
             'unknown_count':sum(row['category']=='Bilinmiyor' for row in ordered),
             'categories':dict(Counter(row['category'] for row in ordered)),
             'services':dict(Counter(f"{port['port']}/{port['protocol']} {port['service']}".strip()
                                     for row in ordered for port in row['ports'])),
             'role_counts_lower_bound':dict(Counter(role['role'] for row in ordered
                                                     for role in row['role_candidates'])),
             'observed_gateways':[ip for ip in sorted(gateways) if ip in devices],
             'firewall_identity_status':('aday var; analist doğrulaması gerekir' if any(
                 role['role']=='Güvenlik duvarı ürünü adayı' for row in ordered
                 for role in row['role_candidates']) else 'doğrulanmadı'),
             'oui_sources':sources,'neighbour_note':neighbour_error,
             'limits':'MAC yalnızca aynı L2 komşuluğunda gözlenebilir. Üretici donanımın modeli veya güvenlik açığı kanıtı değildir. Kategori ve servisler analist doğrulaması gerektirir.',
             'parse_errors':errors,'devices':ordered}
    output=root/'DEVICE_INVENTORY.json'
    temp=root/'.DEVICE_INVENTORY.pending.json'
    temp.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temp.replace(output)
    return summary
