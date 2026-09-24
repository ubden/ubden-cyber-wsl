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
VENDOR_RULES = (
    (('fortinet','palo alto','sonicwall','watchguard','sophos'), 'Güvenlik cihazı adayı'),
    (('hikvision','dahua','axis communications','vivotek'), 'Kamera adayı'),
    (('epson','brother','lexmark','ricoh','xerox','kyocera'), 'Yazıcı adayı'),
    (('synology','qnap','asustor'), 'Depolama cihazı adayı'),
    (('yealink','grandstream','polycom','snom'), 'IP telefon adayı'),
    (('ubiquiti','ruckus','aruba','cisco','juniper','mikrotik','tp-link'), 'Ağ cihazı adayı'),
)
PORT_RULES = ((9100,'Yazıcı adayı','Yazıcı servis portu 9100'),
              (515,'Yazıcı adayı','LPD portu 515'),
              (631,'Yazıcı adayı','IPP portu 631'),
              (554,'Kamera / medya cihazı adayı','RTSP portu 554'),
              (5060,'IP telefon adayı','SIP portu 5060'),
              (2049,'Dosya sunucusu adayı','NFS portu 2049'))
REVIEW_PORTS = {21:'FTP',23:'Telnet',161:'SNMP',445:'SMB',3389:'RDP',5900:'VNC',6379:'Redis',9200:'Elasticsearch'}
HEX=re.compile(r'^[0-9A-F]{12}$')


def normalize_mac(value):
    raw=re.sub(r'[^0-9A-Fa-f]', '', str(value or '')).upper()
    if not HEX.fullmatch(raw) or raw=='000000000000' or int(raw[:2],16)&1:
        return ''
    return ':'.join(raw[i:i+2] for i in range(0,12,2))


def oui_database(paths=None):
    """Use installed Nmap prefixes plus optional offline IEEE MA-L/M/S CSVs."""
    base=Path(__file__).resolve().parent/'data'/'ieee'
    paths=paths if paths is not None else [Path('/usr/share/nmap/nmap-mac-prefixes'),base/'oui.csv',base/'mam.csv',base/'mas.csv']
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
        process=subprocess.run(['ip','-j','neigh','show'],capture_output=True,text=True,timeout=4,check=False)
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


def classify(vendor,ports,snmp_description=''):
    scores=defaultdict(int)
    evidence=[]
    lower=vendor.lower()
    product_text=' '.join(p.get('product','') for p in ports).lower()
    for patterns,category in VENDOR_RULES:
        if any(pattern in lower for pattern in patterns):
            scores[category]+=1
            evidence.append(f'OUI üreticisi: {vendor} ({category})')
            break
    for patterns,category in VENDOR_RULES:
        match=next((pattern for pattern in patterns if pattern in product_text),None)
        if match:
            scores[category]+=1
            evidence.append(f'Nmap servis ürünü: {match} ({category})')
            break
    for patterns,category in VENDOR_RULES:
        match=next((pattern for pattern in patterns if pattern in snmp_description.lower()),None)
        if match:
            scores[category]+=2
            evidence.append(f'SNMP sysDescr cihaz beyanı: {match} ({category})')
            break
    if vendor in VIRTUAL.values() or vendor.startswith('Docker'):
        scores['Sanal sistem adayı']+=1
        evidence.append('Sanallaştırma MAC öneki')
    numbers={int(p['port']) for p in ports if str(p.get('port','')).isdigit()}
    for port,category,reason in PORT_RULES:
        if port in numbers:
            scores[category]+=1
            evidence.append(reason)
    if not scores:
        return 'Bilinmiyor','belirsiz',evidence
    category=sorted(scores, key=lambda key:(-scores[key],key))[0]
    return category,('orta' if scores[category]>=2 else 'düşük'),evidence


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
                ports=[]
                for port in host.findall('./ports/port'):
                    state=port.find('state')
                    if state is None or state.get('state')!='open':
                        continue
                    svc=port.find('service')
                    ports.append({'port':port.get('portid',''),'protocol':port.get('protocol',''),
                                  'service':svc.get('name','') if svc is not None else '',
                                  'product':svc.get('product','')[:100] if svc is not None else ''})
                xml_mac=next((normalize_mac(a.get('addr')) for a in host.findall('./address') if a.get('addrtype')=='mac'), '')
                neighbour=neighbours.get(ip,{})
                neighbour_mac=normalize_mac(neighbour.get('mac'))
                mac=xml_mac or neighbour_mac
                vendor,source=vendor_for(mac,vendors) if mac else ('Bilinmiyor','unavailable')
                snmp_path=path.parent/f'snmp_v1_public_{re.sub(r"[^A-Za-z0-9._-]","_",ip)[:90]}.json'
                snmp_description=''
                if snmp_path.is_file():
                    try:
                        snmp_data=json.loads(snmp_path.read_text(encoding='utf-8'))
                        if (snmp_data.get('target')==ip and snmp_data.get('confirmed_response') is True
                                and snmp_data.get('version')=='1' and snmp_data.get('community')=='public'):
                            snmp_description=str(snmp_data.get('sysDescr',''))[:160]
                    except (ValueError,OSError,AttributeError):
                        pass
                category,confidence,signals=classify(vendor,ports,snmp_description)
                notices=[]
                if xml_mac and neighbour_mac and xml_mac!=neighbour_mac:
                    notices.append('Nmap MAC ve yerel komşu önbelleği uyuşmuyor; MAC doğrulanmalı')
                if mac and int(mac[:2],16)&2:
                    notices.append('Yerel/rastgele MAC: OUI fiziksel cihazı doğrulamaz')
                if not mac:
                    notices.append('Uzak rota veya L2 komşuluk yok; MAC tespit edilmedi')
                review=[f'{REVIEW_PORTS[int(p["port"])]} ({p["port"]}) için erişim ve yapılandırmayı inceleyin'
                        for p in ports if str(p['port']).isdigit() and int(p['port']) in REVIEW_PORTS]
                if snmp_description:
                    review.append('SNMPv1/public ile kimlik bilgisi okunuyor; SNMPv3 ve erişim kısıtlarını değerlendirin')
                devices[ip]={'ip':ip,'mac':mac,'mac_source':'nmap' if xml_mac else 'yerel komşu önbelleği' if mac else 'yok',
                             'interface':neighbour.get('device','') if not xml_mac else '',
                             'vendor':vendor,'vendor_source':source,'category':category,
                             'confidence':confidence,'signals':signals,'ports':ports,
                             'review_notes':review,'notices':notices,'snmp_sysdescr':snmp_description,
                             'evidence':str(path.relative_to(root))}
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
             'unknown_count':sum(row['category']=='Bilinmiyor' for row in ordered),
             'categories':dict(Counter(row['category'] for row in ordered)),
             'oui_sources':sources,'neighbour_note':neighbour_error,
             'limits':'MAC yalnızca aynı L2 komşuluğunda gözlenebilir. Üretici donanımın modeli veya güvenlik açığı kanıtı değildir. Kategori ve servisler analist doğrulaması gerektirir.',
             'parse_errors':errors,'devices':ordered}
    output=root/'DEVICE_INVENTORY.json'
    temp=root/'.DEVICE_INVENTORY.pending.json'
    temp.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temp.replace(output)
    return summary
