#!/usr/bin/env python3
"""UBDEN Cyber Security Systems - scoped assessment runner. Python 3.10+."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import math
import os
import pwd
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from xml.etree import ElementTree as ET
from urllib.parse import parse_qsl, unquote, urlsplit

from tui import Console, UI
from analyst_review import guided, CASES
from ai_analyst import analyze_run, ai_input
from device_inventory import build_inventory
from tool_catalog import CATALOG, inventory as catalog_inventory, version as package_version
from host_bridge import invoke as windows_invoke, screenshot_path
from ad_assessment import inspect as inspect_ad
from wireless_assessment import run as run_wireless, validate as validate_wireless
from supplemental_scans import run as run_supplemental
from credential_assessment import run_ssh as run_ssh_passwords
from sql_discovery import discover as discover_sql_browser

ROOT = Path(__file__).resolve().parent
VERSION = "4.8.3"
BASELINE = ROOT / "templates" / "baseline"
HOST_RE = re.compile(r"(?=^.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+", re.I)
WEB_NEXT_AT = 0.0
TOOL_PACKAGES = {tool.executable: tool.package for tool in CATALOG}
TOOL_PACKAGES.update({'curl':'curl','sslscan':'sslscan','nuclei':'nuclei',
                      'snmpget':'snmp','airodump-ng':'aircrack-ng',
                      'aireplay-ng':'aircrack-ng','reaver':'reaver'})
TOOL_VERSIONS = {}


def recorded_tool_version(executable):
    if executable not in TOOL_VERSIONS:
        TOOL_VERSIONS[executable]=package_version(TOOL_PACKAGES.get(executable,executable))
    return TOOL_VERSIONS[executable]


def web_budget_wait():
    """One shared five-request/s budget for direct curl probes."""
    global WEB_NEXT_AT
    moment=time.monotonic()
    if WEB_NEXT_AT > moment:
        time.sleep(WEB_NEXT_AT-moment)
    WEB_NEXT_AT=max(WEB_NEXT_AT,time.monotonic())+0.2

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def ask(label, default="", required=False):
    while True:
        val = UI.prompt(label, default)
        if val or not required:
            return val
        UI.say("  Bu alan zorunlu.", "yellow")

def parse_target(raw):
    raw = raw.strip().lower().rstrip(".")
    if not raw or any(c.isspace() for c in raw) or len(raw) > 253:
        raise ValueError(f"Geçersiz hedef: {raw!r}")
    try:
        return str(ipaddress.ip_network(raw, strict=False)) if "/" in raw else str(ipaddress.ip_address(raw))
    except ValueError:
        if HOST_RE.fullmatch(raw) and not raw.startswith("*.") and not re.fullmatch(r"[0-9.]+", raw):
            return raw.encode("idna").decode("ascii")
        raise ValueError(f"Yalnızca FQDN, IP ve CIDR kabul edilir: {raw!r}")

def is_network(value):
    return "/" in value

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def excluded(value, exclusions):
    if value in exclusions:
        return True
    try:
        ip = ipaddress.ip_address(value)
        return any("/" in x and ip in ipaddress.ip_network(x) for x in exclusions)
    except ValueError:
        return False

def resolve(host):
    return sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def validate_task_address_budget(targets, frozen=None):
    """Keep the union of all numeric targets within one /24 or /120 budget."""
    addresses={4:set(),6:set()}
    for target in targets:
        if is_network(target):
            candidates=ipaddress.ip_network(target)
        elif is_ip(target):
            candidates=(ipaddress.ip_address(target),)
        else:
            candidates=(ipaddress.ip_address(ip) for ip in (frozen or {}).get(target,[]))
        for ip in candidates:
            addresses[ip.version].add(ip)
            if len(addresses[4])>256 or len(addresses[6])>256:
                raise ValueError('Görevde toplam en fazla 256 IPv4 veya 256 IPv6 adresi olabilir')
    return {family:len(values) for family,values in addresses.items()}


def freeze_scope(meta):
    """Resolve named targets and exclusions once after the operator authorizes traffic."""
    frozen={}
    expanded=list(meta['exclusions'])
    meta['exclusion_dns_names']=[name for name in meta['exclusions']
                                 if not is_ip(name) and not is_network(name)]
    for name in meta['exclusions']:
        if not is_ip(name) and not is_network(name):
            try: addresses=resolve(name)
            except socket.gaierror: addresses=[]
            frozen[name]=addresses
            expanded.extend(addresses)
    for name in meta['targets']:
        if not is_ip(name) and not is_network(name):
            try: frozen[name]=resolve(name)
            except socket.gaierror: frozen[name]=[]
    dc=meta.get('ad',{}).get('dc')
    if dc and not is_ip(dc):
        try: frozen[dc]=resolve(dc)
        except socket.gaierror: frozen[dc]=[]
    try:
        meta['address_budget']=validate_task_address_budget(meta['targets'],frozen)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    meta['exclusions']=list(dict.fromkeys(expanded))
    meta['frozen_dns']=frozen
    meta['scope_frozen_at']=now()


def route_guard(ips, selected, raw, events, target):
    if not selected or not ips:
        return ips
    result=windows_invoke('route',{'ips':ips},timeout=min(180,max(30,len(ips)*2)))
    routes=result.get('routes',[]) if result.get('status')=='ok' else []
    by_ip={row.get('ip'):row for row in routes if isinstance(row,dict)}
    windows_allowed=[ip for ip in ips if by_ip.get(ip,{}).get('status')=='ok' and
                     by_ip[ip].get('interface_index') in selected]
    linux_routes=[]
    if os.name != 'nt':
        allowed=[]
        for ip in windows_allowed:
            try:
                route=subprocess.run(['ip','-j','route','get',ip],capture_output=True,
                                     text=True,timeout=3,check=False)
                entries=json.loads(route.stdout) if route.returncode==0 else []
                selected_route=entries[0] if entries else {}
                okay=bool(selected_route.get('dev') and selected_route['dev']!='lo')
                linux_routes.append({'ip':ip,'status':'ok' if okay else 'blocked',
                                     'route':selected_route})
                if okay: allowed.append(ip)
            except (OSError,ValueError,subprocess.TimeoutExpired,IndexError,TypeError):
                linux_routes.append({'ip':ip,'status':'error'})
    else:
        allowed=windows_allowed
    summary={'target':target,'selected_interfaces':selected,'queried':len(ips),
             'allowed':allowed,'blocked':[ip for ip in ips if ip not in allowed],
             'routes':routes,'linux_routes':linux_routes,
             'bridge_status':result.get('status')}
    path=raw/'route_snapshot.json'
    atomic_json(path,summary)
    events.append({'step':'route_scope','target':target,
                   'status':'ok' if len(allowed)==len(ips) else 'blocked',
                   'detail':f"{len(allowed)}/{len(ips)} IP secilen Windows adaptoru uzerinden erisilebilir",
                   'output':str(path.relative_to(raw.parent.parent.parent)),
                   'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    return allowed

def atomic_json(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)

def safe_filename(value):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:90]

def template_inventory(directory):
    files=sorted(p for p in Path(directory).rglob('*') if p.is_file() and p.suffix.lower() in ('.yaml','.yml'))
    if not files:
        raise ValueError("Nuclei şablon dizini YAML içermiyor.")
    if len(files)>40:
        raise ValueError('Nuclei şablon sayısı 40 sınırını aşıyor')
    import yaml
    entries=[]
    total_paths=0
    for path in files:
        if path.is_symlink() or path.stat().st_size>65536:
            raise ValueError('Nuclei şablonu sembolik bağ veya 64 KB üzeri olamaz')
        body=path.read_bytes()
        try:
            document=yaml.safe_load(body)
        except yaml.YAMLError as exc:
            raise ValueError(f'{path.name}: YAML okunamadi') from exc
        if not isinstance(document,dict) or set(document)-{'id','info','http'} or \
                not isinstance(document.get('http'),list) or len(document['http'])!=1:
            raise ValueError(f'{path.name}: yalnız tek salt okunur HTTP isteği kabul edilir')
        request=document['http'][0]
        if not isinstance(request,dict) or set(request)-{'method','path','matchers','matchers-condition'} or \
                str(request.get('method','')).upper() not in ('GET','HEAD') or \
                not isinstance(request.get('path'),list) or not 1<=len(request['path'])<=2:
            raise ValueError(f'{path.name}: yöntem veya istek biçimi kapsam dışı')
        for url in request['path']:
            if not isinstance(url,str) or not re.fullmatch(r'\{\{BaseURL\}\}/[A-Za-z0-9._~/-]*',url) or \
                    any(segment in ('.','..') for segment in url.split('/')) or '//' in url[11:]:
                raise ValueError(f'{path.name}: yalnız sabit hedef yolu kabul edilir')
        total_paths+=len(request['path'])
        entries.append({'name':str(path.relative_to(directory)),
                        'sha256':hashlib.sha256(body).hexdigest()})
    if total_paths>40:
        raise ValueError('Nuclei şablonları toplam 40 istek sınırını aşıyor')
    return entries

def choose_run_base(override=None):
    if override:
        return Path(override).expanduser().resolve(), None
    try:
        uid=int(os.environ.get("SUDO_UID",str(os.getuid())))
        account=pwd.getpwuid(uid)
    except (ValueError, KeyError):
        return ROOT/"runs", None
    desktop=Path(account.pw_dir)/"Desktop"
    if uid < 1000 or not desktop.is_dir() or desktop.is_symlink():
        return ROOT/"runs", None
    base=desktop/"UBDEN-Cyber-Reports"
    if base.is_symlink():
        raise SystemExit("Masaüstü rapor dizini sembolik bağ olamaz.")
    base.mkdir(mode=0o700,exist_ok=True)
    if base.stat().st_uid not in (uid,os.geteuid()):
        raise SystemExit("Masaüstü rapor dizininin sahibi beklenen kullanıcı değil.")
    if os.geteuid()==0:
        os.chown(base,uid,account.pw_gid)
    os.chmod(base,0o700)
    return base,(uid,account.pw_gid) if os.geteuid()==0 else None

def handoff_run(root, owner):
    if owner is None:
        return
    for path in root.rglob('*'):
        if path.is_symlink():
            raise RuntimeError("Kanıt klasöründe sembolik bağ beklenmiyor.")
        os.chown(path,*owner)
    os.chown(root,*owner)


def register_run(root):
    """Keep an export index for destroy, including custom WSL run directories."""
    if ROOT != Path('/opt/ubden-cyber'):
        return
    index=ROOT/'run-locations.json'
    try:
        previous=json.loads(index.read_text(encoding='utf-8')) if index.exists() else []
    except (OSError,ValueError):
        previous=[]
    if not isinstance(previous,list):
        previous=[]
    location=str(root.resolve())
    if location not in previous:
        previous.append(location)
        atomic_json(index,previous)

def tool_inventory():
    return catalog_inventory()

def auth_path(value):
    # Only a path on the explicitly selected host; never accept a URL or redirect.
    if not value.startswith("/") or value.startswith("//") or "\\" in value or any(ord(c) < 32 for c in value) or "#" in value or "?" in value:
        raise ValueError("Korumalı uç nokta yalnızca / ile başlayan, sorgu ve sır içermeyen aynı hedef yolu olmalı.")
    if any(segment in (".", "..") for segment in value.split("/")):
        raise ValueError("Yolda . veya .. bileşeni olamaz.")
    return value

def scenario_path(value):
    """Same-origin explicit path; query may contain only non-secret test identifiers."""
    if len(value)>256 or not value.startswith('/') or value.startswith('//') or '\\' in value or '#' in value or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Test yolu / ile başlamalı; URL, parça veya kontrol karakteri içeremez.')
    parsed=urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path:
        raise ValueError('Yalnızca aynı hedefteki yol ve sorgu parametreleri kabul edilir.')
    decoded=unquote(parsed.path)
    if decoded.startswith('//') or any(x in ('.','..') for x in decoded.split('/')):
        raise ValueError('Test yolunda yönlendirme veya üst dizin işareti bulunamaz.')
    if parsed.query:
        pairs=parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=8)
        if not pairs or any(not key or re.search(r'(?i)pass|secret|token|auth|cookie|session|api[_-]?key',key) for key,_ in pairs):
            raise ValueError('Sorguda yalnızca sır içermeyen test kimlikleri kabul edilir.')
    return value

def private_value(label):
    if not sys.stdin.isatty():
        raise SystemExit("Gizli bilgi girişi için etkileşimli terminal gerekir.")
    value = getpass.getpass(f"  > {label}: ")
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SystemExit("Gizli değer boş olamaz ve kontrol karakteri içeremez.")
    return value

def collect_credentials(targets, exclusions):
    """Keep secrets in memory only; return public descriptors separately."""
    candidates=[t for t in targets if not is_network(t) and not excluded(t, exclusions)]
    if not candidates:
        UI.say("  Tekil web hedefi yok; kimlik doğrulamalı adım atlanıyor.", "yellow")
        return [], []
    UI.say("  İsteğe bağlı HTTPS erişim kontrolü; boş bırakılırsa kimliksiz devam eder.", "dim")
    UI.say("  Form girişinde tarayıcıdan alınan geçici test oturumu çerezini kullanabilirsiniz.", "dim")
    public, secrets = [], []
    for slot in range(4):
        method=UI.menu("Kimlik yöntemi",[("0","Atla / tamamla"),("1","HTTP Basic: kullanıcı + parola"),("2","Bearer: API token"),("3","Cookie: mevcut test oturumu")],"0")
        if method == "0": break
        target=ask("Yetkili tekil hedef (FQDN/IP)",candidates[0],required=True)
        if target not in candidates:
            raise SystemExit("Kimlik hedefi kapsam içindeki tekil FQDN/IP olmalı.")
        role=ask("Test hesabının rol etiketi (ör. standart_kullanici)",required=True)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}",role):
            raise SystemExit("Rol etiketi 1-40 karakter; harf, rakam, _ veya - kullanın.")
        if any(c["target"]==target and c["role"]==role for c in public):
            raise SystemExit("Aynı hedef ve rol için yinelenen giriş var.")
        port_text=ask("HTTPS portu", "443")
        if not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
            raise SystemExit("Geçerli bir HTTPS portu girin.")
        port=int(port_text)
        try: path=auth_path(ask("Korumalı, salt okunur yol", "/",required=True))
        except ValueError as exc: raise SystemExit(str(exc)) from exc
        secret={"method":{"1":"basic","2":"bearer","3":"cookie"}[method]}
        if method == "1":
            username=ask("Test kullanıcı adı",required=True)
            if ":" in username or any(ord(c)<32 or ord(c)==127 for c in username):
                raise SystemExit("Kullanıcı adı ':' veya kontrol karakteri içeremez.")
            secret["username"]=username
            secret["value"]=private_value("Test parolası (gizli)")
        else:
            secret["value"]=private_value("API token (gizli)" if method=="2" else "Cookie başlığı değeri (gizli)")
        public.append({"target":target,"role":role,"method":secret["method"],"port":port,"path":path})
        secrets.append(secret)
    return public, secrets


def collect_ssh_passwords(targets, exclusions):
    """Only explicit test accounts; at most two in-memory passwords per account."""
    UI.say('  SSH parola modülü isteğe bağlıdır; yalnız yetkili test hesabı kullanılır.','dim')
    public,secret=[],[]
    for slot in range(4):
        value=ask('SSH test hesabı IP (boş=bitir)')
        if not value: break
        try: ip=str(ipaddress.ip_address(value))
        except ValueError as exc: raise SystemExit('SSH test hostu sayısal IP olmalı') from exc
        permitted=any(ip==target if is_ip(target) else
                      ipaddress.ip_address(ip) in ipaddress.ip_network(target)
                      if is_network(target) else False for target in targets)
        if not permitted or excluded(ip,exclusions):
            raise SystemExit('SSH test IP açık hedef veya CIDR içinde ve hariç dışında olmalı')
        username=ask('Yalnız test hesabı kullanıcı adı',required=True)
        if not re.fullmatch(r'[A-Za-z0-9_.@\\-]{1,80}',username):
            raise SystemExit('SSH test hesabı adı geçersiz')
        if any(x['target_ip']==ip and x['username']==username for x in public):
            raise SystemExit('Aynı SSH test hesabı yinelenemez')
        fingerprint=ask('Önceden doğrulanmış SSH sunucu anahtarı SHA256 parmak izi',required=True)
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',fingerprint):
            raise SystemExit('SSH anahtar parmak izi SHA256: biçiminde olmalı')
        count=UI.menu('En fazla iki parola adayı', [('1','Tek aday'),('2','İki aday')],'1')
        values=[private_value(f'SSH parola adayı {i+1} (gizli)') for i in range(int(count))]
        public.append({'target_ip':ip,'username':username,'port':22,
                       'host_key_sha256':fingerprint,'max_attempts':len(values)})
        secret.append({'target_ip':ip,'username':username,'passwords':values,'used':False})
    return public,secret

def collect_role_scenarios(credentials):
    """Pre-authorized, read-only role/IDOR scenarios; no AI may add a URL."""
    choices=[spec for spec,_ in credentials]
    if len(choices)<2 or UI.menu("Rol/IDOR testi",[("0","Atla"),("1","Test hesaplarıyla GET karşılaştırması")],"0")=="0":
        return []
    UI.say("  Her test için aynı hedef/HTTPS portunda iki test hesabı seçin.","dim")
    UI.say("  IDOR: ilk hesabın kendi test nesnesi; ikinci hesap o nesneye erişmemeli.","dim")
    for i,item in enumerate(choices,1):
        UI.say(f"    {i}) {item['target']}:{item['port']} / {item['role']}","dim")
    scenarios=[]
    for slot in range(8):
        kind=UI.menu("Yetki testi",[("0","Bitti"),("1","Rol bazlı yetki: yetkili/yetkisiz rol"),
                                   ("2","IDOR: sahip/başka test hesabı"),
                                   ("3","Salt okunur iş kuralı: yetkisiz profile kapalı kaynak")],"0")
        if kind=="0": break
        a=ask("Kaynak sahibi/yetkili hesabın sıra numarası",required=True)
        b=ask("Erişimi reddedilmesi beklenen hesabın sıra numarası",required=True)
        if not a.isdecimal() or not b.isdecimal() or not 1<=int(a)<=len(choices) or not 1<=int(b)<=len(choices) or a==b:
            raise SystemExit("İki farklı geçerli test hesabı seçin.")
        owner,challenger=choices[int(a)-1],choices[int(b)-1]
        if (owner['target'],owner['port'])!=(challenger['target'],challenger['port']):
            raise SystemExit("Hesaplar aynı hedef ve HTTPS portunda olmalı.")
        try: path=scenario_path(ask("Salt okunur test kaynağı yolu veya ?id=test_nesnesi",required=True))
        except ValueError as exc: raise SystemExit(str(exc)) from exc
        if len(path)>256 or any(x['target']==owner['target'] and x['path']==path and x['owner']==owner['role'] and x['challenger']==challenger['role'] for x in scenarios):
            raise SystemExit("Yol uzun veya senaryo tekrarlı.")
        rule=ask("Beklenen iş kuralı (kısa, sır içermeyen açıklama)",required=True) if kind=='3' else ''
        scenarios.append({'id':f"AC-{slot+1:02d}",'kind':{'1':'role','2':'idor','3':'logic'}[kind],
                          'target':owner['target'],'port':owner['port'],'path':path,
                          'owner':owner['role'],'challenger':challenger['role'],'rule':rule[:240]})
    return scenarios

def configure_ai():
    if UI.menu("Claude AI analist",[("0","Kapalı"),("1","Aç: isteğe bağlı rapor incelemesi ve sınırlı ek kontrol")],"0")=="0":
        return None
    UI.say("  API anahtarı bellekte tutulur; rapora, dosyaya ve komut satırına yazılmaz.","dim")
    model=ask("Claude model kimliği",'claude-sonnet-4-6')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}',model):
        raise SystemExit("Geçersiz model kimliği.")
    raw=UI.menu("Claude'ye gönderilecek içerik",[("1","Sadece anonimleştirilmiş adım/bulgu özeti"),
                      ("2","Özet + sınırlı ham kanıt/rapor metni (müşteri verisi içerebilir)")],"1")=="2"
    UI.say("  Aktarım: Anthropic API. Ham mod müşteri/kişisel veri içerebilir; yalnızca paylaşım yetkiniz varsa seçin.","yellow")
    if UI.prompt("API'ye veri gönderilmesini onaylıyorum: GONDER yazın")!='GONDER':
        UI.say("  Claude kapatıldı; test devam edecek.","yellow")
        return None
    try:
        key=private_value('Claude API anahtarı (gizli)')
    except (SystemExit,EOFError):
        UI.say("  Claude anahtarı alınamadı; AI kapatıldı, diğer adımlar devam edecek.","yellow")
        return None
    return {'key':key,'model':model,'raw':raw}

def _curl_secret_config(secret):
    if secret['method']=='basic':
        return f"user = {json.dumps(secret['username']+':'+secret['value'])}\nbasic\n"
    if secret['method']=='bearer':
        return f"header = {json.dumps('Authorization: Bearer '+secret['value'])}\n"
    return f"header = {json.dumps('Cookie: '+secret['value'])}\n"

def role_probe(root, scenario, ip, credentials, events, attempt=1):
    """Two bounded GETs, never follows redirects or persists response bodies."""
    target=scenario['target']; port=scenario['port']; path=scenario['path']
    if not any(s['target']==target and s['port']==port and s['role']==scenario['owner'] for s,_ in credentials):
        raise ValueError('Kaynak sahibi hesabı bulunamadı')
    folder=root/'targets'/safe_filename(target)/'raw'
    folder.mkdir(parents=True,exist_ok=True)
    host=f'[{target}]' if ':' in target else target
    pin=f'[{ip}]' if ':' in ip else ip
    url=f'https://{host}:{port}{path}'
    outcomes={}
    for label,role in (('owner',scenario['owner']),('challenger',scenario['challenger'])):
        secret=next(secret for spec,secret in credentials if spec['target']==target and spec['port']==port and spec['role']==role)
        argv=['curl','-q','--silent','--show-error','--noproxy','*','--proto','=https','--max-time','15',
              '--connect-timeout','5','--max-redirs','0','--max-filesize','65536','--request','GET',
              '--output','/dev/null','--write-out','%{http_code}\n%{size_download}',
              '--resolve',f'{target}:{port}:{pin}','--config','-',url]
        started=time.monotonic()
        try:
            web_budget_wait()
            result=subprocess.run(argv,input=_curl_secret_config(secret),text=True,capture_output=True,timeout=20,check=False)
            lines=result.stdout.splitlines()
            valid=result.returncode==0 and len(lines)==2 and re.fullmatch(r'[1-5][0-9]{2}',lines[0]) and lines[1].isdigit()
            outcomes[label]={'http_status':int(lines[0]) if valid else None,'bytes':int(lines[1]) if valid else None,
                             'result':'ok' if valid else 'error','seconds':round(time.monotonic()-started,2)}
        except (OSError,subprocess.TimeoutExpired):
            outcomes[label]={'http_status':None,'bytes':None,'result':'error','seconds':round(time.monotonic()-started,2)}
    owner=outcomes['owner']['http_status']; other=outcomes['challenger']['http_status']
    status=('error' if None in (owner,other) else 'blocked' if owner not in (200,206) else
            'review' if other in (200,206) else 'ok' if other in (401,403,404) else 'inconclusive')
    payload={**scenario,'ip':ip,'attempt':attempt,'outcomes':outcomes,'assessment':status,
             'note':'HTTP durum/uzunluk farkı yalnızca gözlemdir; 200 hata sayfası veya önbellek olabilir. Analist kanıtlamalıdır.'}
    dest=folder/f"role_{scenario['id']}_{safe_filename(ip)}_{attempt}.json"
    atomic_json(dest,payload)
    record={'step':f"role_{scenario['id']}_{safe_filename(ip)}_{attempt}",'target':target,'status':status,
            'output':str(dest.relative_to(root)),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),
            'seconds':sum(x['seconds'] for x in outcomes.values()),'detail':f"{scenario['kind']} / salt okunur test hesapları"}
    events.append(record);UI.result(record['step'],status,record['seconds'])
    return payload

def access_probe(target, ip, spec, secret, folder, events):
    """One anonymous and one authenticated HEAD; record only status, no headers or secrets."""
    folder.mkdir(parents=True, exist_ok=True)
    host=f"[{target}]" if ":" in target else target
    pinned=f"[{ip}]" if ":" in ip else ip
    url=f"https://{host}:{spec['port']}{spec['path']}"
    argv=["curl","-q","--silent","--show-error","--noproxy","*","--proto","=https","--max-time","15","--connect-timeout","5","--max-redirs","0","--head","--output","/dev/null","--write-out","%{http_code}","--resolve",f"{target}:{spec['port']}:{pinned}"]
    outcomes={}
    for mode in ("anonymous","authenticated"):
        config=None
        if mode == "authenticated":
            if secret["method"] == "basic":
                # curl reads credentials from stdin; never argv, logs, or on-disk config.
                value=f"{secret['username']}:{secret['value']}"
                config=f"user = {json.dumps(value)}\nbasic\n"
            elif secret["method"] == "bearer":
                config=f"header = {json.dumps('Authorization: Bearer '+secret['value'])}\n"
            else:
                config=f"header = {json.dumps('Cookie: '+secret['value'])}\n"
        started=time.monotonic()
        try:
            web_budget_wait()
            result=subprocess.run(argv+(["--config","-"] if config else [])+[url],input=config,text=True,capture_output=True,timeout=22,check=False)
            code=result.stdout.strip()
            outcomes[mode]={"status":"ok" if result.returncode==0 and re.fullmatch(r"[1-5][0-9]{2}",code) else "error", "http_status":int(code) if re.fullmatch(r"[1-5][0-9]{2}",code) else None,"seconds":round(time.monotonic()-started,2)}
        except (OSError, subprocess.TimeoutExpired):
            outcomes[mode]={"status":"error","http_status":None,"seconds":round(time.monotonic()-started,2)}
    valid=all(x["status"]=="ok" for x in outcomes.values())
    anon=outcomes["anonymous"]["http_status"]
    authed=outcomes["authenticated"]["http_status"]
    status=("error" if not valid else "ok" if anon in (401,403) and 200 <= authed < 300
            else "inconclusive")
    evidence={"target":target,"ip":ip,"role":spec["role"],"method":spec["method"],"port":spec["port"],"path":spec["path"],"anonymous":outcomes["anonymous"],"authenticated":outcomes["authenticated"],"note":"HEAD durum kodları erişim gözlemidir; yetki açığı doğrulaması değildir."}
    dest=folder/f"auth_{safe_filename(ip)}_{safe_filename(spec['role'])}.json"
    atomic_json(dest,evidence)
    record={"step":f"auth_{safe_filename(target)}_{safe_filename(spec['role'])}","target":target,"status":status,"output":str(dest.relative_to(folder.parent.parent.parent)),"seconds":sum(x['seconds'] for x in outcomes.values()),"sha256":hashlib.sha256(dest.read_bytes()).hexdigest(),"detail":"Anonim ve test oturumlu HTTPS HEAD karşılaştırması"}
    events.append(record)
    UI.result(record["step"],status,record["seconds"])

MANUAL_PLAN = """# Manuel penetrasyon testi takip planı

Bu maddeler otomatik taramada **gerçekleştirilmiş sayılmaz**. Tester her adımı
yetki kapsamına göre ayrıca uygulayıp kanıtı ve sonucu
`ubden-cyber --analyst-review GOREV_DIZINI` ile kaydetmelidir.

En az iki normal test hesabı ve bir yetkili rol ile salt okunur örnek
kaynaklar seçin. Her işlem için beklenen erişimi ve gerçek sonucu kaydedin;
IDOR kontrolünde yalnızca kurumca sağlanan test kaynaklarını kullanın.
Ham çerezleri, tokenları, parolaları ve kişisel verileri kanıt dosyasına koymayın.
AI analist önerileri insan doğrulaması olmadan güvenlik açığı olarak raporlanmaz.
İşlem yapan iş mantığı testlerini yalnızca açık izinle analist yürütür.

## Kontrol başlıkları

Her başlık için `bekliyor`, `test edildi`, `bulgu` veya gerekçeli
`uygulanamaz` durumu, sonuç notu ve kanıt kaydedilir.

""" + "\n".join(f"- [ ] {code}: {title}" for code,title in CASES) + """

Web ve API testleri için OWASP WSTG; ağ ve kimlik altyapısı için kurumun onaylı
test yöntemi ve değişiklik penceresi esas alınır.
"""

def open_tcp_ports(xml_path):
    try:
        tree=ET.parse(xml_path)
        return sorted({int(port.get('portid')) for port in tree.findall('.//port')
                       if port.get('protocol')=='tcp' and port.find('state') is not None
                       and port.find('state').get('state')=='open'})
    except (OSError,ValueError,ET.ParseError):
        return []

def open_tcp_ports_by_host(xml_path, allowed):
    """Keep multi-host Nmap results scoped per IP for follow-up NSE checks."""
    try:
        tree=ET.parse(xml_path)
        ports={}
        for host in tree.findall('./host'):
            addresses={node.get('addr') for node in host.findall('./address')}
            for address in addresses & set(allowed):
                ports[address]=sorted({int(port.get('portid')) for port in host.findall('./ports/port')
                    if port.get('protocol')=='tcp' and port.find('state') is not None
                    and port.find('state').get('state')=='open'})
        return ports
    except (OSError,ValueError,ET.ParseError,TypeError):
        return {}

def icmp_fallback(allowed, max_rate, version):
    """Bounded Linux ping sweep to supplement or recover Nmap discovery."""
    if not shutil.which('ping'):
        return None
    rate=min(max(int(max_rate),1),50)
    def probe(ip):
        try:
            result=subprocess.run(['ping','-n','-c','1','-W','1',
                                   '-6' if version==6 else '-4',ip],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                  check=False,timeout=2.5)
            return result.returncode==0
        except (OSError,subprocess.TimeoutExpired):
            return False
    started=time.monotonic()
    with ThreadPoolExecutor(max_workers=min(rate,16)) as pool:
        futures=[]
        next_launch=time.monotonic()
        for ip in allowed:
            pause=next_launch-time.monotonic()
            if pause>0: time.sleep(pause)
            futures.append((ip,pool.submit(probe,ip)))
            next_launch=max(next_launch+1/rate,time.monotonic())
        live=[]
        for index,(ip,future) in enumerate(futures,1):
            if future.result():
                live.append(ip)
            UI.counted('ICMP keşfi',index,len(futures),started)
        return live

def discover_cidr_hosts(target, net, raw, events, exclusions, max_rate, selected_interfaces=()):
    """Probe eligible CIDR addresses once; port scans only get verified responses."""
    allowed=[str(ip) for ip in net.hosts() if not excluded(str(ip),exclusions)]
    allowed=route_guard(allowed,list(selected_interfaces),raw,events,target)
    if not allowed:
        events.append({'step':'discovery','target':target,'status':'excluded',
                       'detail':'Kapsamdaki bütün host adresleri hariç tutulmuş'})
        return []
    # -iL includes only explicitly authorized, non-excluded addresses.
    targets_file=raw/'discovery_targets.txt'
    targets_file.write_text('\n'.join(allowed)+'\n',encoding='ascii')
    xml=raw/'discovery_hosts.xml'
    argv=['nmap']+(['-6'] if net.version==6 else [])+['-sn','-n','--disable-arp-ping',
          '--discovery-ignore-rst','-PE','-PS80,443',
          '-PA80,443','-T3','--stats-every','10s','--max-rate',str(max_rate),'--max-retries','1',
          '--host-timeout','15s','-oX',str(xml),'-iL',str(targets_file)]
    result=command('discovery_hosts',argv,raw,events,90)
    status='error' if result['status']!='ok' else 'ok'
    live=[]
    if status=='ok':
        try:
            tree=ET.parse(xml)
            if tree.getroot().tag!='nmaprun':
                raise ValueError('Nmap XML beklenen biçimde değil')
            candidate=set()
            for host in tree.findall('./host'):
                state=host.find('./status')
                if state is None or state.get('state')!='up': continue
                for address in host.findall('./address'):
                    if address.get('addrtype')==('ipv6' if net.version==6 else 'ipv4'):
                        candidate.add(address.get('addr'))
            if candidate-set(allowed):
                raise ValueError('Keşif sonucu izinli adres kümesinin dışında')
            live=sorted(candidate,key=ipaddress.ip_address)
            if not live: status='no_hosts'
        except (ET.ParseError,OSError,ValueError,TypeError) as exc:
            status='error'
            events.append({'step':'discovery_parse','target':target,'status':'error',
                           'detail':f'Host keşfi çıktısı okunamadı: {type(exc).__name__}'})
    nmap_responding_count=len(live)
    if status!='ok':
        UI.say('  Nmap keşfi eksik kaldı; sınırlı ICMP ping yoklamasıyla yanıt verenler taranacak.','yellow')
    fallback=icmp_fallback(allowed,max_rate,net.version)
    used_fallback=fallback is not None
    if fallback:
        live=sorted(set(live)|set(fallback),key=ipaddress.ip_address)
        if status=='no_hosts': status='ok'
        elif status=='error': status='partial'
    if status=='ok' and not live: status='no_hosts'
    events.append({'step':'icmp_probe','target':target,
                   'status':'missing_tool' if fallback is None else 'ok' if fallback else 'no_hosts',
                   'detail':f"{len(fallback or [])}/{len(allowed)} IP ping yanıtı verdi; Nmap sonucu: {result['status']}"})
    summary={'target':target,'status':status,'eligible_count':len(allowed),
             'responding_count':len(live),'unresponsive_count':len(allowed)-len(live) if status in ('ok','partial','no_hosts') else None,
             'responding_hosts':live,'nmap_responding_count':nmap_responding_count,
             'icmp_responding_count':len(fallback or []),
             'all_addresses_responded':len(allowed)>=32 and len(live)==len(allowed),
             'method':'Nmap -sn; ICMP ve TCP SYN/ACK yoklamaları (ARP/ND keşfi ve RST host yanıtı sayılmaz)',
             'fallback_used':used_fallback,
             'note':'Yanıt vermemesi hostun kapalı olduğunu kanıtlamaz. Nmap tamamlanmadıysa ping yanıtlı hostlarla kısmi tarama sürer.'}
    if used_fallback:
        summary['method']+='; sınırlı ICMP ping tamamlayıcı yoklaması'
    if summary['all_addresses_responded']:
        summary['note']+=' Kapsamdaki bütün adresler yanıt verdi; vekil ARP, sanal ağ veya ağ ayarlarını ayrıca doğrulayın.'
        UI.say(f'  UYARI: Bütün IP adresleri yanıt verdi (Nmap {nmap_responding_count}, ping {len(fallback or [])}).'
               ' Vekil ARP/sanal ağı doğrulayın; toplu tarama hız sınırıyla sürecek.','yellow')
    destination=raw/'discovery_summary.json'
    atomic_json(destination,summary)
    detail=(f"{len(live)}/{len(allowed)} yanıt veren host; {len(allowed)-len(live)} yanıt vermedi"
            if status in ('ok','partial','no_hosts') else 'Keşif tamamlanmadı ve ping yanıtı yok; servis taraması başlatılmadı')
    events.append({'step':'discovery_summary','target':target,'status':status,
                   'detail':detail,
                   'output':str(destination.relative_to(raw.parent.parent.parent)),
                   'sha256':hashlib.sha256(destination.read_bytes()).hexdigest()})
    UI.say((f"  CIDR keşfi: {len(allowed)} IP kontrol edildi, {len(live)} yanıt verdi; "
            f"servis taraması {len(live)} IP için yapılacak." if status in ('ok','partial','no_hosts') else
            '  CIDR keşfi tamamlanmadı ve ping yanıtı yok; diğer hedefler taranmaya devam edecek.'),
           'green' if status=='ok' else 'yellow')
    return live

def command(name, argv, folder, events, timeout=900, stop_on=()):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.txt"
    started = time.monotonic()
    record = {"step": name, "tool": argv[0], "tool_version": recorded_tool_version(argv[0]),
              "started_at": now(), "command": argv,
              "output": str(path.relative_to(folder.parent.parent.parent)), "status": "pending"}
    interrupted = False
    last_snapshot=0.0
    last_stop_check=0.0
    snippet=None
    class StopPattern(Exception):
        pass
    if not shutil.which(argv[0]):
        record.update(status="missing_tool", detail=f"{argv[0]} kurulu değil")
    else:
        try:
            if argv[0] in ('curl','nikto','nuclei'): web_budget_wait()
            with path.open("w", encoding="utf-8", errors="replace") as handle:
                process = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    while True:
                        try:
                            code = process.wait(timeout=.15)
                            break
                        except subprocess.TimeoutExpired:
                            if stop_on and time.monotonic()-last_stop_check>=0.5:
                                last_stop_check=time.monotonic()
                                try:
                                    with path.open('rb') as snapshot:
                                        snapshot.seek(max(0,path.stat().st_size-8192))
                                        tail=snapshot.read().decode('utf-8','replace').lower()
                                    if any(pattern.lower() in tail for pattern in stop_on):
                                        raise StopPattern()
                                except OSError:
                                    pass
                            if argv[0]=='nmap' and time.monotonic()-last_snapshot>=1:
                                last_snapshot=time.monotonic()
                                try:
                                    with path.open('rb') as snapshot:
                                        snapshot.seek(max(0,path.stat().st_size-8192))
                                        snippet=snapshot.read().decode('utf-8','replace')
                                    if '-oX' in argv:
                                        xml_status=Path(argv[argv.index('-oX')+1])
                                        if xml_status.is_file():
                                            with xml_status.open('rb') as snapshot:
                                                snapshot.seek(max(0,xml_status.stat().st_size-8192))
                                                snippet+='\n'+snapshot.read().decode('utf-8','replace')
                                except OSError:
                                    pass
                            UI.tick(name, started, timeout, snippet)
                            if time.monotonic() - started >= timeout:
                                raise subprocess.TimeoutExpired(argv, timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt, StopPattern) as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    if isinstance(exc, KeyboardInterrupt):
                        interrupted = True
                        record.update(status="interrupted")
                    elif isinstance(exc, StopPattern):
                        record.update(status="blocked",detail="Durdurma kosulu ciktiya yansidi")
                    else:
                        record.update(status="timeout", detail=f"{timeout} saniye aşıldı")
                else:
                    record.update(status="ok" if code == 0 else "error", exit_code=code)
        except (OSError, ValueError) as exc:
            record.update(status="error", detail=str(exc))
    record.update(finished_at=now(), seconds=round(time.monotonic()-started, 2))
    if path.exists():
        record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    events.append(record)
    UI.result(name, record["status"], record["seconds"])
    if interrupted:
        raise KeyboardInterrupt
    return record

def nuclei_args(target,ip,scheme,templates,selection,max_rate,raw):
    ip_host=f"[{ip}]" if ":" in ip else ip
    template_set=str(Path(templates)/"web") if selection=="baseline" and scheme=="http" else str(templates)
    name=f"nuclei_{safe_filename(ip)}_{scheme}"
    argv=["nuclei","-u",f"{scheme}://{ip_host}/","-t",template_set,"-pt","http","-ni","-dr","-duc","-rl",str(min(max_rate,5)),"-c","1","-bs","1","-timeout","10","-retries","0","-rsr","32768","-rss","32768","-jsonl","-or","-ot"]
    if not is_ip(target):
        argv += ["-H",f"Host: {target}"]
        if scheme=="https": argv += ["-sni",target]
    return name,argv+["-o",str(raw/f"{name}.jsonl")]

def probe_snmp(target, assets, raw, events, max_rate):
    """One read-only SNMPv1/public sysDescr GET per discovered, in-scope IP."""
    summary_path=raw/'snmp_v1_public_summary.json'
    if not shutil.which('snmpget'):
        events.append({'step':'snmp_v1_public','target':target,'status':'missing_tool',
                       'detail':'snmpget kurulu değil; kontrol yapılamadı'})
        UI.say('  SNMPv1/public kontrolü atlandı: snmpget kurulu değil.','yellow')
        return
    started=time.monotonic()
    oid='1.3.6.1.2.1.1.1.0'
    def query(ip):
        try:
            result=subprocess.run(['snmpget','-v1','-c','public','-t','1','-r','0',
                                   '-Oqv',ip,oid],capture_output=True,text=True,
                                  timeout=3,check=False)
            response=result.stdout.strip()[:300] if result.returncode==0 else ''
            return response if response and not response.lower().startswith(('timeout:', 'no such')) else ''
        except (OSError,subprocess.TimeoutExpired,ValueError):
            return ''
    responses=[]
    with ThreadPoolExecutor(max_workers=min(8,max(1,int(max_rate)))) as pool:
        futures=[(ip,pool.submit(query,ip)) for ip in assets]
        for index,(ip,future) in enumerate(futures,1):
            response=future.result()
            if response:
                evidence=raw/f'snmp_v1_public_{safe_filename(ip)}.json'
                atomic_json(evidence,{'target':ip,'version':'1','community':'public',
                                      'oid':oid,'sysDescr':response,'confirmed_response':True})
                responses.append({'ip':ip,'evidence':str(evidence.relative_to(raw.parent.parent.parent))})
            UI.counted('SNMPv1/public',index,len(assets),started)
    summary={'target':target,'tested_count':len(assets),'responding_count':len(responses),
             'responding':responses,'status':'completed',
             'note':'Yalnızca SNMPv1, public community ve tek salt okunur sysDescr sorgusu denendi. Yanıt yokluğu SNMP kapalı anlamına gelmez.'}
    atomic_json(summary_path,summary)
    events.append({'step':'snmp_v1_public','tool':'snmpget','target':target,'status':'ok',
                   'detail':f'{len(responses)}/{len(assets)} cihaz SNMPv1/public ile yanıtladı',
                   'seconds':round(time.monotonic()-started,2),
                   'output':str(summary_path.relative_to(raw.parent.parent.parent)),
                   'sha256':hashlib.sha256(summary_path.read_bytes()).hexdigest()})
    UI.say(f'  SNMPv1/public: {len(responses)}/{len(assets)} yanıt; ayrıntılar raporda.','yellow' if responses else 'cyan')

def scan_cidr_web(target, assets, discovered_ports, raw, events, meta):
    """Inspect discovered web services in a CIDR with a shared 16-host budget."""
    ports = {80: 'http', 443: 'https', 8080: 'http', 8443: 'https'}
    hosts = [ip for ip in assets if set(discovered_ports.get(ip, [])) & ports.keys()]
    if len(hosts) > 16:
        events.append({'step': 'cidr_web_budget', 'target': target, 'status': 'skipped',
                       'detail': f'{len(hosts)-16} web hostu 16-host sinirinda atlandi'})
    for ip in hosts[:16]:
        address = f'[{ip}]' if ':' in ip else ip
        opened = set(discovered_ports.get(ip, []))
        for port, scheme in ports.items():
            if port not in opened:
                continue
            url = f'{scheme}://{address}:{port}/'
            for method in ('HEAD', 'OPTIONS'):
                name = f'cidr_{method.lower()}_{safe_filename(ip)}_{port}'
                argv = ['curl', '--silent', '--show-error', '--noproxy', '*',
                        '--max-time', '15', '--connect-timeout', '5',
                        '--max-redirs', '0', '--proto', '=http,https',
                        '--request', method, '--output', '/dev/null',
                        '--dump-header', '-', url]
                command(name, argv, raw, events, 25)['target'] = ip
        if 443 in opened and shutil.which('sslscan'):
            command(f'cidr_tls_{safe_filename(ip)}',
                    ['sslscan', '--no-colour', f'{address}:443'], raw, events, 75)['target'] = ip
        if shutil.which('nikto'):
            port = next((p for p in (443, 80, 8443, 8080) if p in opened), None)
            if port is not None:
                argv = ['nikto', '-host', address, '-port', str(port), '-Tuning',
                        '123b', '-Pause', '0.2', '-maxtime', '60s', '-timeout', '5s',
                        '-nocheck', '-nolookup', '-nointeractive']
                if ports[port] == 'https':
                    argv.append('-ssl')
                command(f'cidr_nikto_{safe_filename(ip)}_{port}', argv,
                        raw, events, 70)['target'] = ip
        templates = meta.get('nuclei_templates')
        if templates:
            for port, scheme in ((443, 'https'), (80, 'http')):
                if port in opened:
                    name, argv = nuclei_args(ip, ip, scheme, templates,
                                             meta.get('nuclei_profile'), meta['max_rate'], raw)
                    command(name, argv, raw, events, 1200)['target'] = ip


def scan_target(target, meta, root, events, credentials=(), index=1, total=1,
                ssh_tests=()):
    folder = root / "targets" / safe_filename(target)
    raw = folder / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    exclusions = meta["exclusions"]
    for name in meta.get('exclusion_dns_names',[]):
        try: current=set(resolve(name))
        except socket.gaierror: current=set()
        if current != set(meta.get('frozen_dns',{}).get(name,[])):
            events.append({'step':'exclusion_dns_scope','target':target,'status':'blocked',
                           'detail':f'Hariç FQDN adresleri degisti: {name}'})
            return
    if is_network(target):
        net = ipaddress.ip_network(target)
        if (net.version == 4 and net.prefixlen < 24) or (net.version == 6 and net.prefixlen < 120):
            events.append({"step":"scope", "target":target,"status":"blocked", "detail":"CIDR sınırı aşıldı"})
            return
        assets=discover_cidr_hosts(target,net,raw,events,exclusions,meta['max_rate'],
                                   meta.get('selected_interfaces',[]))
    elif is_ip(target):
        assets = [] if excluded(target, exclusions) else [target]
    else:
        try:
            frozen=meta.get('frozen_dns',{}).get(target)
            current=resolve(target)
            if frozen is not None and set(current)!=set(frozen):
                events.append({'step':'dns_scope','target':target,'status':'blocked',
                               'detail':'FQDN IP adresleri kapsam dondurulduktan sonra degisti'})
                return
            assets = [x for x in (frozen if frozen is not None else current)
                      if not excluded(x, exclusions)]
        except socket.gaierror as exc:
            events.append({"step":"dns", "target":target,"status":"error", "detail":str(exc)})
            return
        (raw / "dns_resolution.json").write_text(json.dumps({"host":target,"addresses":assets,"at":now()},indent=2), encoding="utf-8")
        if not assets:
            events.append({"step":"scope","target":target,"status":"blocked","detail":"DNS sonucunun tamamı hariç tutulmuş"})
            return
        if len(assets) > 16:
            events.append({"step":"scope","target":target,"status":"blocked","detail":"16 üzeri DNS adresi; kapsamı IP bazında daraltın"})
            return
    if not assets:
        if not is_network(target):
            events.append({"step":"scope","target":target,"status":"blocked","detail":"Tüm adresler hariç tutulmuş"})
        return
    if not is_network(target):
        assets=route_guard(assets,meta.get('selected_interfaces',[]),raw,events,target)
        if not assets:
            events.append({'step':'route_scope_empty','target':target,'status':'blocked',
                           'detail':'Secilen Windows adaptoru uzerinden kapsam ici IP yok'})
            return
    UI.target(index, total, target, assets)
    if is_network(target):
        UI.say(f"  Toplu servis taraması: {len(assets)} adres / tek Nmap işlemi; Nmap host gruplarını eşzamanlı işler, hız sınırı {meta['max_rate']} paket/sn.","cyan")
    profile=meta["profile"]
    ports=["-p","80,443,8080,8443"] if profile == "web" else ["--top-ports",str(meta["top_ports"])]
    if is_network(target):
        # First scan the selected TCP ports without service/version scripts;
        # the second pass visits only hosts with at least one open TCP port.
        probes=len(assets)*(4 if profile=='web' else int(meta['top_ports']))
        minimum=math.ceil(probes/max(1,meta['max_rate']))
        budget=min(86400,max(3600,minimum*3+1200))
        UI.say(f"  Port keşfi: {probes} yoklama / {meta['max_rate']} paket/sn tavan; kuramsal alt sınır ~{math.ceil(minimum/60)} dk. Sürüm kontrolü sadece açık portlarda.",'cyan')
        live_list=raw/'discovery_live_targets.txt'
        live_list.write_text('\n'.join(assets)+'\n',encoding='ascii')
        fast_xml=raw/'port_discovery.xml'
        fast_result=command('port_discovery',["nmap"]+(['-6'] if ':' in assets[0] else [])+
                ["-Pn","-n","-sS","-T3","--stats-every","10s","--max-rate",str(meta["max_rate"]),
                 "--max-retries","1"]+ports+
                ["-oX",str(fast_xml),"-iL",str(live_list)],raw,events,budget)
        discovered_ports=open_tcp_ports_by_host(fast_xml,assets)
        if fast_result.get('status') != 'ok':
            UI.say('  Port keşfi eksik; okunabilen XML kanıtından devam ediliyor, görünmeyen portlar test edilmiş sayılmaz.','yellow')
        audited=[ip for ip in assets if discovered_ports.get(ip)]
        xml=raw/'nmap_cidr.xml'
        if audited:
            service_list=raw/'service_targets.txt'
            service_list.write_text('\n'.join(audited)+'\n',encoding='ascii')
            opened=sorted({port for ip in audited for port in discovered_ports[ip]})
            UI.say(f'  Sürüm tanıma: {len(audited)}/{len(assets)} açık portlu IP; {len(opened)} farklı TCP portu.','cyan')
            command('nmap_cidr',["nmap"]+(['-6'] if ':' in audited[0] else [])+
                    ["-Pn","-n","-sS","-sV","--version-light","-T3","--stats-every","10s",
                     "--max-rate",str(meta['max_rate']),"--max-retries","1","-p",','.join(map(str,opened)),
                     "-oX",str(xml),"-iL",str(service_list)],raw,events,
                    min(86400,max(1200,math.ceil(len(audited)*len(opened)/max(1,meta['max_rate']))*3+1200)))
            service_ports=open_tcp_ports_by_host(xml,audited)
            for ip in audited:
                if service_ports.get(ip):
                    discovered_ports[ip]=service_ports[ip]
        elif fast_xml.is_file():
            shutil.copyfile(fast_xml,xml)
    else:
        discovered_ports={}
        for ip in assets:
            key=safe_filename(ip)
            xml=raw/("nmap_"+key+".xml")
            command("nmap_"+key,["nmap"]+(["-6"] if ":" in ip else [])+
                    ["-Pn","-sT","-sV","--version-light","-T3","--stats-every","10s","--max-rate",str(meta["max_rate"]),
                     "--max-retries","1","--host-timeout","5m"]+ports+
                    ["-oX",str(xml),ip],raw,events,360)
            discovered_ports[ip]=open_tcp_ports(xml)
    if profile in ("network","full"):
        # Explicit low-impact NSE scripts; never the entire 'vuln' category.
        scripts='ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,http-security-headers'
        if is_network(target):
            audited=[ip for ip in assets if discovered_ports.get(ip)]
            if audited:
                audit_list=raw/'audit_targets.txt'
                audit_list.write_text('\n'.join(audited)+'\n',encoding='ascii')
                opened=sorted({port for ip in audited for port in discovered_ports[ip]})
                command('audit_cidr',["nmap"]+(["-6"] if ':' in audited[0] else [])+
                        ["-Pn","-n","-sS","-T3","--stats-every","10s","--max-rate",str(meta["max_rate"]),
                         "--max-retries","1","--script-timeout","30s",
                         "--script",scripts,"-p",','.join(map(str,opened)),
                         "-oX",str(raw/'audit_cidr.xml'),"-iL",str(audit_list)],raw,events,
                        min(86400,max(3600,math.ceil(len(audited)*len(opened)/max(1,meta['max_rate']))*3+1200)))
        else:
            for ip in assets:
                opened=discovered_ports.get(ip,[])
                if opened:
                    key=safe_filename(ip)
                    command("audit_"+key,["nmap"] + (["-6"] if ":" in ip else []) + ["-Pn","-sT","-sV","-T3","--stats-every","10s","--max-rate",str(meta["max_rate"]),"--max-retries","1","--script-timeout","30s","--host-timeout","5m","--script",scripts,"-p",",".join(map(str,opened)),"-oX",str(raw/("audit_"+key+".xml")),ip],raw,events,360)
    if profile in ('network','full'):
        discover_sql_browser(assets,raw,events,meta['max_rate'])
        probe_snmp(target,assets,raw,events,meta['max_rate'])
        if 'supplemental_network' in meta.get('enabled_modules',[]):
            run_supplemental(target,assets,discovered_ports,raw,events,command,profile)
        for item in ssh_tests:
            ip=item['target_ip']
            if not item['used'] and ip in assets and 22 in discovered_ports.get(ip,[]):
                item['used']=True
                spec=next((row for row in meta.get('password_probes',[])
                           if row['target_ip']==ip and row['username']==item['username']),None)
                if spec:
                    run_ssh_passwords(spec,item['passwords'],events)
    if is_network(target):
        if profile in ('web', 'full'):
            scan_cidr_web(target, assets, discovered_ports, raw, events, meta)
        return
    if profile == "network":
        return
    # CURL pins the destination IP and disallows redirects, preventing off-scope traversal.
    host = target if not is_ip(target) else target
    url_host = f"[{host}]" if ":" in host else host
    for ip in assets:
        opened=set(discovered_ports.get(ip,[]))
        candidates=[("https",443),("http",80)]
        if profile in ("web","full"):
            candidates += [("http",8080),("https",8443)]
        web_ports=[(scheme,port) for scheme,port in candidates if port in opened]
        if not web_ports:
            events.append({'step':'web_preflight','target':ip,'status':'skipped',
                           'detail':'Nmap ciktisinda acik HTTP(S) portu dogrulanmadi'})
        pinned_ip=f"[{ip}]" if ":" in ip else ip
        for scheme, port in web_ports:
            port_suffix=f":{port}" if port not in (80,443) else ""
            url = f"{scheme}://{url_host}{port_suffix}/"
            args = ["curl","--silent","--show-error","--noproxy","*","--max-time","15","--connect-timeout","5","--max-redirs","0","--proto","=http,https","--head","--output","-","--resolve",f"{host}:{port}:{pinned_ip}",url]
            command(f"headers_{safe_filename(ip)}_{scheme}_{port}", args, raw, events, 25)
            if profile in ("web","full"):
                options=["curl","--silent","--show-error","--noproxy","*","--max-time","15","--connect-timeout","5","--max-redirs","0","--proto","=http,https","--request","OPTIONS","--output","/dev/null","--dump-header","-","--resolve",f"{host}:{port}:{pinned_ip}",url]
                command(f"methods_{safe_filename(ip)}_{scheme}_{port}",options,raw,events,25)
        if 443 in opened and shutil.which("sslscan"):
            command(f"tls_{safe_filename(ip)}",["sslscan","--no-colour",f"{pinned_ip}:443"],raw,events,75)
    if profile in ('web','full'):
        web_hosts=[ip for ip in assets if set(discovered_ports.get(ip,[])) & {80,443}]
        if not shutil.which('nikto') and web_hosts:
            events.append({'step':'nikto_preflight','tool':'nikto','target':target,
                           'status':'missing_tool','detail':'nikto kurulu degil'})
        for ip in web_hosts[:16] if shutil.which('nikto') else []:
            ports=set(discovered_ports.get(ip,[]))
            port=443 if 443 in ports else 80
            ip_host=f'[{ip}]' if ':' in ip else ip
            args=['nikto','-host',ip_host,'-port',str(port),'-Tuning','123b',
                  '-Pause','0.2','-maxtime','60s','-timeout','5s',
                  '-nocheck','-nolookup','-nointeractive']
            if port==443: args.append('-ssl')
            if not is_ip(target): args.extend(['-vhost',target])
            result=command(f'nikto_{safe_filename(ip)}_{port}',args,raw,events,70)
            result['target']=ip
            result['detail']='Sinirli bilgi/yapilandirma adaylari; analist dogrulamasi gerekir'
        if len(web_hosts)>16:
            events.append({'step':'nikto_budget','tool':'nikto','target':target,
                           'status':'skipped','detail':f'{len(web_hosts)-16} web hostu 16-host is yukunde atlandi'})
    if profile == "full":
        matches=[(spec,secret) for spec,secret in credentials if spec["target"]==target]
        if matches and not is_ip(target):
            try: current=set(resolve(target))
            except socket.gaierror: current=set()
            if current != set(assets):
                events.append({"step":"auth_scope","target":target,"status":"blocked","detail":"DNS adresleri değişti; kimlik doğrulamalı istekler atlandı"})
                matches=[]
        for ip in assets:
            for spec,secret in matches:
                if spec['port'] in discovered_ports.get(ip,[]):
                    access_probe(target,ip,spec,secret,raw,events)
                else:
                    events.append({'step':'auth_preflight','target':ip,'status':'skipped',
                                   'detail':'Secilen kimlikli HTTPS portu acik dogrulanmadi'})
            if matches:
                for scenario in meta.get('role_scenarios',[]):
                    if scenario['target']==target and scenario['port'] in discovered_ports.get(ip,[]):
                        role_probe(root,scenario,ip,matches,events)
    templates=meta.get("nuclei_templates")
    # Use numeric destination addresses. Host header and SNI preserve virtual host
    # semantics without letting Nuclei resolve a new, out-of-scope address.
    if templates and profile in ("web","full"):
        selection=meta.get("nuclei_profile")
        for ip in assets:
            for scheme,port in (("https",443),("http",80)):
                if port not in discovered_ports.get(ip,[]):
                    continue
                name,argv=nuclei_args(target,ip,scheme,templates,selection,meta["max_rate"],raw)
                command(name,argv,raw,events,1200)
    if not is_ip(target) and profile in ("external","full"):
        command("whois",["whois",target],raw,events,25)
        command("nslookup",["nslookup",target],raw,events,15)
        command("dns_a",["dig","+time=3","+tries=1","+noall","+answer",target,"A"],raw,events,15)
        command("dns_aaaa",["dig","+time=3","+tries=1","+noall","+answer",target,"AAAA"],raw,events,15)
        command("dns_mx",["dig","+time=3","+tries=1","+noall","+answer",target,"MX"],raw,events,15)
        command("dns_caa",["dig","+time=3","+tries=1","+noall","+answer",target,"CAA"],raw,events,15)
        command("dns_txt",["dig","+time=3","+tries=1","+noall","+answer",target,"TXT"],raw,events,15)
        command("dns_dmarc",["dig","+time=3","+tries=1","+noall","+answer","_dmarc."+target,"TXT"],raw,events,15)


def show_windows_network(snapshot):
    if not isinstance(snapshot,dict) or not snapshot.get('adapters'):
        UI.say('  Windows adaptör envanteri alınamadı; hedefleri elle girin.','yellow')
        return
    UI.say('  Windows adaptörleri (alt ağlar yalnızca öneridir):','cyan')
    for item in snapshot['adapters']:
        addresses=[]
        for address in item.get('addresses',[]):
            try:
                net=ipaddress.ip_network(f"{address['address']}/{address['prefix']}",strict=False)
                if not address['address'].startswith(('127.','169.254.')):
                    addresses.append(str(net))
            except (ValueError,KeyError,TypeError):
                continue
        UI.say(f"    {item.get('name','?')} [{item.get('status','?')}] "
               f"{'VPN' if item.get('is_vpn') else ''} {', '.join(addresses) or 'uygun IP yok'}",'dim')


def collect_ad(snapshot):
    joined=bool(snapshot.get('part_of_domain')) if isinstance(snapshot,dict) else False
    if joined:
        UI.say(f"  Windows etki alanına bağlı: {snapshot.get('domain','?')}",'cyan')
    choice=UI.menu('AD / Domain kontrolü',
        [('0','Atla'),('1','Bağlı Windows etki alanını salt okunur incele'),
         ('2','Verilen DC ve test hesabıyla LDAPS incele')], '1' if joined else '0')
    if choice=='0': return {'mode':'disabled'},None
    if choice=='1':
        if not joined:
            raise SystemExit('Windows etki alanına bağlı değil; DC ve test hesabı seçin.')
        return {'mode':'joined','domain':snapshot.get('domain','')},None
    try:
        domain=parse_target(ask('Yetkili AD alan adı',required=True))
        dc=parse_target(ask('Yetkili domain controller FQDN/IP',required=True))
        if is_network(domain) or is_ip(domain) or is_network(dc):
            raise ValueError('AD alanı FQDN, DC ise tekil FQDN veya IP olmalı')
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    account=ask('AD test hesabı (UPN veya DOMAIN\\user)',required=True)
    if len(account)>160 or any(ord(c)<32 for c in account):
        raise SystemExit('AD test hesabı geçersiz')
    secret=private_value('AD test parolası (gizli)')
    return {'mode':'supplied','domain':domain,'dc':dc,'account':account},{'password':secret}


def collect_wireless():
    if UI.menu('İsteğe bağlı ham Wi-Fi testi',
               [('0','Atla'),('1','Yetkili AP ve test istemcisiyle etkinleştir')],'0')=='0':
        return {'enabled':False}
    usb=windows_invoke('usb_list',timeout=15)
    if usb.get('status')=='ok':
        for line in usb.get('lines',[])[:24]: UI.say('  '+str(line),'dim')
    else:
        UI.say('  USB geçişi: '+str(usb.get('reason','aygıt listesi alınamadı')),'yellow')
    spec={'enabled':True,'ssid':ask('Yetkili SSID',required=True),
          'bssid':ask('Yetkili AP BSSID',required=True),
          'channel':ask('Kanal',required=True),
          'interface':ask('Kali monitor arayüzü (örn. wlan0mon)',required=True),
          'busid':ask('WSL içine geçirilecek USB BusID (zaten Kali’deyse boş)'),
          'test_station':ask('Yetkili test istemcisi MAC',required=True),
          'test_station_ip':ask('Test istemcisi IP (aktif adım sağlık kontrolü)',required=True),
          'wordlist':ask('Yetkili çevrimdışı kelime listesi (isteğe bağlı)')}
    try:
        return {'enabled':True,**validate_wireless(spec)}
    except (ValueError,TypeError) as exc:
        raise SystemExit(str(exc)) from exc


def run_ad_module(root,meta,secret,events):
    config=meta.get('ad',{})
    mode=config.get('mode')
    if mode=='joined': result=windows_invoke('domain',timeout=30)
    elif mode=='supplied':
        dc=config['dc']
        try: current=[dc] if is_ip(dc) else resolve(dc)
        except socket.gaierror: current=[]
        frozen=meta.get('frozen_dns',{}).get(dc,current)
        approved=[ip for ip in current if not excluded(ip,meta['exclusions'])]
        if set(current)!=set(frozen) or not approved:
            result={'status':'blocked','reason':'AD DC DNS veya haric kapsam denetimi basarisiz'}
        else:
            raw=root/'targets'/'authorized_ad'/'raw'
            raw.mkdir(parents=True,exist_ok=True)
            allowed=route_guard(approved,meta.get('selected_interfaces',[]),raw,events,dc)
            result=(inspect_ad(dc,config['domain'],config['account'],secret['password'],approved[0])
                    if set(allowed)==set(approved) else
                    {'status':'blocked','reason':'AD DC secilen Windows rotasinda degil'})
    else:
        result={'status':'skipped','reason':'Etki alanı veya test hesabı seçilmedi'}
    dest=root/'AD_ASSESSMENT.json'
    atomic_json(dest,result)
    events.append({'step':'ad_assessment','status':result.get('status','error'),
                   'detail':result.get('reason',result.get('source','')),
                   'output':dest.name,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})


def record_exploit_gate(root,events):
    candidates=0
    for path in (root/'targets').glob('*/raw/nuclei_*.jsonl'):
        try:
            with path.open(encoding='utf-8',errors='replace') as handle:
                for line in handle:
                    if 'CVE-' in line.upper():
                        candidates+=1
                    if candidates>=1000: break
        except OSError:
            continue
    events.append({'step':'metasploit_proof_gate','tool':'msfconsole','status':'skipped',
                   'detail':('Aday bulunmadi; istismar dogrulamasi baslatilmadi' if not candidates else
                             f'{candidates} CVE aday satiri var; onayli CVE-modul eslesmesi yok, istismar baslatilmadi')})


def run_browser_module(root,meta,credentials,events):
    if not meta.get('browser_enabled'):
        events.append({'step':'browser','status':'skipped',
                       'detail':'Operatör Windows test tarayıcısı modülünü seçmedi'})
        return
    for target in meta['targets']:
        if is_network(target):
            events.append({'step':'browser_'+safe_filename(target),'target':target,
                           'status':'skipped',
                           'detail':'Tarayici icin CIDR yerine tekil yetkili FQDN/IP gerekli'})
            continue
        raw=root/'targets'/safe_filename(target)/'raw'
        if is_ip(target): ips=[target]
        else:
            try: ips=json.loads((raw/'dns_resolution.json').read_text(encoding='utf-8')).get('addresses',[])
            except (OSError,ValueError): ips=[]
        if not ips:
            events.append({'step':'browser_'+safe_filename(target),'target':target,
                           'status':'skipped','detail':'Hedef IP çözümlemesi yok'})
            continue
        if not is_ip(target):
            try: current=set(resolve(target))
            except socket.gaierror: current=set()
            if current != set(ips):
                events.append({'step':'browser_'+safe_filename(target),'target':target,
                               'status':'blocked','detail':'DNS adresleri degisti; tarayici atlandi'})
                continue
        if meta.get('selected_interfaces'):
            try:
                route_data=json.loads((raw/'route_snapshot.json').read_text(encoding='utf-8'))
                allowed=set(route_data.get('allowed',[]))
            except (OSError,ValueError,TypeError):
                allowed=set()
            ips=[ip for ip in ips if ip in allowed]
            if not ips:
                events.append({'step':'browser_'+safe_filename(target),'target':target,
                               'status':'blocked','detail':'Tarayici icin secilen adaptorde izinli IP yok'})
                continue
        selected=None
        for candidate in ips:
            if excluded(candidate,meta['exclusions']):
                continue
            xml=raw/('nmap_'+safe_filename(candidate)+'.xml')
            if not xml.is_file(): xml=raw/'nmap_cidr.xml'
            candidate_ports=open_tcp_ports(xml)
            if 443 in candidate_ports or 80 in candidate_ports:
                selected=(candidate,candidate_ports)
                break
        if selected is None:
            events.append({'step':'browser_'+safe_filename(target),'target':target,
                           'status':'skipped','detail':'Izinli IP uzerinde acik HTTP(S) portu dogrulanmadi'})
            continue
        ip,open_ports=selected
        port=443 if 443 in open_ports else 80
        scheme='https' if port==443 else 'http'
        url_host=f'[{target}]' if ':' in target else target
        url=f'{scheme}://{url_host}/'
        scenarios=[(target,'/',url,None)]
        for spec,secret in credentials:
            if spec['target']==target and spec['port'] in open_ports:
                auth_url=f'https://{url_host}:{spec["port"]}{spec["path"]}'
                scenarios.append((target+'_'+spec['role'],spec['path'],auth_url,secret))
        for label,path,scenario_url,secret in scenarios:
            screenshot=screenshot_path(root,label)
            request={'url':scenario_url,'host':target,'ip':ip,
                     'path':path,'screenshot':screenshot}
            if secret: request['auth']=secret
            result=windows_invoke('browser',request,timeout=75)
            image=root/f'browser_{safe_filename(label)}.png'
            event={'step':'browser_'+safe_filename(label),'target':target,
                   'status':result.get('status','error'),
                   'detail':result.get('reason',f"HTTP {result.get('http_status','?')}; "
                            f"istek {result.get('requests',0)}; engellenen {result.get('blocked_requests',0)}")}
            if image.is_file():
                event.update(output=image.name,sha256=hashlib.sha256(image.read_bytes()).hexdigest())
            events.append(event)

def collect_meta(args):
    UI.banner(VERSION)
    UI.section(1,5,"Görev bilgileri","Müşteri, proje ve yazılı yetki referansı")
    client=ask("Müşteri unvanı",required=True)
    project=ask("Proje", "Dış yüzey güvenlik değerlendirmesi")
    auth=ask("Yazılı yetki/sözleşme referansı",required=True)
    tester=ask("Tester / test ekibi adı", required=True)
    UI.section(2,5,"Kapsam","Hedefleri ve hariç tutulan adresleri açıkça tanımlayın")
    host_snapshot=windows_invoke('inventory',timeout=20)
    show_windows_network(host_snapshot)
    if os.environ.get('UBDEN_WINDOWS_BRIDGE') and host_snapshot.get('status')!='ok':
        raise SystemExit('Windows adaptör köprüsü doğrulanamadı; WSL operasyonu başlatılmadı')
    selectable={int(item['index']) for item in host_snapshot.get('adapters',[])
                if item.get('status')=='Up' and item.get('addresses') and
                isinstance(item.get('index'),int)} if host_snapshot.get('status')=='ok' else set()
    selected_interfaces=[]
    if os.environ.get('UBDEN_WINDOWS_BRIDGE') and not selectable:
        raise SystemExit('Kullanılabilir Windows ağ adaptörü yok; WSL operasyonu başlatılmadı')
    if selectable:
        selected_text=ask('Test trafigi icin Windows adaptör indeksleri (virgülle)',required=True)
        try:
            selected_interfaces=sorted({int(x.strip()) for x in selected_text.split(',')})
        except ValueError as exc:
            raise SystemExit('Adaptör indeksleri sayı olmalı') from exc
        if not selected_interfaces or set(selected_interfaces)-selectable:
            raise SystemExit('Yalnız etkin ve adresli Windows adaptörleri seçilebilir')
    raw_targets=ask("Açıkça yetkilendirilmiş FQDN/IP/CIDR (virgülle)",required=True)
    raw_exclusions=ask("Hariç tutulan FQDN/IP/CIDR (virgülle)")
    try:
        targets=list(dict.fromkeys(parse_target(x) for x in raw_targets.split(",") if x.strip()))
        exclusions=list(dict.fromkeys(parse_target(x) for x in raw_exclusions.split(",") if x.strip()))
    except ValueError as exc:
        raise SystemExit(str(exc))
    if not targets or len(targets)>30:
        raise SystemExit("1-30 açık hedef giriniz.")
    for t in targets:
        if is_network(t):
            net=ipaddress.ip_network(t)
            if (net.version == 4 and net.prefixlen<24) or (net.version==6 and net.prefixlen<120):
                raise SystemExit("Tek görevde en fazla /24 IPv4 veya /120 IPv6 izinlidir.")
    try:
        validate_task_address_budget(targets)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    UI.section(3,5,"Test profili","Üretim ortamı için kontrollü hız ve süre limitleri")
    profile_choice=UI.menu("Tarama kapsamı",[("1","External: dış yüzey, DNS/WHOIS, servis, HTTP/TLS"),("2","Web: web portları, başlıklar, yöntemler ve TLS"),("3","Network: servisler + seçilmiş NSE güvenlik kontrolleri"),("4","Full: tüm otomatik modüller + isteğe bağlı kimlikli erişim kontrolü")],"4")
    profile={"1":"external","2":"web","3":"network","4":"full"}[profile_choice]
    if args.nuclei_templates and profile not in ("web","full"):
        raise SystemExit("Nuclei şablonları yalnızca Web veya Full profiliyle kullanılabilir.")
    template_dir=""
    nuclei_profile="disabled"
    if profile in ("web","full"):
        selected="0" if args.no_nuclei else str(args.nuclei_templates or ask("Nuclei şablonu: Enter=UBDEN varsayılan, 0=atla, /dizin=özel")).strip()
        if selected != "0":
            nuclei_profile="custom" if selected else "baseline"
            template_dir=selected or str(BASELINE)
            candidate=Path(template_dir).expanduser().resolve()
            if not candidate.is_dir() or not any(p.is_file() and p.suffix.lower() in ('.yaml','.yml') for p in candidate.rglob('*')):
                raise SystemExit("Nuclei şablon dizini bulunamadı veya YAML içermiyor.")
            try:
                template_inventory(candidate)
            except ValueError as exc:
                raise SystemExit(f'Nuclei şablonları kapsam sınırına uymuyor: {exc}') from exc
            template_dir=str(candidate)
    auth_specs, auth_secrets=collect_credentials(targets,exclusions) if profile=="full" else ([],[])
    credentials=list(zip(auth_specs,auth_secrets))
    role_scenarios=collect_role_scenarios(credentials) if profile=='full' else []
    ssh_specs,ssh_tests=collect_ssh_passwords(targets,exclusions) if profile in ('network','full') else ([],[])
    ad_spec,ad_secret=collect_ad(host_snapshot)
    browser_enabled=(profile in ('web','full') and UI.menu('Ayrı Windows test tarayıcısı',
        [('0','Atla'),('1','Kapsam içi web hedeflerinin kökünü aç ve ekran görüntüsü al')],'1')=='1')
    wireless_spec=collect_wireless()
    ai_config=configure_ai()
    top_ports=4 if profile=='web' else min(max(args.top_ports if args.top_ports is not None else (100 if profile=='external' else 1000),1),1000)
    enabled_modules=['core_scan']
    if profile in ('network','full'): enabled_modules.append('supplemental_network')
    if ad_spec.get('mode')!='disabled': enabled_modules.append('ad')
    if browser_enabled: enabled_modules.append('browser')
    if wireless_spec.get('enabled'): enabled_modules.append('wireless')
    if ssh_specs: enabled_modules.append('ssh_test_account')
    meta={"schema":8,"id":str(uuid.uuid4()),"client":client,"project":project,"authorization_reference":auth,"product":"UBDEN Cyber Security Systems","product_owner":"UBDEN®","tester":tester,"targets":targets,"exclusions":exclusions,"selected_interfaces":selected_interfaces,"profile":profile,"enabled_modules":enabled_modules,"allowed_techniques":enabled_modules,"auth_probes":auth_specs,"role_scenarios":role_scenarios,"password_probes":ssh_specs,"ad":ad_spec,"browser_enabled":browser_enabled,"wireless":wireless_spec,"host_snapshot":host_snapshot,"limits":{"max_online_failures_per_test_account_service":2,"max_exploit_attempts_per_finding_host":1,"wireless_capture_seconds":600,"wireless_offline_seconds":1800,"wireless_deauth_events":3,"wireless_wps_attempts":10},"ai_enabled":bool(ai_config),"ai_raw_evidence":bool(ai_config and ai_config['raw']),"nuclei_templates":template_dir,"nuclei_profile":nuclei_profile,"nuclei_template_count":len(template_inventory(template_dir)) if template_dir else 0,"max_rate":min(max(args.max_rate,1),500),"top_ports":top_ports,"started_at":now(),"status":"planned","tool_version":VERSION}
    UI.section(4,5,"Ön izleme ve onay","Gerçek trafik başlamadan önce kapsamı kontrol edin")
    UI.preview([("Müşteri",client),("Yetki",auth),("Ürün","UBDEN Cyber Security Systems"),("Test ekibi",tester),("Hedefler",", ".join(targets)),("Hariç",", ".join(exclusions) or "Yok"),("Windows adaptörleri",", ".join(map(str,selected_interfaces)) or "Köprü yok"),("Modüller",", ".join(enabled_modules)),("SSH test hesapları",str(len(ssh_specs))),("Profil",profile),("Kimlikli kontrol",", ".join(f"{x['target']} / {x['role']} ({x['method']})" for x in auth_specs) or "Atlanacak"),("Rol/IDOR",str(len(role_scenarios))+" salt okunur senaryo"),("AD",ad_spec.get('mode','disabled')),("Windows tarayıcı",'Açık' if browser_enabled else 'Kapalı'),("Ham Wi-Fi",'Açık' if wireless_spec['enabled'] else 'Kapalı'),("Claude",'Sınırlı ham kanıt' if ai_config and ai_config['raw'] else 'Anonim özet' if ai_config else 'Kapalı'),("Nuclei",f"{nuclei_profile} / {meta['nuclei_template_count']} şablon" if template_dir else "Atlanacak"),("Hız/port",f"{meta['max_rate']} paket/sn, {meta['top_ports']} TCP portu")])
    required=["nmap"]
    if profile != "network": required += ["curl","sslscan"]
    if profile in ("external","full"): required += ["dig","whois"]
    if template_dir and not shutil.which("nuclei"):
        UI.say("  Nuclei kurulu değil; diğer adımlar çalışır, Nuclei adımı eksik olarak raporlanır.","yellow")
    missing=[tool for tool in required if not shutil.which(tool)]
    if missing:
        raise SystemExit("Eksik araç: " + ", ".join(missing) + ". Kurulumu tamamlayın.")
    if UI.prompt("Yazılı izin ve kapsamı kontrol ettim. Başlatmak için YETKILIYIM yazın") != "YETKILIYIM":
        raise SystemExit("Başlatılmadı.")
    return meta,credentials,ai_config,ad_secret,ssh_tests

def run(args):
    meta,credentials,ai_config,ad_secret,ssh_tests=collect_meta(args)
    freeze_scope(meta)
    os.umask(0o077)
    base,owner=choose_run_base(args.runs)
    root=base / f"{safe_filename(meta['client'])}_{dt.datetime.now(dt.timezone.utc):%Y%m%d_%H%M%S}_{meta['id'][:8]}"
    root.mkdir(parents=True, exist_ok=False)
    os.chmod(root,0o700)
    register_run(root)
    atomic_json(root/"engagement.json",meta)
    atomic_json(root/"HOST_CAPABILITIES.json",meta.get('host_snapshot',{}))
    if meta.get("nuclei_templates"):
        atomic_json(root/"nuclei_template_manifest.json",{"profile":meta["nuclei_profile"],"templates":template_inventory(meta["nuclei_templates"])})
    atomic_json(root/"TOOL_ENVIRONMENT.json",tool_inventory())
    (root/"MANUEL_TEST_PLANI.md").write_text(MANUAL_PLAN,encoding="utf-8")
    events=[]
    try:
        for index,target in enumerate(meta["targets"],1):
            if excluded(target,meta["exclusions"]):
                events.append({"step":"scope","target":target,"status":"excluded"})
                continue
            scan_target(target,meta,root,events,credentials,index,len(meta["targets"]),ssh_tests)
            UI.target_done(index,len(meta['targets']))
        record_exploit_gate(root,events)
        run_ad_module(root,meta,ad_secret,events)
        for item in ssh_tests:
            if not item['used']:
                events.append({'step':'ssh_password_preflight','tool':'paramiko',
                               'target':item['target_ip'],'status':'skipped',
                               'detail':'Kapsam icinde acik SSH portu dogrulanmadi'})
        run_browser_module(root,meta,credentials,events)
        if meta.get('wireless',{}).get('enabled'):
            wireless_raw=root/'targets'/'authorized_wireless'/'raw'
            busid=meta['wireless'].get('busid')
            if busid:
                attached=windows_invoke('usb_attach',{'busid':busid},timeout=45)
                events.append({'step':'wireless_usb_attach','status':attached.get('status','error'),
                               'detail':attached.get('reason',attached.get('detail',''))})
            if not busid or attached.get('status')=='ok':
                run_wireless(meta['wireless'],wireless_raw,events,command)
        else:
            events.append({'step':'wireless','status':'skipped',
                           'detail':'Ham Wi-Fi modülü görevde seçilmedi'})
    except KeyboardInterrupt:
        meta["status"]="interrupted"
        UI.say("\n  Durduruldu; eldeki çıktılardan rapor oluşturuluyor.","yellow")
    except Exception as exc:
        meta["status"]="completed_with_errors"
        events.append({"step":"operation_error","status":"error",
                       "detail":f"Modul hatasi: {type(exc).__name__}; kalan adimlar durduruldu"})
        UI.say(f"  Operasyon hatasi: {type(exc).__name__}; eldeki kanitlardan rapor oluşturuluyor.","yellow")
    else:
        scanned=any((str(e.get('step','')).startswith('nmap_') or e.get('step')=='port_discovery')
                    and e.get('status')=='ok' for e in events)
        meta["status"]=("no_data" if not scanned
                        else "completed_with_errors" if any(e.get("status") in ("error","timeout","missing_tool","blocked","no_hosts","partial") for e in events)
                        else "completed")
    finally:
        meta["finished_at"]=now()
        try:
            summary=build_inventory(root,meta)
            events.append({'step':'device_inventory','status':'ok','detail':f"{summary['host_count']} cihaz; {summary['mac_count']} MAC; {summary['unknown_count']} sınıflandırılmamış",'output':'DEVICE_INVENTORY.json'})
            UI.say(f"  Cihaz envanteri: {summary['host_count']} adres, {summary['mac_count']} MAC, {summary['unknown_count']} belirsiz.",'cyan')
        except Exception as exc:
            events.append({'step':'device_inventory','status':'error','detail':f'{type(exc).__name__}: {exc}'})
            UI.say(f'  Cihaz envanteri oluşturulamadı: {type(exc).__name__}: {exc}','yellow')
        atomic_json(root/"steps.json",events)
        atomic_json(root/"TOOL_ENVIRONMENT.json",catalog_inventory(events))
        atomic_json(root/"engagement.json",meta)
        try:
            result=subprocess.run([sys.executable,str(ROOT/"report_v2.py"),str(root)],check=False)
            if ai_config:
                def replay(scenario):
                    target=scenario['target']
                    raw=root/'targets'/safe_filename(target)/'raw'
                    if is_ip(target):
                        ips=[target]
                    else:
                        recorded=json.loads((raw/'dns_resolution.json').read_text())['addresses']
                        if set(resolve(target))!=set(recorded):
                            raise ValueError('DNS kapsamı değişti; AI ek kontrolü engellendi')
                        ips=recorded
                    for ip in ips[:1]:
                        matching=[pair for pair in credentials if pair[0]['target']==target]
                        role_probe(root,scenario,ip,matching,events,attempt=2)
                outcome=analyze_run(root,meta,events,ai_config,replay)
                UI.say(f"  Claude AI analist: {outcome['status']}; ek kontrol: {len(outcome['checks_executed'])}",
                       'green' if outcome['status']=='completed' else 'yellow')
                atomic_json(root/'steps.json',events)
                result=subprocess.run([sys.executable,str(ROOT/"report_v2.py"),str(root)],check=False)
        finally:
            handoff_run(root,owner)
        if result.returncode:
            UI.say("  Rapor üretimi başarısız. steps.json ve terminal çıktısını inceleyin.","red")
            UI.done(root,'report_error')
            raise SystemExit(result.returncode)
    UI.done(root,meta["status"])

def main():
    parser=argparse.ArgumentParser(description="UBDEN Cyber Security Systems | yetkili güvenlik değerlendirmesi")
    parser.add_argument("--runs",default=None,help="Rapor ana klasörü (varsayılan: Kali masaüstü, yoksa /opt/ubden-cyber/runs)")
    parser.add_argument("--max-rate",type=int,default=250,help="Toplu Nmap paket/saniye tavanı (varsayılan 250; aralık 1-500)")
    parser.add_argument("--top-ports",type=int,default=None,help="External varsayılan 100; Network/Full varsayılan 1000")
    parser.add_argument("--nuclei-templates",type=Path,help="Önceden incelenmiş Nuclei şablon dizini (Web/Full)")
    parser.add_argument("--no-nuclei",action="store_true",help="Web/Full profilinde Nuclei adımını atla")
    parser.add_argument("--report-only",type=Path)
    parser.add_argument("--analyst-review",type=Path,help="Görev klasöründe insan denetimli test ve kanıt kayıt sihirbazı")
    parser.add_argument("--ai-review",type=Path,help="Mevcut görevi Claude ile yeniden değerlendir (yeni ağ testi yapmaz)")
    parser.add_argument("--no-color",action="store_true",help="ANSI renkleri kapat")
    parser.add_argument("--no-animation",action="store_true",help="Canlı durum animasyonunu kapat")
    parser.add_argument("--preview-ui",action="store_true",help="Ağ isteği yapmadan arayüz örneği göster")
    parser.add_argument("--version",action="version",version=f"UBDEN Cyber Security Systems {VERSION}")
    args=parser.parse_args()
    if args.no_nuclei and args.nuclei_templates:
        parser.error("--no-nuclei ile --nuclei-templates birlikte kullanılamaz")
    if sum(bool(x) for x in (args.report_only,args.analyst_review,args.ai_review))>1:
        parser.error("Rapor, analist ve AI inceleme seçenekleri ayrı kullanılmalıdır")
    UI.__init__(args.no_color,args.no_animation)
    if args.preview_ui:
        UI.banner(VERSION)
        UI.say("  === SADECE ARAYÜZ ÖN İZLEMESİ / TEST BAŞLATILMAZ ===", "yellow")
        UI.section(1,5,"Görev bilgileri")
        UI.section(2,5,"Kapsam")
        UI.section(3,5,"Test profili")
        UI.section(4,5,"Ön izleme ve onay")
        UI.preview([("Ürün","UBDEN Cyber Security Systems"),("Tester","Gerçek sihirbazda siz gireceksiniz")])
        UI.say("\n  Ön izleme tamamlandı. Gerçek sihirbaz için: ubden-cyber", "dim")
        return
    if args.ai_review:
        root=args.ai_review.expanduser().resolve()
        if not (root/'engagement.json').is_file():
            parser.error("Görev klasörü bulunamadı")
        meta=json.loads((root/'engagement.json').read_text(encoding='utf-8'))
        events=json.loads((root/'steps.json').read_text(encoding='utf-8'))
        config=configure_ai()
        if config:
            outcome=analyze_run(root,meta,events,config)
            subprocess.run([sys.executable,str(ROOT/'report_v2.py'),str(root)],check=True)
            print('Claude incelemesi:',outcome['status'],'(ek ağ testi yapılmadı)')
    elif args.analyst_review:
        review_root=args.analyst_review.expanduser().resolve()
        if not review_root.is_dir():
            parser.error("Görev klasörü bulunamadı")
        guided(review_root)
        subprocess.run([sys.executable,str(ROOT/"report_v2.py"),str(review_root)],check=True)
    elif args.report_only:
        report_root=args.report_only.expanduser().resolve()
        folder_stat=report_root.stat()
        try:
            subprocess.run([sys.executable,str(ROOT/"report_v2.py"),str(report_root)],check=True)
        finally:
            if os.geteuid()==0 and folder_stat.st_uid>=1000:
                handoff_run(report_root,(folder_stat.st_uid,folder_stat.st_gid))
    else:
        run(args)

if __name__ == "__main__":
    main()
