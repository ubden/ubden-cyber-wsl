#!/usr/bin/env python3
"""Generate Turkish executive and technical reports from recorded evidence."""
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote
from xml.etree import ElementTree as ET

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image, HRFlowable
from reportlab.platypus.tableofcontents import TableOfContents
from analyst_review import assess, verified_finding
from assessment_coverage import build_coverage, write_coverage
from report_insights import write as write_insights
from analyst_workplan import write_plan
from device_inventory import build_inventory, CATEGORY_ORDER, CATEGORY_ICONS
import report_visuals as V
import correlation as CORR
import eol_data
import case_coverage as CASE_COV

BASE = Path(__file__).resolve().parent
NAVY = colors.HexColor('#101b32')
TEAL = colors.HexColor('#00b9bd')
TEXT = colors.HexColor('#263249')
PALE = colors.HexColor('#edf7f8')
GRAY = colors.HexColor('#65758b')
SEVERITIES = {'critical':'Kritik','high':'Yüksek','medium':'Orta','low':'Düşük','info':'Bilgi'}
SEVERITY_COLORS = {'critical':'#9d174d','high':'#d84734','medium':'#e49722','low':'#337ec6','info':'#73859c'}
# 'DV'/'DVB' anahtarlarına Türkçe destekli font kaydeder: assets DejaVu bulunursa
# onu, yoksa sistem fontuna (Segoe UI/Arial/Liberation) düşerek — glif doğrulamalı.
V.register_fonts()

# Bulgu tipi/başlık/kategorisinden CWE zayıflık sınıfı çıkarımı (analist ayrıca
# override edebilir). Eşleşme yalnız sınıflandırma içindir; istismar kanıtı değildir.
CWE_RULES = (
    ('kerberoast', 'CWE-522 · Yetersiz korunan kimlik bilgileri'),
    ('asrep', 'CWE-522 · Yetersiz korunan kimlik bilgileri'),
    ('cracked', 'CWE-521 · Zayıf parola gereksinimleri'),
    ('zayıf parola', 'CWE-521 · Zayıf parola gereksinimleri'),
    ('varsayılan/zayıf kimlik', 'CWE-1392 · Varsayılan kimlik bilgisi kullanımı'),
    ('varsayılan kimlik', 'CWE-1392 · Varsayılan kimlik bilgisi kullanımı'),
    ('adcs', 'CWE-295 · Hatalı sertifika doğrulaması'),
    ('telnet', 'CWE-319 · Hassas bilginin şifresiz iletimi'),
    ('ftp servisi', 'CWE-319 · Hassas bilginin şifresiz iletimi'),
    ('hsts', 'CWE-319 · Hassas bilginin şifresiz iletimi'),
    ('x-content-type-options', 'CWE-693 · Koruma mekanizması eksikliği'),
    ('http uç', 'CWE-319 · Hassas bilginin şifresiz iletimi'),
    ('trace', 'CWE-16 · Güvensiz yapılandırma'),
    ('sslv3', 'CWE-327 · Zayıf/eski kriptografik algoritma'),
    ('tlsv1', 'CWE-327 · Zayıf/eski kriptografik algoritma'),
    ('protokolü kabul', 'CWE-327 · Zayıf/eski kriptografik algoritma'),
    ('public toplulu', 'CWE-1188 · Güvensiz varsayılan yapılandırma'),
    ('snmpv1', 'CWE-319 · Hassas bilginin şifresiz iletimi'),
    ('smb servisi', 'CWE-284 · Hatalı erişim denetimi'),
    ('rdp servisi', 'CWE-284 · Hatalı erişim denetimi'),
    ('veritabanı servisi', 'CWE-284 · Hatalı erişim denetimi'),
    ('tls', 'CWE-295 · Hatalı sertifika doğrulaması'),
)

def infer_cwe(finding):
    """Bulgu metninden CWE sınıfı önerir; eşleşme yoksa boş döner."""
    haystack=' '.join(str(finding.get(k,'')) for k in ('type','title','category')).lower()
    for keyword,label in CWE_RULES:
        if keyword in haystack:
            return label
    return ''

def safe(value):
    return html.escape(str(value or ''), quote=True)

def device_inventory(root):
    path=root/'DEVICE_INVENTORY.json'
    try:
        data=json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data,dict) and isinstance(data.get('devices'),list) else {}
    except (OSError,ValueError):
        return {}

def network_rows(meta):
    snapshot=meta.get('host_snapshot',{})
    if not isinstance(snapshot,dict):
        return []
    selected=set(meta.get('selected_interfaces',[]))
    rows=[]
    for item in snapshot.get('adapters',[]):
        if not isinstance(item,dict):
            continue
        addresses=', '.join(f"{address.get('address','')}/{address.get('prefix','')}"
                            for address in item.get('addresses',[]) if isinstance(address,dict))
        routes=[str(route.get('gateway','')) for route in snapshot.get('default_routes',[])
                if isinstance(route,dict) and route.get('interface_index')==item.get('index')]
        rows.append({'name':str(item.get('name','')),'status':str(item.get('status','')),
                     'selected':item.get('index') in selected,'addresses':addresses,
                     'gateway':', '.join(routes),'dns':', '.join(map(str,item.get('dns',[]))),
                     'vpn':bool(item.get('is_vpn'))})
    return rows

def finding_evidence(finding):
    items=[]
    if finding.get('evidence'):
        items.append({'path':str(finding['evidence']), 'caption':'Birincil kanıt',
                      'sha256':str(finding.get('evidence_sha256',''))})
    for item in finding.get('evidence_items',[]):
        if isinstance(item,dict) and item.get('path'):
            items.append({'path':str(item['path']), 'caption':str(item.get('caption') or 'Ek kanıt'),
                          'sha256':str(item.get('sha256',''))})
    return items

def severity_chart(counts, width):
    drawing=Drawing(width, 69*mm)
    maximum=max(max(counts.values(),default=0),1)
    for index,key in enumerate(SEVERITIES):
        y=(4-index)*12.5*mm+3*mm
        drawing.add(String(0,y,SEVERITIES[key],fontName='DV',fontSize=8,fillColor=TEXT))
        drawing.add(Rect(27*mm,y-2*mm,(width-46*mm)*counts[key]/maximum,6.5*mm,
                         fillColor=colors.HexColor(SEVERITY_COLORS[key]),strokeColor=None))
        drawing.add(String(width-14*mm,y,str(counts[key]),fontName='DVB',fontSize=9,fillColor=NAVY))
    return drawing

def evidence_link(root, value):
    """Link only existing files inside the run; never trust a recorded path as a URL."""
    value=str(value or '').strip()
    if not value:
        return ''
    links=[]
    for part in value.split('; '):
        part=part.strip()
        relative=Path(part)
        if (not part or relative.is_absolute() or '..' in relative.parts
                or any(piece.is_symlink() for piece in (root/relative, *(root/relative).parents) if piece != root)):
            links.append(safe(part))
            continue
        candidate=root/relative
        if candidate.is_file() and candidate.resolve().is_relative_to(root.resolve()):
            href=quote(relative.as_posix(),safe='/')
            links.append(f'<a href="{safe(href)}">{safe(part)}</a>')
        else:
            links.append(safe(part))
    return '; '.join(links)

def logo():
    png = BASE/'assets'/'ubden-logo.png'
    return png if png.exists() else None

def auth_summary(meta, steps):
    selected=meta.get('auth_probes') or []
    checked=[s for s in steps if str(s.get('step','')).startswith('auth_') and s.get('step') != 'auth_scope']
    ok=sum(s.get('status')=='ok' for s in checked)
    if not selected:
        return 'Kimlik doğrulamalı erişim kontrolü seçilmedi; uygulama içi erişim değerlendirilmedi.'
    return (f'Kimlikli HTTPS HEAD erişim kontrolü: {len(selected)} rol/hedef tanımlandı; '
            f'{len(checked)} deneme, {ok} anonim erişimi reddedip test oturumunu kabul eden yanıt. '
            'Yalnızca anonim ve test oturumlu HTTP durum kodları karşılaştırıldı. '
            'Giriş bilgileri kaydedilmedi; yetki açığı ve uygulama iş mantığı doğrulanmadı.')

def advanced_summary(root,meta,steps):
    scenarios=meta.get('role_scenarios',[])
    trials=[s for s in steps if str(s.get('step','')).startswith('role_')]
    flagged=sum(s.get('status')=='review' for s in trials)
    role_text=(f"Tanımlanan rol/IDOR GET senaryosu: {len(scenarios)}; çalışan deneme: {len(trials)}; "
               f"manuel inceleme gerektiren yanıt: {flagged}. HTTP durumları tek başına açık doğrulamaz. "
               "Durum değiştiren iş mantığı akışları analist çalışması gerektirir.")
    path=root/'AI_DURUM.json'
    if not path.is_file():
        return role_text,'Claude AI kullanılmadı.',''
    try:
        ai=json.loads(path.read_text(encoding='utf-8'))
        stale=(root/'review.json').exists() and (root/'review.json').stat().st_mtime>path.stat().st_mtime
        note=f"Claude AI: {ai.get('status','bilinmiyor')}; çağrı: {ai.get('calls',0)}; ek kontrol: {len(ai.get('checks_executed',[]))}; ham kanıt aktarımı: {'evet' if ai.get('raw_evidence') else 'hayır'}."
        if stale: note+=' Analist kayıtları AI incelemesinden sonra değişti; yeniden değerlendirme gerekir.'
        return role_text,note,str(ai.get('commentary') or ai.get('proposal') or '')[:1200]
    except (OSError,ValueError,TypeError):
        return role_text,'Claude durum kaydı okunamadı; AI incelemesi tamamlanmış sayılmaz.',''

def discovery_summaries(root):
    summaries=[]
    for path in sorted((root/'targets').glob('*/raw/discovery_summary.json')) if (root/'targets').exists() else []:
        try:
            entry=json.loads(path.read_text(encoding='utf-8'))
            entry['evidence']=str(path.relative_to(root))
            summaries.append(entry)
        except (ValueError,OSError,TypeError):
            summaries.append({'target':path.parent.parent.name,'status':'error','evidence':str(path.relative_to(root))})
    return summaries

def snmp_summaries(root):
    result=[]
    for path in sorted((root/'targets').glob('*/raw/snmp_v1_public_summary.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
            if isinstance(item,dict) and item.get('status')=='completed':
                item['evidence']=str(path.relative_to(root))
                result.append(item)
        except (OSError,ValueError,TypeError):
            continue
    return result

def discovery_line(summary):
    count=summary.get('unresponsive_count')
    status_label={'partial':'kısmi','ok':'tamamlandı','no_hosts':'yanıt alınamadı',
                  'error':'hata'}.get(summary.get('status'),summary.get('status','?'))
    method=(' ICMP ping yoklaması da uygulandı.' if summary.get('fallback_used') else '')
    coverage=(' Nmap tamamlanmadı; yalnızca yanıtı doğrulanan IP adresleri servis taraması kapsamına alındı.'
              if summary.get('status')=='partial' else '')
    anomaly=(f" Tüm adresler yanıtlı görünüyor (Nmap {summary.get('nmap_responding_count','?')}, "
             f"ping {summary.get('icmp_responding_count','?')}); vekil ARP/sanal ağ olasılığı doğrulanmalı."
             if summary.get('all_addresses_responded') else '')
    local=(" Windows adaptöründe kayıtlı olup Kali üzerinden doğrulanamayan adresler: " +
           ', '.join(summary.get('windows_local_unreachable',[])) + '. Bu adreslerde servis testi yapılmış sayılmaz.'
           if summary.get('windows_local_unreachable') else '')
    return (f"{summary.get('target','?')}: durum {status_label}; "
            f"uygun {summary.get('eligible_count','?')}; yanıt veren {summary.get('responding_count','?')}; "
            f"yanıt vermeyen {count if count is not None else 'bilinmiyor'}. "
            'Yanıt vermemesi sistemin kapalı olduğunu kanıtlamaz.'+method+coverage+anomaly+local)

def tool_rows(root, steps):
    path=root/'TOOL_ENVIRONMENT.json'
    if not path.exists():
        return []
    data=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(data.get('tools'),list):
        ran={str(step.get('tool','')).lower() for step in steps if step.get('status') in
             ('ok','warning','partial','no_response','error','timeout','interrupted','auth_failed')}
        rows=[]
        for item in data['tools']:
            name=str(item.get('name',''))
            executable=str(item.get('executable',''))
            executed=bool(item.get('executed') or executable.lower() in ran)
            rows.append((name,'Kurulu' if item.get('installed') else 'Eksik',
                         'Çalıştırıldı' if executed else 'Çalıştırılmadı',
                         str(item.get('category',''))+' / '+str(item.get('mode',''))+
                         ' — '+str(item.get('reason','')),
                         ''))
        return sorted(rows,key=lambda row:(row[2]!='Çalıştırıldı',row[0].lower()))
    used={'nmap':('discovery_hosts','port_discovery','nmap_','audit_'),'curl':('headers_','methods_','auth_'),'sslscan':('tls_',),
          'dig':('dns_',),'whois':('whois',),'nuclei':('nuclei_',),'snmpget':('snmp_v1_public',)}
    used['nslookup']=('nslookup',)
    info={'nmap':('Ağ keşfi','https://nmap.org/'),'curl':('Web / HTTP','https://curl.se/'),
          'sslscan':('TLS analizi','https://github.com/rbsec/sslscan'),
          'dig':('DNS keşfi','https://www.isc.org/bind/'),'nslookup':('DNS keşfi','https://www.isc.org/bind/'),
          'whois':('Alan adı keşfi','https://www.iana.org/whois'),
          'nuclei':('Şablon kontrolü','https://github.com/projectdiscovery/nuclei'),
          'snmpget':('SNMP kontrolü','https://www.net-snmp.org/'),
          'wafw00f':('Web keşfi','https://github.com/EnableSecurity/wafw00f'),
          'tcpdump':('Paket analizi','https://www.tcpdump.org/'),
          'fping':('Host keşfi','https://fping.org/'),
          'wireshark':('Paket analizi','https://www.wireshark.org/')}
    rows=[]
    for group in ('automatic_candidates','manual_only'):
        for name,available in data.get(group,{}).items():
            executed=any(any(str(s.get('step','')).startswith(prefix) for prefix in used.get(name,())) and
                         s.get('status') in ('ok','warning','partial','no_response','error','timeout','interrupted','auth_failed')
                         for s in steps)
            category,url=info.get(name,('Uzman aracı',''))
            rows.append((name,'Kurulu' if available else 'Eksik', 'Çalıştırıldı' if executed else 'Çalıştırılmadı',category,url))
    return sorted(rows,key=lambda item:(item[2]!='Çalıştırıldı',item[0]))


def platform_lines(root, meta, steps):
    if int(meta.get('schema',0) or 0)<8:
        return []
    snapshot=meta.get('host_snapshot',{})
    lines=[]
    network_mode=meta.get('network_mode','unknown')
    if network_mode in ('nat','mirrored'):
        lines.append('Kali WSL ağ modu: '+network_mode.upper())
        if network_mode=='nat':
            lines.append('Ağ yeteneği: IP tabanlı testler hedef bazında rota ve erişimle doğrulanır; ham katman-2 ve fiziksel kart görünürlüğü sağlanmaz.')
    if isinstance(snapshot,dict):
        adapters=[]
        for item in snapshot.get('adapters',[]):
            address=', '.join(str(a.get('address')) for a in item.get('addresses',[]))
            adapters.append(f"{item.get('name','?')} [{item.get('status','?')}]: {address or 'IP yok'}")
        lines.append('Windows adaptörleri: '+('; '.join(adapters) or 'envanter alınamadı'))
        lines.append('Windows etki alanı: '+(str(snapshot.get('domain')) if snapshot.get('part_of_domain') else 'bağlı değil'))
    selected=meta.get('selected_interfaces',[])
    if selected:
        names={item.get('index'):item.get('name') for item in snapshot.get('adapters',[])} if isinstance(snapshot,dict) else {}
        lines.append('Seçilen Windows ağ yolları: '+', '.join(f"{index} ({names.get(index,'?')})" for index in selected))
    routes=[s for s in steps if s.get('step')=='route_scope']
    if routes:
        lines.append('Rota kapsamı: '+', '.join(f"{s.get('target','?')}={s.get('status','?')} ({s.get('detail','')})" for s in routes))
    try:
        ad=json.loads((root/'AD_ASSESSMENT.json').read_text(encoding='utf-8'))
        lines.append(f"AD değerlendirmesi: {ad.get('status','?')} — {ad.get('domain',ad.get('reason',''))}")
    except (OSError,ValueError):
        pass
    for path in sorted((root/'targets').glob('*/raw/ad_rootdse_summary.json'))[:1] if (root/'targets').exists() else []:
        try:
            rootdse=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError):
            continue
        domains=', '.join(sorted({str(item.get('domain')) for item in rootdse.get('evidence',[]) if item.get('is_ad') and item.get('domain')}))
        lines.append(f"Anonim RootDSE: {rootdse.get('ad_count',0)}/{rootdse.get('target_count',0)} adreste AD dizini kimlik doğrulamasız gözlendi"
                     +(f"; alan: {domains}" if domains else '')+". Yetki/parola ilkesi bu okumayla test edilmiş sayılmaz.")
    browser=[s for s in steps if str(s.get('step','')).startswith('browser_')]
    wireless=[s for s in steps if str(s.get('step','')).startswith('wireless_')]
    if browser:
        lines.append('Windows test tarayıcısı: '+', '.join(f"{s.get('target','?')}={s.get('status','?')}" for s in browser))
    if wireless:
        lines.append('Ham Wi-Fi: '+', '.join(f"{s.get('step')}={s.get('status')}" for s in wireless))
    passwords=[s for s in steps if str(s.get('step','')).startswith('ssh_password_')]
    if passwords:
        lines.append('SSH test hesabı denemeleri: '+', '.join(
            f"{s.get('target','?')}={s.get('status','?')}" for s in passwords))
    stopped=[s for s in steps if s.get('status') in ('blocked','timeout','interrupted')]
    if stopped:
        lines.append('Sınır veya ön koşul nedeniyle duran adımlar: '+', '.join(str(s.get('step','?')) for s in stopped[:25]))
    for path in sorted((root/'targets').glob('*/raw/audit_*.xml'))[:20]:
        try:
            tree=ET.parse(path)
        except (ET.ParseError,OSError):
            continue
        for host in tree.findall('./host'):
            ip=next((a.get('addr','') for a in host.findall('./address')
                     if a.get('addrtype') in ('ipv4','ipv6')),path.parent.parent.name)
            for port in host.findall('./ports/port'):
                script=next((s for s in port.findall('./script') if s.get('id')=='ssl-cert'),None)
                if script is None:
                    continue
                output=script.get('output','')
                subject=re.search(r'^Subject:\s*(.+)$',output,re.M)
                validity=re.search(r'^Not valid after:\s*(.+)$',output,re.M)
                if subject:
                    lines.append(f"TLS sertifikası {ip}:{port.get('portid','?')}: {subject.group(1)[:150]}"
                                 +(f"; bitiş {validity.group(1)[:40]}" if validity else '')
                                 +f"; kanıt {path.relative_to(root)}. Sertifika HTTP yanıtını doğrulamaz.")
    if (root/'STEP_AUDIT.json').is_file():
        lines.append('Önceki adım durumları ham kanıta göre yeniden değerlendirildi; steps.json korundu. Ayrıntı: STEP_AUDIT.json')
    return lines

def styles():
    s=getSampleStyleSheet()
    s.add(ParagraphStyle(name='CoverTitleX',fontName='DVB',fontSize=23,leading=31,textColor=NAVY,spaceAfter=15))
    s.add(ParagraphStyle(name='SectionX',fontName='DVB',fontSize=15,leading=20,textColor=NAVY,spaceBefore=17,spaceAfter=8,keepWithNext=True))
    s.add(ParagraphStyle(name='SubX',fontName='DVB',fontSize=10.5,leading=15,textColor=NAVY,spaceBefore=12,spaceAfter=5,keepWithNext=True))
    s.add(ParagraphStyle(name='BodyX',fontName='DV',fontSize=9,leading=14,textColor=TEXT,spaceAfter=8))
    s.add(ParagraphStyle(name='SmallX',fontName='DV',fontSize=7.4,leading=11,textColor=TEXT,spaceAfter=4,wordWrap='CJK'))
    s.add(ParagraphStyle(name='SmallWhiteX',fontName='DVB',fontSize=7.4,leading=11,textColor=colors.white,spaceAfter=2,wordWrap='CJK'))
    s.add(ParagraphStyle(name='FindingTitleX',fontName='DVB',fontSize=11,leading=16,textColor=colors.white,
                         backColor=NAVY,borderPadding=8,spaceBefore=12,spaceAfter=9,keepWithNext=True))
    s.add(ParagraphStyle(name='TOCTitleX',fontName='DVB',fontSize=19,leading=24,textColor=NAVY,spaceBefore=8,spaceAfter=12))
    s.add(ParagraphStyle(name='TOCEntryX',fontName='DV',fontSize=9,leading=15,textColor=TEXT,leftIndent=4*mm,
                         firstLineIndent=-4*mm,spaceBefore=4))
    s.add(ParagraphStyle(name='LabelX',fontName='DVB',fontSize=7.5,leading=12,textColor=GRAY,spaceAfter=3))
    s.add(ParagraphStyle(name='ValueX',fontName='DVB',fontSize=11,leading=15,textColor=NAVY,spaceAfter=8))
    s.add(ParagraphStyle(name='NoticeX',fontName='DVB',fontSize=9,leading=14,textColor=colors.HexColor('#8a5000'),backColor=colors.HexColor('#fff2d4'),borderPadding=9,spaceAfter=12))
    # Koyu siber kapak için açık renkli metin stilleri.
    s.add(ParagraphStyle(name='CoverBrandX',fontName='DVB',fontSize=30,leading=34,textColor=colors.white,spaceAfter=2))
    s.add(ParagraphStyle(name='CoverBrandSubX',fontName='DVB',fontSize=11,leading=15,textColor=TEAL,spaceAfter=18))
    s.add(ParagraphStyle(name='CoverTitleLightX',fontName='DVB',fontSize=22,leading=28,textColor=colors.white,spaceAfter=6))
    s.add(ParagraphStyle(name='CoverLabelLightX',fontName='DVB',fontSize=7.5,leading=12,textColor=colors.HexColor('#90a0c4'),spaceAfter=1))
    s.add(ParagraphStyle(name='CoverValueLightX',fontName='DVB',fontSize=12,leading=16,textColor=colors.white,spaceAfter=7))
    s.add(ParagraphStyle(name='CoverNoticeLightX',fontName='DV',fontSize=8.6,leading=13,textColor=colors.HexColor('#c3ccdf'),spaceAfter=2))
    return s

def P(value, style, limit=5000):
    return Paragraph(safe(str(value)[:limit]).replace('\n','<br/>'),style)

def grid_table(rows, widths, header=True):
    table=Table(rows,colWidths=widths,repeatRows=1 if header else 0,hAlign='LEFT')
    commands=[('VALIGN',(0,0),(-1,-1),'TOP'),
              ('GRID',(0,0),(-1,-1),.3,colors.HexColor('#dce5eb')),
              ('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),
              ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]
    if header:
        commands.extend([('BACKGROUND',(0,0),(-1,0),NAVY),
                         ('TEXTCOLOR',(0,0),(-1,0),colors.white)])
    table.setStyle(TableStyle(commands))
    return table

def coverage_story(root,meta,steps,review,st,width,executive):
    ledger=build_coverage(root,meta,steps,review)
    result=[P('Test kapsamı ve yürütme durumu',st['SectionX']),
            P('Bir kontrolün çalışmış olması bir zafiyet bulunduğunu veya kontrolün tüm senaryolarının tamamlandığını göstermez. Durumlar gerçek adım ve analist kanıt kayıtlarından hesaplanır.',st['BodyX'])]
    totals=ledger['counts']
    result.append(P(' · '.join(f'{label}: {totals[label]}' for label in totals),st['SmallX']))
    controls=ledger['controls'] if not executive else [r for r in ledger['controls'] if r['status']!='kayıt yok']
    if controls:
        headings=('Kontrol','Durum','Yürütme / gerekçe')
        rows=[[P(x,st['SmallWhiteX']) for x in headings]]
        for row in controls:
            reason=row['reason'] or (f"{row['executed']}/{row['attempted']} kayıtlı adım" if row['attempted'] else 'Bu görevde yürütme kaydı yok')
            rows.append([P(f"{row['id']} · {row['title']}",st['SmallX'],limit=120),
                         P(row['status'],st['SmallX']),P(reason,st['SmallX'],limit=180)])
        result.append(grid_table(rows,[width*.34,width*.15,width*.51]))
    result.append(P('Tam kontrol matrisi ve adım bağlantıları: ASSESSMENT_COVERAGE.json / steps.json.',st['SmallX']))
    return result

def network_story(meta,st,width):
    rows=network_rows(meta)
    if not rows:
        return []
    result=[P('Windows ağ yolları',st['SectionX']),
            P('Adaptör ve alt ağ görünürlüğü hedef yetkisinin yerine geçmez. Seçilen yol, görevdeki kapsamla ayrıca eşleştirilir.',st['BodyX'])]
    cells=[[P(x,st['SmallWhiteX']) for x in ('Adaptör / durum','IP ve ağ','Ağ geçidi / DNS')]]
    for row in rows:
        cells.append([P(row['name']+(' · seçili' if row['selected'] else '')+
                        (' · VPN' if row['vpn'] else '')+' / '+row['status'],st['SmallX'],limit=150),
                      P(row['addresses'] or 'IP yok',st['SmallX'],limit=180),
                      P('GW: '+(row['gateway'] or '—')+'\nDNS: '+(row['dns'] or '—'),st['SmallX'],limit=180)])
    result.append(grid_table(cells,[width*.30,width*.30,width*.40]))
    return result

def ad_result(root):
    try:
        value=json.loads((root/'AD_ASSESSMENT.json').read_text(encoding='utf-8'))
        return value if isinstance(value,dict) else {}
    except (OSError,ValueError):
        return {}

def ad_story(root,st,width):
    ad=ad_result(root)
    if not ad:
        return []
    result=[P('Etki alanı değerlendirmesi',st['SectionX']),
            P(f"Durum: {ad.get('status','?')} · Kaynak: {ad.get('source','?')} · Alan: {ad.get('domain','?')} · DC: {ad.get('domain_controller',ad.get('dc','?'))}",st['BodyX'])]
    if ad.get('reason'):
        result.append(P('Sınır / hata: '+str(ad['reason']),st['SmallX']))
    inventory=ad.get('inventory',{})
    if isinstance(inventory,dict) and inventory:
        cells=[[P(x,st['SmallWhiteX']) for x in ('Nesne türü','Gözlenen sayı','Sorgu sınırı')]]
        for kind,item in inventory.items():
            if isinstance(item,dict):
                cells.append([P(kind,st['SmallX']),P(item.get('observed_count','?'),st['SmallX']),
                              P(item.get('truncated_at','?'),st['SmallX'])])
        result.append(grid_table(cells,[width*.45,width*.25,width*.30]))
    # Test hesabının kendi grup üyelikleri (memberOf) — hangi gruplardayız.
    mem=ad.get('test_account_membership')
    if isinstance(mem,dict):
        groups=mem.get('groups',[])
        result.append(P(f"Test hesabı: {mem.get('account','?')}"+(f" ({mem.get('display_name')})" if mem.get('display_name') else '')
                        +f" · üye olduğu grup sayısı: {len(groups)}",st['SubX']))
        if groups:
            result.append(P('Üye olunan gruplar: '+', '.join(groups),st['SmallX'],limit=1500))
    # Kullanıcı / grup / bilgisayar adı listeleri (yalnız ad; parola/hash yok).
    for key,title in (('user_names','Kullanıcı adları'),('group_names','Grup adları'),
                      ('computer_names','Bilgisayar adları')):
        names=ad.get(key)
        if isinstance(names,list) and names:
            shown=', '.join(str(n) for n in names[:200])
            more=f" (+{len(names)-200} daha)" if len(names)>200 else ''
            result.append(P(f"{title} ({len(names)}): "+shown+more,st['SmallX'],limit=4000))
    if ad.get('domain_admins') and isinstance(ad['domain_admins'],dict):
        da=ad['domain_admins']
        result.append(P(f"{da.get('group','Domain Admins')} üyeleri ({da.get('count','?')}): "
                        +', '.join(da.get('members',[])),st['SmallX'],limit=1500))
    # Hassas grup üyelikleri (Domain Admins dışı ayrıcalıklı gruplar).
    groups=ad.get('sensitive_groups')
    if isinstance(groups,dict) and groups:
        result.append(P('Hassas grup üyelikleri',st['SubX']))
        for gname,members in groups.items():
            if members:
                result.append(P(f"{gname} ({len(members)}): "+', '.join(members[:60]),st['SmallX'],limit=1500))
    # Hesap risk bayrakları (userAccountControl), Kerberoast ve AS-REP.
    _UAC_LABELS={'disabled':'Devre dışı','passwd_notreqd':'Parola gerekmiyor',
        'reversible_encryption':'Tersinir şifreleme','password_never_expires':'Parolası hiç bitmiyor',
        'unconstrained_delegation':'Kısıtlanmamış yetkilendirme','asrep_roastable':'AS-REP roast edilebilir',
        'constrained_delegation_proto':'Protokol geçişli yetkilendirme'}
    risky=ad.get('risky_accounts')
    if isinstance(risky,dict) and risky:
        result.append(P('Hesap risk bayrakları (userAccountControl)',st['SubX']))
        for key,names in risky.items():
            if names:
                result.append(P(f"{_UAC_LABELS.get(key,key)} ({len(names)}): "
                                +', '.join(names[:80])+(f" (+{len(names)-80})" if len(names)>80 else ''),st['SmallX'],limit=2000))
    kerb=ad.get('kerberoastable')
    if isinstance(kerb,list) and kerb:
        result.append(P(f"Kerberoast edilebilir hesaplar ({len(kerb)}): "
                        +', '.join((str(k.get('account','?'))+('*' if isinstance(k,dict) and k.get('admin') else '')) for k in kerb[:80]),
                        st['SmallX'],limit=2000))
    asrep=ad.get('asrep_roastable')
    if isinstance(asrep,list) and asrep:
        result.append(P(f"AS-REP roast edilebilir ({len(asrep)}): "+', '.join(asrep[:80]),st['SmallX'],limit=2000))
    if ad.get('ldap_cleartext_bind') is True:
        result.append(P('LDAP imzalama/kanal bağlama zorlanmıyor: 389 üzerinde şifresiz SIMPLE bağlanma kabul edildi '
                        '(kimlik bilgisi ağda açık; NTLM relay-to-LDAP riski).',st['SmallX']))
    osx=ad.get('computer_os_summary')
    if isinstance(osx,dict) and osx:
        result.append(P('Bilgisayar işletim sistemi dağılımı: '+', '.join(f"{k}: {v}" for k,v in osx.items()),st['SmallX'],limit=1500))
    stale=ad.get('stale_computers')
    if isinstance(stale,list) and stale:
        result.append(P(f"90+ gün oturum açmamış bilgisayarlar ({len(stale)}): "+', '.join(stale[:60]),st['SmallX'],limit=1500))
    # ADCS (sertifika servisleri) ve SYSVOL/GPP.
    adcs=ad.get('adcs')
    if isinstance(adcs,dict) and adcs.get('cas'):
        result.append(P('AD Sertifika Servisleri (ADCS)',st['SubX']))
        result.append(P('Sertifika Yetkilisi (CA): '+', '.join(f"{c.get('name','?')} @ {c.get('host','?')}" for c in adcs['cas']),st['SmallX'],limit=1500))
        escs=adcs.get('esc') or []
        if escs:
            for e in escs:
                result.append(P(f"{e.get('esc')} · {e.get('template')}: {e.get('detail')}",st['SmallX'],limit=2000))
        else:
            result.append(P(f"{len(adcs.get('templates') or [])} şablon incelendi; düşük yetkili istismar adayı (ESC1-ESC4) bulunmadı. ESC6/ESC7/ESC8 Attack Mode (certipy) ile değerlendirilir.",st['SmallX']))
    sv=ad.get('sysvol')
    if isinstance(sv,dict) and sv.get('status')=='ok' and sv.get('cpassword_count'):
        result.append(P(f"SYSVOL / Group Policy Preferences: {sv['cpassword_count']} adet cpassword bulundu ve kamuya açık anahtarla çözüldü (kritik).",st['SubX']))
        for hit in (sv.get('findings') or [])[:20]:
            if isinstance(hit,dict):
                result.append(P(f"  {hit.get('file_type','?')} · kullanıcı: {hit.get('username','?')} · {hit.get('path','')}",st['SmallX'],limit=1200))
    # Yönetici-benzeri özel gruplar, GPO bağlantıları, OU kullanıcı dağılımı.
    admin_g=ad.get('admin_like_groups')
    if isinstance(admin_g,dict) and admin_g:
        result.append(P('Yönetici-benzeri özel gruplar',st['SubX']))
        for g,info in admin_g.items():
            if isinstance(info,dict):
                result.append(P(f"{g} ({len(info.get('members',[]))}): "+', '.join(info.get('members',[])[:40]),st['SmallX'],limit=1500))
    gpos=ad.get('gpos')
    if isinstance(gpos,list) and gpos:
        result.append(P('Grup İlkeleri (GPO)',st['SubX']))
        for g in gpos[:40]:
            if isinstance(g,dict):
                links=', '.join(str(x).split(',')[0] for x in (g.get('links') or [])[:4]) or 'bağlı değil'
                result.append(P(f"{g.get('name') or g.get('guid')} → {links}",st['SmallX'],limit=1500))
    dist=ad.get('ou_user_distribution')
    if isinstance(dist,list) and dist:
        result.append(P('OU kullanıcı dağılımı: '+', '.join(f"{str(x.get('ou','')).split(',')[0]}={x.get('users')}" for x in dist[:20] if isinstance(x,dict)),st['SmallX'],limit=1500))
    # Riskli AD: ayrıcalıklı hesap ACL'leri, delegasyon, RBCD (BloodHound-benzeri).
    acl_risks=ad.get('privileged_acl_risks')
    if isinstance(acl_risks,list) and acl_risks:
        result.append(P('Nesneler üzerinde tehlikeli haklar (BloodHound-benzeri ACL taraması)',st['SubX']))
        for r in acl_risks[:60]:
            if isinstance(r,dict):
                ot=f" [{r.get('object_type')}]" if r.get('object_type') else ''
                result.append(P(f"{r.get('account','?')}{ot} ← {r.get('principal','?')}: {r.get('right','?')}",st['SmallX'],limit=1500))
    hyg=ad.get('privileged_hygiene')
    if isinstance(hyg,list) and hyg:
        unused=[h for h in hyg if isinstance(h,dict) and h.get('never_logged_on') and h.get('enabled')]
        oldpw=[h for h in hyg if isinstance(h,dict) and (h.get('pwd_age_days') or 0)>730 and h.get('enabled')]
        if unused:
            result.append(P('Hiç oturum açmamış (kullanılmayan) ayrıcalıklı hesaplar: '+', '.join(h['account'] for h in unused[:30]),st['SmallX'],limit=1500))
        if oldpw:
            result.append(P('Parolası çok eski (>2 yıl) ayrıcalıklı hesaplar: '+', '.join(f"{h['account']} ({h['pwd_age_days']}g)" for h in oldpw[:30]),st['SmallX'],limit=1500))
    descpw=ad.get('description_password_candidates')
    if isinstance(descpw,list) and descpw:
        result.append(P(f"Açıklama (description) alanında parola şüphesi ({len(descpw)}): "+', '.join(d.get('account','?') for d in descpw[:30]),st['SmallX'],limit=1500))
    deleg=ad.get('constrained_delegation')
    if isinstance(deleg,list) and deleg:
        result.append(P('Kısıtlı yetkilendirme: '+', '.join(f"{x.get('account')}"+(' [T2A4D]' if x.get('protocol_transition') else '') for x in deleg[:30] if isinstance(x,dict)),st['SmallX'],limit=1500))
    rbcd=ad.get('rbcd_configured')
    if isinstance(rbcd,list) and rbcd:
        result.append(P('RBCD kurulu hesaplar: '+', '.join(rbcd[:30]),st['SmallX'],limit=1500))
    if ad.get('forest') or ad.get('domain_mode'):
        result.append(P(f"Orman: {ad.get('forest','?')} · Orman modu: {ad.get('forest_mode','?')} · Alan modu: {ad.get('domain_mode','?')}",st['SmallX']))
    if ad.get('dc_dns_records'):
        result.append(P('DC DNS kayıtları: '+', '.join(str(x.get('name',''))+':'+str(x.get('port',''))
                     for x in ad['dc_dns_records'] if isinstance(x,dict)),st['SmallX']))
    result.append(P('Bu bölüm dizin envanteridir. Kullanıcı/grup adları ve üyelikler salt-okunur LDAP ile alınmıştır; parola/hash içermez. Ayrıcalık ve paylaşım izinleri ancak ayrıca kaydedilen kontrollerle değerlendirilmiş sayılır.',st['SmallX']))
    return result

def finding_story(root,f,st,width):
    result=[P(f"{f['id']}  ·  {f['title']}",st['FindingTitleX'])]
    metadata=[('Önem derecesi',SEVERITIES.get(f.get('severity'),'Bilgi')),
              ('Durum',f.get('status','')),('Etkilenen varlık',f.get('asset','')),
              ('Diğer etkilenenler',', '.join(f.get('affected_assets',[]))),
              ('Kategori',f.get('category','')),('Erişim noktası',f.get('access_point','')),
              ('Kullanıcı profili',f.get('user_profile','')),('Kök neden',f.get('root_cause','')),
              ('CVSS / referans', ' · '.join(x for x in (f.get('cvss',''),f.get('reference','')) if x)),
              ('CWE sınıfı', f.get('cwe',''))]
    rows=[[P(label,st['LabelX']),P(value,st['SmallX'],limit=250)]
          for label,value in metadata if value]
    result.append(grid_table(rows,[width*.28,width*.72],header=False))
    for label,key in (('Bulgu açıklaması','description'),('Tekrar üretim ve doğrulama','reproduction'),
                      ('İş etkisi','impact'),('Düzeltme önerisi','recommendation'),
                      ('Düzeltme önceliği','remediation_priority'),('Yeniden test','retest_status')):
        if f.get(key):
            result.extend([P(label,st['SubX']),P(f[key],st['BodyX'])])
    if f.get('reviewed_by'):
        result.append(P('Doğrulayan analist: '+f['reviewed_by'],st['SmallX']))
    evidence_items=finding_evidence(f)
    result.append(P('Kanıt zinciri',st['SubX']))
    if not evidence_items:
        result.append(P('Kanıt dosyası kaydedilmedi.',st['SmallX']))
    for item in evidence_items:
        result.append(P(f"{item['caption']}: {item['path']}"+
                        (f" · SHA-256: {item['sha256']}" if item['sha256'] else ''),st['SmallX']))
    if f.get('status')=='doğrulandı':
        from analyst_review import evidence
        from PIL import Image as PILImage
        for item in evidence_items[:2]:
            path=root/item['path']
            try:
                if path.suffix.lower() not in ('.png','.jpg','.jpeg') or evidence(root,item['path'])!=item['sha256']:
                    continue
                with PILImage.open(path) as picture:
                    picture.verify()
                with PILImage.open(path) as picture:
                    if picture.width*picture.height>25_000_000:
                        continue
                    scale=min((width-10*mm)/picture.width,90*mm/picture.height)
                    result.append(Image(str(path),width=picture.width*scale,height=picture.height*scale))
                    result.append(Spacer(1,3*mm))
            except (OSError,ValueError):
                continue
    result.append(Spacer(1,6*mm))
    return result

def _parse_smb_shares(output):
    """Return 'SHARE [access]' strings for shares smb-enum-shares reports as readable/writable."""
    shares=[]
    current=None
    for line in output.splitlines():
        header=re.match(r'\s*\\\\[^\\]+\\(.+?):\s*$',line)
        if header:
            current={'name':header.group(1).strip(),'access':''}
            shares.append(current)
            continue
        if current is not None:
            access=re.match(r'\s*(?:Anonymous access|Current user access):\s*(.+?)\s*$',line,re.I)
            if access and re.search(r'READ|WRITE',access.group(1),re.I):
                current['access']=access.group(1).strip()
    return [f"{s['name']} [{s['access']}]" for s in shares if s['access']]


def read_data(root):
    meta=json.loads((root/'engagement.json').read_text(encoding='utf-8'))
    steps=json.loads((root/'steps.json').read_text(encoding='utf-8')) if (root/'steps.json').exists() else []
    review=json.loads((root/'review.json').read_text(encoding='utf-8')) if (root/'review.json').exists() else {'findings':[], 'analyst_summary':''}
    if not isinstance(review.get('findings',[]),list):
        raise ValueError('review.json findings bir liste olmalı')
    hosts=[]
    for path in sorted((root/'targets').glob('*/raw/nmap_*.xml')) if (root/'targets').exists() else []:
        try:
            tree=ET.parse(path)
            for host in tree.findall('.//host'):
                address=host.find('address')
                if address is None: continue
                ip=address.get('addr','')
                ports=[]
                for port in host.findall('./ports/port'):
                    if port.find('state') is not None and port.find('state').get('state')=='open':
                        service=port.find('service')
                        ports.append({'port':port.get('portid',''),'protocol':port.get('protocol',''), 'service':service.get('name','') if service is not None else '', 'product':service.get('product','') if service is not None else '', 'version':service.get('version','') if service is not None else '', 'extrainfo':service.get('extrainfo','') if service is not None else ''})
                hosts.append({'ip':ip,'ports':ports,'evidence':str(path.relative_to(root))})
        except ET.ParseError:
            steps.append({'step':'parse','status':'error','detail':f'Bozuk Nmap XML: {path.name}'})
    # Aynı IP birden çok Nmap XML'inde (ör. top-1000 + platform portları) görülebilir;
    # portları birleştir ve kanıt yollarını topla ki adres tek satırda gösterilsin.
    merged={}
    for host in hosts:
        entry=merged.setdefault(host['ip'],{'ip':host['ip'],'ports':[],'evidence':host['evidence'],'_seen':set()})
        for port in host['ports']:
            key=(port['port'],port['protocol'])
            if key not in entry['_seen']:
                entry['_seen'].add(key)
                entry['ports'].append(port)
        if host['evidence'] not in entry['evidence']:
            entry['evidence']+='; '+host['evidence']
    hosts=[{k:v for k,v in entry.items() if k!='_seen'} for entry in merged.values()]
    findings=[]
    # Non-intrusive header observations are review candidates, never confirmed vulnerabilities.
    observations=[]
    service_candidates={
        21:('FTP servisi erişilebilir','info','FTP komut kanalı şifrelenmemiş olabilir. Anonim erişim, veri aktarımı veya kimlik bilgisi gözlenmedi.','Servis yapılandırmasına göre kimlik ve veri gizliliği etkilenebilir.','FTP gerekmiyorsa kapatın; gerekiyorsa FTPS/SFTP ve erişim sınırlarını doğrulayın.'),
        23:('Telnet servisi erişilebilir','medium','TCP/23 açık göründü. Etkileşimli oturum, şifreleme eksikliği ve kimlik doğrulama ayrıca doğrulanmalıdır.','Telnet kullanılıyorsa oturum ve kimlik bilgileri korunmasız iletilebilir.','Telnet ihtiyacını kaldırıp SSH veya eşdeğer şifreli yönetim yoluna geçin.'),
        445:('SMB servisi erişilebilir','info','TCP/445 açık göründü. Paylaşım izinleri, SMB sürümü ve imzalama denetlenmedi.','İzin veya sürüm hatası varsa dosya erişimi ve kimlik doğrulama etkilenebilir.','Paylaşım ve erişim izinlerini, SMBv1 durumunu ve imzalama politikasını doğrulayın.'),
        3389:('RDP servisi erişilebilir','info','TCP/3389 açık göründü. Ağ segmenti, NLA, MFA ve hesap kilitlenme politikası doğrulanmadı.','Erişim sınırları zayıfsa uzak yönetim saldırı yüzeyi artabilir.','RDP erişimini yetkili yönetim ağlarıyla sınırlayın; NLA, MFA ve günlüklemeyi doğrulayın.'),
        1433:('Veritabanı servisi erişilebilir','info','TCP/1433 açık göründü. Kimlik doğrulama ve veritabanı izinleri sınanmadı.','Yanlış yapılandırma varsa veritabanı erişimi mümkün olabilir.','Dinleme arayüzünü, ağ erişim listesini, sürümü ve en az yetki ilkesini doğrulayın.'),
        3306:('Veritabanı servisi erişilebilir','info','TCP/3306 açık göründü. Kimlik doğrulama ve veritabanı izinleri sınanmadı.','Yanlış yapılandırma varsa veritabanı erişimi mümkün olabilir.','Dinleme arayüzünü, ağ erişim listesini, sürümü ve en az yetki ilkesini doğrulayın.'),
    }
    for host in hosts:
        for port in host['ports']:
            if port.get('protocol')!='tcp' or not str(port.get('port','')).isdigit():
                continue
            number=int(port['port'])
            service=str(port.get('service','')).lower()
            expected={21:('ftp',),23:('telnet',),445:('microsoft-ds','smb'),
                      3389:('ms-wbt-server','rdp'),1433:('ms-sql-s','mssql'),
                      3306:('mysql',)}.get(number,())
            if service and not any(name in service for name in expected):
                continue
            profile=service_candidates.get(number)
            if profile:
                title,severity,description,impact,recommendation=profile
                if not service:
                    title=f'TCP/{number} üzerinde servis erişilebilir (tür doğrulanmadı)'
                observations.append({'title':title,'severity':severity,'asset':host['ip']+':'+port['port'],
                                     'description':description,'impact':impact,'recommendation':recommendation,
                                     'evidence':host['evidence']})
    for path in sorted((root/'targets').glob('*/raw/headers_*_*.txt')) if (root/'targets').exists() else []:
        body=path.read_text(encoding='utf-8',errors='replace')[:16384]
        statuses=[int(x) for x in re.findall(r'(?im)^HTTP/\S+\s+(\d{3})',body)]
        if not statuses or statuses[-1] >= 400: continue
        headers={}
        for line in body.splitlines():
            if ':' in line:
                key,value=line.split(':',1)
                headers[key.strip().lower()]=value.strip()
        asset=path.parent.parent.name
        evidence=str(path.relative_to(root))
        if re.search(r'_https_\d+$',path.stem) and 'strict-transport-security' not in headers:
            observations.append({'title':'HTTPS yanıtında HSTS başlığı görülmedi','severity':'low','asset':asset,'description':'HEAD yanıtında Strict-Transport-Security başlığı bulunmadı. Alt alan adları ve uygulama mimarisi dikkate alınarak doğrulayın.','impact':'Tarayıcının daha sonraki HTTP isteklerini HTTPS üzerinden zorlama koruması bulunmayabilir.','recommendation':'Tüm uçlarda HTTPS doğrulandıktan sonra uygun max-age ile HSTS değerlendirin.','evidence':evidence})
        if re.search(r'_https_\d+$',path.stem) and 'x-content-type-options' not in headers:
            observations.append({'title':'X-Content-Type-Options başlığı görülmedi','severity':'info','asset':asset,'description':'HEAD yanıtında X-Content-Type-Options bulunmadı.','impact':'Tarayıcı içerik türünü tahmin edebilir; uygulamaya göre risk değişir.','recommendation':'Uygunsa nosniff başlığını ekleyip MIME tiplerini doğrulayın.','evidence':evidence})
        if re.search(r'_http_\d+$',path.stem) and statuses[-1] == 200:
            observations.append({'title':'HTTP uç noktası 200 yanıtı veriyor','severity':'info','asset':asset,'description':'HTTP HEAD isteğine başarılı yanıt verildi; içerik aktarımını ve HTTPS yönlendirmesini manuel doğrulayın.','impact':'Uygulama verileri HTTP ile iletiliyorsa gizlilik riski oluşabilir.','recommendation':'HTTP uçlarında HTTPS yönlendirmesini ve HSTS politikasını doğrulayın.','evidence':evidence})
    for path in sorted((root/'targets').glob('*/raw/methods_*_*.txt')) if (root/'targets').exists() else []:
        body=path.read_text(encoding='utf-8',errors='replace')[:16384]
        allow=re.search(r'(?im)^Allow:\s*([^\r\n]+)',body)
        if allow and 'TRACE' in {x.strip().upper() for x in allow.group(1).split(',')}:
            observations.append({'title':'TRACE HTTP yöntemi Allow başlığında listeleniyor','severity':'low','asset':path.parent.parent.name,'description':'OPTIONS yanıtında TRACE göründü; yöntem gerçekten çalışıyor mu ve iş etkisi var mı manuel doğrulayın.','impact':'Gereksiz HTTP yöntemleri saldırı yüzeyini artırabilir.','recommendation':'Gerekmiyorsa sunucu veya ters vekil yapılandırmasında TRACE yöntemini devre dışı bırakın.','evidence':str(path.relative_to(root))})
    for path in sorted((root/'targets').glob('*/raw/audit_*.xml')) if (root/'targets').exists() else []:
        try:
            tree=ET.parse(path)
        except ET.ParseError:
            continue
        for host in tree.findall('./host'):
            address=host.find('./address')
            asset=address.get('addr',path.parent.parent.name) if address is not None else path.parent.parent.name
            for script in host.findall('.//script'):
                if script.get('id')!='ssl-enum-ciphers':
                    continue
                output=script.get('output','')
                for legacy in ('SSLv3','TLSv1.0','TLSv1.1'):
                    if re.search(r'(?m)^\s*'+re.escape(legacy)+r'\s*:',output):
                        observations.append({'title':f'{legacy} protokolü kabul ediliyor olabilir','severity':'medium','asset':asset,'description':'Nmap ssl-enum-ciphers çıktısında eski TLS/SSL sürümü listelendi. TLS sonlandırma noktası ve uygulama etkisi doğrulanmalıdır.','impact':'Eski protokoller modern güvenlik gereksinimlerini karşılamayabilir.','recommendation':'Uyumluluk etkisini değerlendirdikten sonra eski sürümleri kapatıp TLS 1.2/1.3 kullanın.','evidence':str(path.relative_to(root))})
    for path in sorted((root/'targets').glob('*/raw/nuclei_*.jsonl')) if (root/'targets').exists() else []:
        for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
            try:
                result=json.loads(line)
            except json.JSONDecodeError:
                continue
            info=result.get('info') or {}
            severity=str(info.get('severity','info')).lower()
            observations.append({'title':str(info.get('name') or result.get('template-id') or 'Nuclei gözlemi'),'severity':severity if severity in SEVERITIES else 'info','asset':str(result.get('matched-at') or result.get('host') or path.parent.parent.name),'description':str(info.get('description') or 'Şablon eşleşmesi; analist doğrulaması gerekir.'),'impact':'Gerçek etki ve tekrar üretilebilirlik analist tarafından doğrulanmalıdır.','recommendation':'Şablon referanslarını ve kanıtı inceleyip doğrulanmışsa düzeltme planı hazırlayın.','evidence':str(path.relative_to(root))})
    for path in sorted((root/'targets').glob('*/raw/snmp_v1_public_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict) or item.get('confirmed_response') is not True or item.get('version') not in ('1','2c') or item.get('community')!='public':
            continue
        observations.append({'title':'SNMP varsayılan public topluluğuyla bilgi okunabiliyor',
                             'severity':'medium','asset':str(item.get('target','')),
                             'description':'Tek salt okunur sysDescr sorgusuna SNMPv1/public yanıtı alındı. Erişim sınırları ve yanıtın kaynak cihazı analistçe doğrulanmalıdır.',
                             'impact':'Varsayılan toplulukla cihaz ve sürüm bilgisi edinilebilir; SNMPv1 trafik şifrelemez.',
                             'recommendation':'SNMPv1/v2c ve varsayılan toplulukları kapatın; gerekliyse SNMPv3, erişim kontrolü ve sınırlandırılmış yönetim ağı kullanın.',
                             'evidence':str(path.relative_to(root))})
    for path in sorted((root/'targets').glob('*/raw/cred_default_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict) or not item.get('valid'):
            continue
        service=str(item.get('service','')).upper()
        observations.append({'title':f'{service} varsayılan/zayıf kimlik bilgisi geçerli',
                             'severity':'high','asset':f"{item.get('ip','')}:{item.get('port','')}",
                             'description':f"Kamuya açık üretici varsayılan kimlik bilgisi geçerli göründü (kullanıcı: {item.get('username','')}). Parola görev dosyasına yazılmadı; analist doğrulamalı ve iş etkisini kaydetmelidir.",
                             'impact':'Varsayılan/zayıf kimlik bilgisiyle cihaz veya servis yönetimi ele geçirilebilir.',
                             'recommendation':'Varsayılan hesabı devre dışı bırakın veya güçlü, benzersiz parolayla değiştirin; mümkünse MFA ve yönetim erişim sınırı ekleyin.',
                             'evidence':str(path.relative_to(root))})
    # --- EOL (kullanım ömrü dolmuş) yazılım: Nmap ürün/sürüm dizelerinden ---
    for host in hosts:
        seen_eol=set()
        for port in host['ports']:
            hit=eol_data.detect(str(port.get('product','')),str(port.get('version','')),
                                str(port.get('extrainfo','')))
            if not hit or hit['name'] in seen_eol:
                continue
            seen_eol.add(hit['name'])
            observations.append({'title':f"{hit['name']} kullanım ömrü (EOL) dolmuş sürüm",
                'severity':hit['severity'],'asset':f"{host['ip']}:{port['port']}",
                'description':f"{hit['name']} {hit['matched_version']} sürümü üreticinin desteklediği yaşam döngüsünü doldurmuş görünüyor (EOL tarihi: {hit['eol_date']}). {hit['note']} Sürüm bilgisi Nmap servis tespitinden alınmıştır.",
                'impact':'Destek dışı yazılım güvenlik yaması alamaz; bilinen açıklıklar kapatılamadan açık kalır.',
                'recommendation':'Desteklenen bir sürüme yükseltin; mümkün değilse sistemi ağdan yalıtıp telafi edici kontroller uygulayın.',
                'evidence':host['evidence']})
    # --- Salt okunur / güvenli NSE betikleri (ftp-anon, telnet, SMB, MSSQL) ---
    for path in sorted((root/'targets').glob('*/raw/audit_*.xml')) if (root/'targets').exists() else []:
        try:
            tree=ET.parse(path)
        except (ET.ParseError,OSError):
            continue
        rel=str(path.relative_to(root))
        for host in tree.findall('./host'):
            ip=next((a.get('addr','') for a in host.findall('./address')
                     if a.get('addrtype') in ('ipv4','ipv6')),path.parent.parent.name)
            scripts=[]
            for port in host.findall('./ports/port'):
                pid=port.get('portid','')
                for script in port.findall('./script'):
                    scripts.append((pid,script.get('id',''),script.get('output','')))
            for script in host.findall('./hostscript/script'):
                scripts.append(('',script.get('id',''),script.get('output','')))
            for pid,sid,output in scripts:
                asset=f"{ip}:{pid}" if pid else ip
                low=output.lower()
                if sid=='ftp-anon' and 'anonymous ftp login allowed' in low:
                    observations.append({'title':'Anonim FTP erişimine izin veriliyor','severity':'medium','asset':asset,
                        'description':'Nmap ftp-anon betiği anonim (Anonymous) FTP oturumuna izin verildiğini gösterdi. Erişilebilen dizinler ve yazma izni analistçe doğrulanmalıdır.\n'+output.strip()[:600],
                        'impact':'Kimlik doğrulaması olmadan dosyalara erişim veya yükleme mümkün olabilir; bilgi ifşası ve yetkisiz erişim riski.',
                        'recommendation':'Anonymous hesabını kaldırın; FTP yerine kimlik doğrulamalı SFTP/FTPS kullanın ve dizin izinlerini sınırlayın.',
                        'evidence':rel})
                elif sid=='telnet-encryption' and 'does not support encryption' in low:
                    observations.append({'title':'Telnet servisi şifreleme desteklemiyor (düz metin)','severity':'medium','asset':asset,
                        'description':'Nmap telnet-encryption betiği Telnet sunucusunun şifreleme desteklemediğini gösterdi. Telnet oturumu düz metin (plain text) taşır.\n'+output.strip()[:300],
                        'impact':'Kullanıcı adı, parola ve komutlar ağ trafiği izlenerek (sniffing) elde edilebilir.',
                        'recommendation':'Telnet servisini kapatıp SSH gibi şifreli bir yönetim kanalına geçin.',
                        'evidence':rel})
                elif sid in ('smb-security-mode','smb2-security-mode') and 'message signing' in low and ('disabled' in low or 'not required' in low):
                    observations.append({'title':'SMB ileti imzalama zorunlu değil','severity':'medium','asset':ip,
                        'description':'Nmap '+sid+' betiği SMB ileti imzalamanın devre dışı olduğunu veya zorunlu kılınmadığını gösterdi.\n'+output.strip()[:300],
                        'impact':'İmzalama zorunlu değilse SMB oturumları araya girme (MITM) ve NTLM röle saldırılarına açık olabilir.',
                        'recommendation':'Sunucu ve istemcilerde SMB imzalamayı grup ilkesiyle zorunlu hale getirin.',
                        'evidence':rel})
                elif sid=='smb-enum-shares':
                    listed=_parse_smb_shares(output)
                    if listed:
                        observations.append({'title':'SMB paylaşımlarına erişilebiliyor','severity':'medium','asset':ip,
                            'description':'Nmap smb-enum-shares betiği erişilebilir paylaşımlar listeledi. Erişim düzeyi (READ/WRITE) ve içerik analistçe doğrulanmalıdır.\nPaylaşımlar: '+('; '.join(listed))[:800],
                            'impact':'Yetkisiz kullanıcılar hassas dosyalara erişebilir veya yazabilir; bilgi ifşası ve bütünlük riski.',
                            'recommendation':'Paylaşım ve NTFS izinlerini en az yetki ilkesine göre daraltın; gereksiz paylaşımları kaldırın; anonim/guest erişimini kapatın.',
                            'evidence':rel})
                elif sid=='ms-sql-info':
                    product=re.search(r'(?im)product:\s*(microsoft sql server[^\r\n]*)',output)
                    number=re.search(r'(?im)version number:\s*([0-9.]+)',output)
                    if product:
                        hit=eol_data.detect(product.group(1),number.group(1) if number else '',product.group(1))
                        if hit:
                            observations.append({'title':f"{hit['name']} kullanım ömrü (EOL) dolmuş sürüm",
                                'severity':hit['severity'],'asset':asset,
                                'description':f"ms-sql-info betiği {product.group(1).strip()} tespit etti; bu sürüm yaşam döngüsünü doldurmuş görünüyor (EOL tarihi: {hit['eol_date']}). {hit['note']}",
                                'impact':'Destek dışı veritabanı sunucusu güvenlik yaması alamaz.',
                                'recommendation':'Desteklenen bir MSSQL sürümüne yükseltin; mümkün değilse sunucuyu yalıtın.',
                                'evidence':rel})
    # --- Etki alanı politikası bulguları (AD_ASSESSMENT.json'dan) ---
    ad_json=root/'AD_ASSESSMENT.json'
    if ad_json.is_file():
        try:
            ad=json.loads(ad_json.read_text(encoding='utf-8'))
        except (ValueError,OSError):
            ad={}
        if isinstance(ad,dict) and ad.get('status')=='ok':
            dom=str(ad.get('domain','etki alanı'))
            pol=ad.get('password_policy') or {}
            minlen=pol.get('min_length')
            if isinstance(minlen,int) and minlen<8:
                observations.append({'title':'Zayıf etki alanı parola politikası (minimum uzunluk)','severity':'medium','asset':dom,
                    'description':f"Etki alanı minimum parola uzunluğu {minlen} karakter olarak okundu (LDAP). Önerilen değer en az 12 karakterdir.",
                    'impact':'Kısa parolalar kaba kuvvet ve tahmin saldırılarına karşı belirgin şekilde zayıftır.',
                    'recommendation':'Minimum parola uzunluğunu en az 12 karaktere çıkarın ve karmaşıklık ile hesap kilitleme politikalarını birlikte uygulayın.',
                    'evidence':'AD_ASSESSMENT.json'})
            if pol.get('complexity_enabled') is False:
                observations.append({'title':'Etki alanı parola karmaşıklığı zorunlu değil','severity':'medium','asset':dom,
                    'description':'Etki alanı parola karmaşıklık gereksinimi (pwdProperties) devre dışı okundu.',
                    'impact':'Karmaşıklık olmadan basit ve tahmin edilebilir parolalar kullanılabilir.',
                    'recommendation':'Parola karmaşıklık gereksinimini etkinleştirin.',
                    'evidence':'AD_ASSESSMENT.json'})
            if pol.get('lockout_threshold')==0:
                observations.append({'title':'Hesap kilitleme eşiği tanımlı değil','severity':'medium','asset':dom,
                    'description':'Etki alanı hesap kilitleme eşiği (lockoutThreshold) 0 okundu; başarısız denemelerde hesap kilitlenmez.',
                    'impact':'Sınırsız parola denemesi kaba kuvvet ve parola püskürtme (password spraying) saldırılarını kolaylaştırır.',
                    'recommendation':'Makul bir kilitleme eşiği (ör. 5-10 deneme) ve kilit süresi tanımlayın.',
                    'evidence':'AD_ASSESSMENT.json'})
            maq=ad.get('machine_account_quota')
            if isinstance(maq,int) and maq>0:
                observations.append({'title':'Standart kullanıcı etki alanına makine ekleyebiliyor (MachineAccountQuota)','severity':'medium','asset':dom,
                    'description':f"ms-DS-MachineAccountQuota değeri {maq} okundu; yetkisiz standart kullanıcılar da etki alanına makine ekleyebilir.",
                    'impact':'Saldırgan sahte makine hesabı oluşturarak RBCD gibi AD saldırılarına zemin hazırlayabilir.',
                    'recommendation':'ms-DS-MachineAccountQuota değerini 0 yapın; makine ekleme yetkisini yalnızca yetkili gruplara verin.',
                    'evidence':'AD_ASSESSMENT.json'})
            admins=ad.get('domain_admins') or {}
            count=admins.get('count')
            if isinstance(count,int) and count>5:
                observations.append({'title':'Fazla sayıda Domain Admin hesabı','severity':'medium','asset':dom,
                    'description':f"{admins.get('group','Domain Admins')} grubunda {count} üye görüldü. Ayrıcalıklı hesap sayısının fazla olması saldırı yüzeyini büyütür.",
                    'impact':'Herhangi bir domain admin hesabının ele geçirilmesi tüm etki alanının ele geçirilmesi anlamına gelir.',
                    'recommendation':'Domain Admins üyeliğini en aza indirin; ayrıcalıklı erişim için katmanlı model ve JIT/PAM yaklaşımını uygulayın.',
                    'evidence':'AD_ASSESSMENT.json'})
            risky=ad.get('risky_accounts') or {}
            def _names_line(items,cap=40):
                items=list(items or [])
                return ', '.join(items[:cap])+(f" (+{len(items)-cap})" if len(items)>cap else '')
            if isinstance(risky,dict):
                if risky.get('asrep_roastable'):
                    n=risky['asrep_roastable']
                    observations.append({'title':'AS-REP roast edilebilir hesaplar (ön-kimlik doğrulama kapalı)','severity':'high','asset':dom,
                        'description':f"{len(n)} hesapta Kerberos ön-kimlik doğrulaması kapalı (DONT_REQ_PREAUTH): {_names_line(n)}.",
                        'impact':'Saldırgan kimlik doğrulamadan bu hesaplar için AS-REP alıp parolayı çevrimdışı kırabilir.',
                        'recommendation':'Bu hesaplarda "Kerberos ön kimlik doğrulaması gerektirme" seçeneğini kapatın; güçlü parola zorunlu kılın.',
                        'evidence':'AD_ASSESSMENT.json'})
                if risky.get('passwd_notreqd'):
                    n=risky['passwd_notreqd']
                    observations.append({'title':'Parola gerektirmeyen hesaplar (PASSWD_NOTREQD)','severity':'high','asset':dom,
                        'description':f"{len(n)} hesapta parola gerekmiyor bayrağı açık: {_names_line(n)}.",
                        'impact':'Bu hesaplar boş/zayıf parolayla ele geçirilebilir.',
                        'recommendation':'PASSWD_NOTREQD bayrağını kaldırın ve parola politikasını uygulayın.',
                        'evidence':'AD_ASSESSMENT.json'})
                if risky.get('reversible_encryption'):
                    n=risky['reversible_encryption']
                    observations.append({'title':'Tersinir şifreleme açık hesaplar','severity':'high','asset':dom,
                        'description':f"{len(n)} hesapta tersinir şifreleme (ENCRYPTED_TEXT_PWD_ALLOWED) açık: {_names_line(n)}.",
                        'impact':'Parolalar geri döndürülebilir biçimde saklanır; DC ele geçirilirse düz metin elde edilir.',
                        'recommendation':'Tersinir şifrelemeyi kapatın ve etkilenen hesapların parolalarını sıfırlayın.',
                        'evidence':'AD_ASSESSMENT.json'})
                if risky.get('unconstrained_delegation'):
                    n=risky['unconstrained_delegation']
                    observations.append({'title':'Kısıtlanmamış yetkilendirme (unconstrained delegation)','severity':'high','asset':dom,
                        'description':f"{len(n)} hesap/kaynakta kısıtlanmamış Kerberos yetkilendirmesi açık: {_names_line(n)}.",
                        'impact':'Bu sistem ele geçirilirse ona kimlik doğrulayan ayrıcalıklı hesapların TGT biletleri toplanabilir.',
                        'recommendation':'Kısıtlanmamış yetkilendirmeyi kaldırın; gerekiyorsa kaynak-tabanlı kısıtlı yetkilendirmeye geçin.',
                        'evidence':'AD_ASSESSMENT.json'})
                if risky.get('password_never_expires'):
                    n=risky['password_never_expires']
                    observations.append({'title':'Parolası hiç bitmeyen hesaplar','severity':'medium','asset':dom,
                        'description':f"{len(n)} hesapta parola hiç bitmiyor (DONT_EXPIRE_PASSWORD): {_names_line(n)}.",
                        'impact':'Kalıcı parolalar sızıntı ve çevrimdışı kırma açısından uzun vadeli risk oluşturur; özellikle servis/ayrıcalıklı hesaplarda kritiktir.',
                        'recommendation':'Servis hesapları için gMSA kullanın; diğer hesaplarda parola yaşlanmasını uygulayın.',
                        'evidence':'AD_ASSESSMENT.json'})
            kerb=ad.get('kerberoastable') or []
            if isinstance(kerb,list) and kerb:
                admins_spn=[k.get('account') for k in kerb if isinstance(k,dict) and k.get('admin')]
                observations.append({'title':'Kerberoast edilebilir servis hesapları (SPN)','severity':'high' if admins_spn else 'medium','asset':dom,
                    'description':f"SPN tanımlı {len(kerb)} kullanıcı hesabı bulundu"+(f"; ayrıcalıklı olanlar: {', '.join(str(x) for x in admins_spn)}" if admins_spn else '')+".",
                    'impact':'Saldırgan bu hesaplar için servis biletleri alıp parolayı çevrimdışı kırabilir; ayrıcalıklı SPN hesabı doğrudan yükseltme sağlar.',
                    'recommendation':'Servis hesaplarında uzun/rastgele parola veya gMSA kullanın; gereksiz SPN’leri kaldırın.',
                    'evidence':'AD_ASSESSMENT.json'})
            if ad.get('ldap_cleartext_bind') is True:
                observations.append({'title':'LDAP imzalama / kanal bağlama zorlanmıyor (şifresiz SIMPLE bağlanma kabul edildi)','severity':'high','asset':str(ad.get('dc',dom)),
                    'description':'DC, 389/TCP üzerinde TLS olmadan SIMPLE LDAP bağlanmayı kabul etti; test hesabı kimlik bilgisi düz metin olarak doğrulandı.',
                    'impact':'Kimlik bilgileri ağda açık taşınır ve DC NTLM relay-to-LDAP saldırılarına açıktır.',
                    'recommendation':'LDAP imzalamayı ve LDAP kanal bağlamayı (channel binding) zorunlu kılın; şifresiz LDAP bağlanmayı reddedin (LDAPS/StartTLS).',
                    'evidence':'AD_ASSESSMENT.json'})
            adcs=ad.get('adcs') or {}
            for esc in (adcs.get('esc') or []):
                if not isinstance(esc,dict):
                    continue
                tag=str(esc.get('esc','ESC'))
                observations.append({'title':f"ADCS {tag}: istismar edilebilir sertifika şablonu ({esc.get('template','?')})",
                    'severity':'high','asset':str((adcs.get('cas') or [{}])[0].get('host',dom)),
                    'description':f"{tag} adayı — {esc.get('detail','')}",
                    'impact':'Düşük yetkili bir kullanıcı, ayrıcalıklı bir kimlik için kimlik-doğrulama sertifikası alarak etki alanı ayrıcalığı kazanabilir.',
                    'recommendation':'Şablonda ENROLLEE_SUPPLIES_SUBJECT (SAN) bayrağını kaldırın, yönetici onayı/RA imzası ekleyin, kayıt ve yazma haklarını yalnızca yetkili gruplara verin; certipy ile doğrulayın.',
                    'evidence':'AD_ASSESSMENT.json'})
            sv=ad.get('sysvol') or {}
            if isinstance(sv,dict) and sv.get('cpassword_count'):
                users=', '.join(str(h.get('username','?')) for h in (sv.get('findings') or [])[:10] if isinstance(h,dict))
                observations.append({'title':'SYSVOL Group Policy Preferences içinde şifre (GPP cpassword)','severity':'critical','asset':str(ad.get('dc',dom)),
                    'description':f"SYSVOL'da {sv['cpassword_count']} adet GPP cpassword bulundu ve Microsoft'un yayımladığı anahtarla düz metne çözüldü. Etkilenen hesaplar: {users}.",
                    'impact':'SYSVOL’u okuyabilen HERHANGİ bir etki alanı kullanıcısı bu parolaları elde edebilir; genellikle yerel yönetici/servis hesabıdır ve yatay harekete olanak verir.',
                    'recommendation':'İlgili GPP nesnelerini kaldırın (MS14-025), açığa çıkan parolaları hemen sıfırlayın; yerel yönetici parolaları için LAPS kullanın.',
                    'evidence':'AD_ASSESSMENT.json'})
            for r in (ad.get('privileged_acl_risks') or [])[:80]:
                if isinstance(r,dict):
                    ot=r.get('object_type','nesne')
                    observations.append({'title':f"AD {ot} üzerinde tehlikeli hak: {r.get('account','?')}",'severity':'high','asset':dom,
                        'description':f"{r.get('principal','?')} — güvenli/Tier-0 principal olmadığı halde {ot} '{r.get('account','?')}' üzerinde '{r.get('right','?')}' hakkına sahip.",
                        'impact':'Bu hak; parola sıfırlama, shadow credentials, RBCD, SPN yazma, gruba kendini ekleme veya DCSync yoluyla ayrıcalık yükseltme/nesne ele geçirme sağlayabilir.',
                        'recommendation':'Bu ACE’yi kaldırın; ayrıcalıklı (Tier-0) nesneler üzerindeki yazma/kontrol haklarını yalnızca yönetici gruplarıyla sınırlayın.',
                        'evidence':'AD_ASSESSMENT.json'})
            for h in (ad.get('privileged_hygiene') or []):
                if isinstance(h,dict) and h.get('enabled') and h.get('never_logged_on'):
                    observations.append({'title':f"Kullanılmayan ayrıcalıklı hesap (hiç oturum açmamış): {h.get('account','?')}",'severity':'medium','asset':dom,
                        'description':f"{h.get('account','?')} ayrıcalıklı bir hesap; etkin ama hiç oturum açmamış (logonCount 0, lastLogon yok)."+(f" Parola yaşı ~{h['pwd_age_days']} gün." if h.get('pwd_age_days') else ''),
                        'impact':'Kullanılmayan ayrıcalıklı hesaplar saldırı yüzeyini büyütür ve fark edilmeden kötüye kullanılabilir.',
                        'recommendation':'Gerekmeyen ayrıcalıklı hesabı devre dışı bırakın/kaldırın; gerekliyse parolayı döndürüp izleyin.',
                        'evidence':'AD_ASSESSMENT.json'})
                elif isinstance(h,dict) and h.get('enabled') and (h.get('pwd_age_days') or 0)>730:
                    observations.append({'title':f"Çok eski parolalı ayrıcalıklı hesap: {h.get('account','?')}",'severity':'medium','asset':dom,
                        'description':f"{h.get('account','?')} ayrıcalıklı hesabının parolası ~{h['pwd_age_days']} gündür değişmemiş.",
                        'impact':'Uzun ömürlü ayrıcalıklı parolalar sızıntı ve çevrimdışı kırma açısından yüksek risklidir.',
                        'recommendation':'Ayrıcalıklı hesap parolalarını düzenli döndürün; servis hesapları için gMSA kullanın.',
                        'evidence':'AD_ASSESSMENT.json'})
            for d in (ad.get('description_password_candidates') or []):
                if isinstance(d,dict):
                    observations.append({'title':f"AD açıklama alanında olası parola: {d.get('account','?')}",'severity':'high','asset':dom,
                        'description':f"{d.get('account','?')} hesabının description alanı parola içeriyor olabilir: \"{d.get('description','')}\".",
                        'impact':'Description/info alanları tüm etki alanı kullanıcıları tarafından okunabilir; buradaki bir parola doğrudan kimlik ele geçirmeye yol açar.',
                        'recommendation':'Açıklama alanındaki parolayı kaldırın ve ilgili hesabın parolasını hemen sıfırlayın; personeli bilgilendirin.',
                        'evidence':'AD_ASSESSMENT.json'})
            for x in (ad.get('constrained_delegation') or [])[:30]:
                if isinstance(x,dict):
                    observations.append({'title':f"Kısıtlı Kerberos yetkilendirmesi ({x.get('account','?')})",'severity':'high' if x.get('protocol_transition') else 'medium','asset':dom,
                        'description':f"{x.get('account','?')} şu hedeflere yetkilendirilmiş: {', '.join(x.get('targets',[])[:6])}."+(' Protokol geçişi (T2A4D) açık.' if x.get('protocol_transition') else ''),
                        'impact':'Hesap ele geçirilirse hedef servislere başka kullanıcılar adına erişilebilir; T2A4D açıkken herhangi bir kullanıcı (yönetici dahil) taklit edilebilir.',
                        'recommendation':'Gereksiz delegasyonu kaldırın; protokol geçişi yerine kaynak-tabanlı kısıtlı yetkilendirme kullanın; hassas hesapları Protected Users’a ekleyin.',
                        'evidence':'AD_ASSESSMENT.json'})
            if ad.get('rbcd_configured'):
                observations.append({'title':'RBCD yapılandırılmış hesaplar','severity':'medium','asset':dom,
                    'description':'msDS-AllowedToActOnBehalfOfOtherIdentity ayarlı hesaplar: '+', '.join(list(ad['rbcd_configured'])[:20])+'.',
                    'impact':'Yanlış yapılandırılmış kaynak-tabanlı kısıtlı yetkilendirme, bir bilgisayar hesabı üzerinden ayrıcalıklı taklide olanak verebilir.',
                    'recommendation':'RBCD kayıtlarını doğrulayın; beklenmeyen/işlevsiz olanları kaldırın.',
                    'evidence':'AD_ASSESSMENT.json'})
    # --- VMware vSphere/vCenter kimliksiz sürüm ifşası ---
    for path in sorted((root/'targets').glob('*/raw/vmware_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict) or not (item.get('version') or item.get('product')):
            continue
        observations.append({'title':'VMware vSphere / vCenter kimliksiz sürüm ifşası','severity':'medium','asset':str(item.get('target','')),
            'description':f"{item.get('product','VMware vSphere')} sürüm {item.get('version','?')}"+(f" build {item.get('build')}" if item.get('build') else '')+" — vSphere Web Services SDK, kimlik doğrulamadan sürüm/derleme bilgisini açıkladı.",
            'impact':'Kesin derleme numarası, o sürüme özgü bilinen CVE’lerin (ör. vCenter RCE zincirleri) hedeflenmesini kolaylaştırır.',
            'recommendation':'vCenter/ESXi’yi desteklenen ve yamalı sürüme güncelleyin; yönetim arayüzlerine erişimi yönetim ağıyla sınırlayın.',
            'evidence':str(path.relative_to(root))})
    # --- Cihaz ailesi kimlik/sürüm ifşası (FortiGate, Webmin, iLO/iDRAC BMC, Synology/QNAP NAS) ---
    _APP_META={
        'ilo':('HPE iLO (BMC)',True,'Sunucu dışı-bant yönetim denetleyicisi (BMC) ele geçirilirse fiziksel sunucunun tamamı (güç, konsol, sanal medya) kontrol edilebilir; kesin firmware bilinen BMC açıklarını (ör. kimlik doğrulama atlatma) hedeflemeyi kolaylaştırır.'),
        'idrac':('Dell iDRAC (BMC)',True,'Sunucu dışı-bant yönetim denetleyicisi (BMC) ele geçirilirse fiziksel sunucunun tamamı kontrol edilebilir; kesin firmware bilinen iDRAC açıklarını hedeflemeyi kolaylaştırır.'),
        'synology':('Synology DSM (NAS)',False,'NAS verisine ve yönetimine yönelik saldırılarda kesin DSM sürümü bilinen açıkların hedeflenmesini kolaylaştırır.'),
        'qnap':('QNAP QTS (NAS)',False,'QTS geçmişte kimliksiz uzaktan kod çalıştırma açıklarına sahip oldu; kesin sürüm/derleme bilinen açıkların hedeflenmesini kolaylaştırır.'),
        'webmin':('Webmin (MiniServ)',False,'Belirli Webmin sürümleri kritik uzak kod çalıştırma (RCE) açıklarına sahiptir; kesin sürüm hedeflemeyi kolaylaştırır.'),
    }
    for path in sorted((root/'targets').glob('*/raw/appliance_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict):
            continue
        ip=str(item.get('target',''))
        rel=str(path.relative_to(root))
        for key,(label,is_bmc,impact) in _APP_META.items():
            a=item.get(key) or {}
            if not isinstance(a,dict) or not a.get('product'):
                continue
            ver=a.get('version') or ''
            extra=(f" sürüm {ver}" if ver else '')+(f" (build {a['build']})" if a.get('build') else '')
            extra+=(f", sunucu modeli {a['server_model']}" if a.get('server_model') else '')+(f", seri no {a['serial']}" if a.get('serial') else '')
            observations.append({'title':f"{label} kimliksiz kimlik/sürüm ifşası"+(' (BMC)' if is_bmc else ''),
                'severity':'medium' if ver else 'low','asset':ip,
                'description':f"{a['product']}{extra} — {a.get('evidence','web arayüzü')} kimlik doğrulamadan kimlik/sürüm bilgisini açıkladı"+(f" (port {a['port']})" if a.get('port') else '')+".",
                'impact':impact,
                'recommendation':f"{label.split(' (')[0]} yönetim arayüzünü ayrı/güvenilir yönetim ağıyla sınırlayın; mümkünse kimliksiz veri ifşasını kapatın; en güncel firmware/sürüme yükseltin.",
                'evidence':rel})
        fg=item.get('fortigate') or {}
        if fg.get('product'):
            observations.append({'title':'FortiGate yönetim/SSL-VPN arayüzü'+(' + sürüm ifşası' if fg.get('version') else ''),'severity':'medium' if fg.get('version') else 'low','asset':ip,
                'description':f"{fg['product']} tespit edildi (port {fg.get('port',443)})."+(f" FortiOS sürümü: {fg['version']}." if fg.get('version') else ' FortiOS sürümü gizli.'),
                'impact':'Erişilebilir FortiGate yönetim veya SSL-VPN arayüzü, bilinen FortiOS açıkları (ör. kimlik doğrulama atlatma/RCE) için birincil hedeftir.',
                'recommendation':'Yönetim arayüzünü güvenilir ağlarla sınırlayın (trusted hosts); gerekmiyorsa SSL-VPN’i kapatın; FortiOS’u yamalı tutun.',
                'evidence':rel})
    # --- Ağ cihazı (firewall/switch/AP/router/NAS) kimliksiz kimlik ve sürüm ifşası ---
    for path in sorted((root/'targets').glob('*/raw/netdev_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict) or not item.get('brand'):
            continue
        ver=item.get('version') or ''
        observations.append({'title':f"Ağ cihazı kimliksiz tespit{' + sürüm ifşası' if ver else ''}: {item.get('brand','?')}",'severity':'medium' if ver else 'low','asset':str(item.get('target','')),
            'description':f"{item.get('brand','?')} yönetim arayüzü kimlik doğrulamadan tespit edildi (port {item.get('port','?')}, {item.get('path','')})."+(f" Sürüm/derleme: {ver}." if ver else ' Sürüm sızmadı.'),
            'impact':'Erişilebilir cihaz yönetim arayüzü, bilinen üretici açıkları için birincil hedeftir; kesin sürüm/derleme, o sürüme özgü CVE’lerin hedeflenmesini kolaylaştırır.',
            'recommendation':'Yönetim arayüzünü ayrı/güvenilir yönetim ağıyla sınırlayın; güçlü kimlik doğrulama uygulayın; firmware’i güncel tutun.',
            'evidence':str(path.relative_to(root))})
    # --- SMB paylaşım envanteri: düşük yetkili yazılabilir paylaşımlar ---
    for path in sorted((root/'targets').glob('*/raw/share_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict):
            continue
        ip=str(item.get('target',''))
        for rec in (item.get('non_default') or []):
            if isinstance(rec,dict) and rec.get('low_priv_writable'):
                observations.append({'title':f"Düşük yetkili yazılabilir SMB paylaşımı ({rec.get('share','?')})",'severity':'high','asset':ip,
                    'description':f"\\\\{ip}\\{rec.get('share','?')} paylaşımı düşük yetkili bir principal'a yazma izni veriyor: {', '.join(rec['low_priv_writable'][:6])}.",
                    'impact':'Herhangi bir etki alanı kullanıcısı bu paylaşıma dosya yazabilir; kötü amaçlı içerik dağıtımı, logon script/GPP değişikliği ve yatay hareket için kullanılabilir.',
                    'recommendation':'Paylaşım ve NTFS izinlerini en az ayrıcalık ilkesine göre daraltın; yazma iznini yalnızca gereken gruplara verin.',
                    'evidence':str(path.relative_to(root))})
    # --- Opt-in sqlmap (yetkili SQL enjeksiyon testi) sonuçları ---
    for path in sorted((root/'targets').glob('*/raw/sqlmap_result_*.json')) if (root/'targets').exists() else []:
        try:
            item=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError,TypeError):
            continue
        if not isinstance(item,dict) or not item.get('injectable'):
            continue
        params=', '.join(item.get('parameters',[])) or 'parametre kaydı yok'
        observations.append({'title':'SQL enjeksiyonu belirtisi (sqlmap)','severity':'high',
            'asset':str(item.get('ip','')),
            'description':f"sqlmap {item.get('url','')} üzerinde enjekte edilebilir nokta işaretledi. Parametre(ler): {params}. Arka uç DBMS: {item.get('dbms') or 'bilinmiyor'}. Otomatik sonuç; analist manuel doğrulamalıdır.",
            'impact':'Doğrulanırsa veritabanına yetkisiz erişim, veri ifşası veya değişikliği mümkün olabilir.',
            'recommendation':'Parametreli sorgu/ORM kullanın, girdi doğrulama ve en az yetkili DB hesabı uygulayın; WAF telafi edici olabilir ama kök çözüm değildir.',
            'evidence':str(path.relative_to(root))})
    # Group identical observations across hosts into ONE finding with an affected-
    # assets list (professional "Zafiyeti Barındıran Sistemler" style) instead of an
    # OBS card per host — otherwise a service seen on 30 hosts yields 30 near-identical
    # high/medium cards and drowns the real signal.
    grouped={}
    for item in observations:
        key=(item['title'],item['severity'])
        if key not in grouped:
            entry=dict(item)
            entry['_assets']=[item['asset']] if item.get('asset') else []
            grouped[key]=entry
        else:
            entry=grouped[key]
            if item.get('asset') and item['asset'] not in entry['_assets']:
                entry['_assets'].append(item['asset'])
            if item.get('evidence') and item['evidence'] not in entry['evidence']:
                entry['evidence']+='; '+item['evidence']
    for i, entry in enumerate(grouped.values(),1):
        assets=entry.pop('_assets',[])
        primary=entry.get('asset') or (assets[0] if assets else '')
        others=[a for a in assets if a!=primary]
        entry['asset']=primary
        entry['affected_assets']=others
        if others:
            shown=assets[:60]
            entry['description']=(entry.get('description','')
                +f"\n\nAynı bulgu {len(assets)} varlıkta görüldü: "+', '.join(shown)
                +(f" (+{len(assets)-60} daha)" if len(assets)>60 else ''))
        findings.append({'id':f'OBS-{i:03d}','status':'taslak','source':'Otomatik gözlem',
                         'reference':'','cvss':'','cwe':infer_cwe(entry),**entry})
    for i,item in enumerate(review.get('findings',[]),1):
        if not isinstance(item,dict): continue
        finding={'id':str(item.get('id') or f'PX-{i:03d}'),'type':str(item.get('type') or '').lower(), 'title':str(item.get('title') or 'Başlıksız bulgu'), 'severity':str(item.get('severity') or 'info').lower(), 'status':str(item.get('status') or 'taslak').lower(), 'asset':str(item.get('asset') or ''), 'affected_assets':[str(x) for x in item.get('affected_assets',[]) if isinstance(x,str)] if isinstance(item.get('affected_assets',[]),list) else [], 'description':str(item.get('description') or ''), 'impact':str(item.get('impact') or ''), 'recommendation':str(item.get('recommendation') or ''), 'evidence':str(item.get('evidence') or ''), 'evidence_sha256':str(item.get('evidence_sha256') or ''), 'evidence_items':item.get('evidence_items',[]) if isinstance(item.get('evidence_items',[]),list) else [], 'reference':str(item.get('reference') or ''), 'cvss':str(item.get('cvss') or ''), 'cwe':str(item.get('cwe') or ''), 'reproduction':str(item.get('reproduction') or ''), 'reviewed_by':str(item.get('reviewed_by') or ''), 'category':str(item.get('category') or ''), 'access_point':str(item.get('access_point') or ''), 'user_profile':str(item.get('user_profile') or ''), 'root_cause':str(item.get('root_cause') or ''), 'remediation_priority':str(item.get('remediation_priority') or ''), 'retest_status':str(item.get('retest_status') or ''), 'disposition_reason':str(item.get('disposition_reason') or ''), 'source':'Analist'}
        if finding['severity'] not in SEVERITIES: finding['severity']='info'
        if finding['status'] not in ('doğrulandı','taslak','yanlış pozitif','risk kabul edildi'): finding['status']='taslak'
        if finding['status']=='doğrulandı' and not verified_finding(root,item):
            finding['status']='taslak'
            finding['description'] += '\nKanıt / doğrulama alanları eksik veya dosya özeti değişmiş; doğrulandı sayılmadı.'
        if not finding['cwe']:
            finding['cwe']=infer_cwe(finding)
        findings.append(finding)
    # Merge Claude AI-operator findings (drafts; human 'doğrulandı' stays a higher bar).
    ai_path=root/'AI_FINDINGS.json'
    if ai_path.is_file():
        try:
            ai_data=json.loads(ai_path.read_text(encoding='utf-8'))
        except (ValueError,OSError):
            ai_data={}
        for item in ai_data.get('findings',[]) if isinstance(ai_data,dict) else []:
            if not isinstance(item,dict) or not item.get('title'): continue
            sev=str(item.get('severity','info')).lower()
            findings.append({'id':str(item.get('id') or 'AI-000'),'type':'','title':str(item.get('title'))[:160],
                'severity':sev if sev in SEVERITIES else 'info','status':'taslak',
                'asset':str(item.get('asset') or ''),'affected_assets':[],
                'description':str(item.get('description') or '')+(f"\n[AI güven: %{item.get('ai_confidence')}]" if item.get('ai_confidence') is not None else ''),
                'impact':str(item.get('impact') or ''),'recommendation':str(item.get('recommendation') or ''),
                'evidence':str(item.get('evidence') or ''),'evidence_sha256':'','evidence_items':[],
                'reference':'','cvss':str(item.get('cvss') or ''),'cwe':str(item.get('cwe') or '')or infer_cwe(item),
                'reproduction':'','reviewed_by':'','category':str(item.get('category') or ''),
                'access_point':'','user_profile':'','root_cause':'','remediation_priority':'',
                'retest_status':'','disposition_reason':'','source':'AI (otomatik analiz)'})
    findings.sort(key=lambda f:(list(SEVERITIES).index(f['severity']),f['id']))
    return meta,steps,hosts,findings,review


def audit_recorded_steps(root, steps):
    """Correct old zero-exit tool failures in reports; preserve the original log."""
    corrected=[]
    changes=[]
    base=root.resolve()
    for original in steps:
        if not isinstance(original,dict):
            corrected.append(original)
            continue
        item=dict(original)
        output=str(item.get('output',''))
        relative=Path(output)
        path=base/relative
        sample=''
        if (output and not relative.is_absolute() and '..' not in relative.parts and
                path.resolve().is_relative_to(base) and path.is_file() and not path.is_symlink()):
            with path.open('rb') as handle:
                sample=handle.read(65536).decode('utf-8','replace')
        tool=item.get('tool')
        if tool=='nikto' and item.get('status')=='ok' and (
                'invalid for option' in sample.lower() or 'unknown option' in sample.lower()):
            item.update(status='error',detail='Nikto secenek hatasi; onceki sifir cikis kodu testi tamamlamadi')
        elif tool=='nuclei' and item.get('status')=='ok':
            errors=[line for line in sample.splitlines() if re.search(r'\bERR\b',
                re.sub(r'\x1b\[[0-9;]*m','',line))]
            if errors:
                config_only=all('Could not read nuclei-ignore file' in line for line in errors)
                item.update(status='warning' if config_only else 'partial',
                    detail='Nuclei ignore dosyasi eksik; sablonlar calisti' if config_only
                    else 'Nuclei hata satirlari verdi; cikti incelenmeli')
        elif tool=='fping' and item.get('status')=='error' and item.get('exit_code')==1:
            item.update(status='no_response',detail='ICMP yaniti yok; TCP servis bulgulari bundan etkilenmez')
        elif tool=='curl' and item.get('exit_code') in (52,60) and not item.get('detail'):
            item['detail']=('TLS sertifikasi istenen IP/alan adiyla eslesmiyor' if
                item['exit_code']==60 else 'Baglanti kuruldu fakat HTTP yaniti bos')
        if (item.get('status'),item.get('detail'))!=(original.get('status'),original.get('detail')):
            changes.append({'step':str(item.get('step','')),'original_status':original.get('status'),
                'report_status':item.get('status'),'reason':item.get('detail'),
                'evidence':output,'evidence_sha256':item.get('sha256','')})
        corrected.append(item)
    return corrected,changes

def footer(canvas,doc):
    if getattr(doc,'_ubden_cover',False) and doc.page==1:
        V.cover_backdrop(canvas,*A4,'DV',footer_left='UBDEN CYBER SECURITY SYSTEMS',
                         footer_right='GİZLİ · YETKİLİ ALICILAR')
        return
    canvas.saveState()
    w,h=A4
    canvas.setStrokeColor(TEAL);canvas.setLineWidth(1)
    canvas.line(18*mm,h-17*mm,w-18*mm,h-17*mm)
    canvas.setFont('DV',8);canvas.setFillColor(GRAY)
    canvas.drawString(18*mm,13*mm,'UBDEN CYBER SECURITY SYSTEMS  |  GIZLI - YETKILI ALICILAR')
    canvas.drawRightString(w-18*mm,13*mm,f'Sayfa {doc.page}')
    canvas.restoreState()

def analyst_pdf(root, filename, plan, meta):
    st=styles()
    doc=ReportDocument(str(root/filename),pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,
        topMargin=23*mm,bottomMargin=22*mm,title='UBDEN | Analist Çalışma Raporu',
        author=meta.get('tester') or 'UBDEN test ekibi')
    frame=Frame(doc.leftMargin,doc.bottomMargin,doc.width,doc.height,id='normal')
    doc.addPageTemplates(PageTemplate(id='main',frames=frame,onPage=footer))
    story=[Spacer(1,16*mm)]
    if logo():
        from PIL import Image as PILImage
        with PILImage.open(logo()) as im:
            ratio=im.height/im.width
        story += [Image(str(logo()),width=60*mm,height=min(60*mm*ratio,25*mm)),Spacer(1,20*mm)]
    story += [P('Analist Çalışma Raporu',st['CoverTitleX']),
              HRFlowable(width='100%',thickness=3,color=TEAL,spaceAfter=14)]
    for label,value in [('MÜŞTERİ',plan['client']),('GÖREV',plan['project']),
                        ('TEST EKİBİ',meta.get('tester')),('YETKİ REFERANSI',meta.get('authorization_reference')),
                        ('KAYIT',plan['engagement_id']),('RAPOR TARİHİ',plan['generated_at'])]:
        story += [P(label,st['LabelX']),P(value,st['ValueX'])]
    story += [Spacer(1,8*mm),P('GİZLİ • Yalnızca yetkili müşteri ve test ekibi',st['NoticeX']),PageBreak(),
              P('Çalışma durumu',st['SectionX']),P(plan['note'],st['BodyX']),
              P(f"Gözlenen adres: {plan['observed_hosts']} · Web: {plan['observed_web_hosts']} · "
                f"Paylaşım: {plan['observed_share_hosts']} · Veritabanı: {plan['observed_database_hosts']} · "
                f"Bekleyen analist adımı: {plan['pending_count']}",st['BodyX']),
              P('Kapsam: '+(', '.join(plan['scope']) or 'Kayıt yok'),st['SmallX']),
              P('Komutlardaki yer tutucuları yazılı kapsamda bulunan hedeflerle değiştirin. Parola/tokenu komuta veya rapora yazmayın. Canlı giriş ekranında sözlük denemesi yapmayın.',st['NoticeX'])]
    rows=[[P(x,st['SmallWhiteX']) for x in ('Öncelik','Görev','Durum','Hedef')]]
    for task in plan['tasks']:
        rows.append([P(task['priority'],st['SmallX']),P(task['id']+' · '+task['title'],st['SmallX']),
                     P(task['status'],st['SmallX']),P(', '.join(task['targets'][:3]),st['SmallX'],limit=130)])
    story += [P('Öncelik sırası',st['SectionX']),grid_table(rows,[doc.width*.12,doc.width*.43,doc.width*.16,doc.width*.29]),PageBreak()]
    for task in plan['tasks']:
        story += [P(task['id']+' · '+task['title'],st['SectionX']),
                  P(f"{task['priority']} · {task['status']} · {task['case']}",st['SmallX']),
                  P('İlgili varlık: '+(', '.join(task['targets']) or 'müşteri bilgisi bekleniyor'),st['BodyX']),
                  P('Tetikleyen kayıt: '+task['trigger'],st['BodyX'])]
        if task['customer_input']:
            story.append(P('Müşteriden gereken: '+task['customer_input'],st['NoticeX']))
        if task['review_note']:
            story.append(P('Analist notu: '+task['review_note'],st['SmallX']))
        story.append(P('Uygulanacak adımlar',st['SubX']))
        for index,item in enumerate(task['steps'],1):
            story.append(P(f'{index}. {item}',st['BodyX']))
        story.append(P('Alınacak kanıt',st['SubX']))
        for item in task['evidence_required']:
            story.append(P('• '+item,st['BodyX']))
        if task['commands']:
            story.append(P('Örnek komutlar',st['SubX']))
            for command in task['commands']:
                story.append(P(command,st['SmallX'],limit=450))
        if task['source_evidence']:
            story.append(P('Mevcut görev kanıtı: '+'; '.join(task['source_evidence']),st['SmallX']))
        story.append(P(task['completion'],st['SmallX']))
    doc.build(story)

class ReportDocument(BaseDocTemplate):
    def beforeDocument(self):
        self._section_index=0

    def afterFlowable(self,flowable):
        if isinstance(flowable,Paragraph) and flowable.style.name=='SectionX':
            self._section_index+=1
            key=f'ubden-section-{self._section_index}'
            self.canv.bookmarkPage(key)
            self.notify('TOCEntry',(0,flowable.getPlainText(),self.page,key))

def pdf(root, filename, meta, steps, hosts, findings, review, executive=False):
    st=styles()
    doc=ReportDocument(str(root/filename),pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=23*mm,bottomMargin=22*mm,title='UBDEN Cyber Security Systems | Güvenlik Değerlendirmesi',author=meta.get('tester') or 'Test ekibi belirtilmedi')
    frame=Frame(doc.leftMargin,doc.bottomMargin,doc.width,doc.height,id='normal')
    doc.addPageTemplates(PageTemplate(id='main',frames=frame,onPage=footer))
    doc._ubden_cover=True  # footer, 1. sayfaya koyu siber kapak zeminini çizer
    story=[Spacer(1,30*mm),
           P('UBDEN',st['CoverBrandX']),P('CYBER SECURITY SYSTEMS',st['CoverBrandSubX']),
           P('Yönetici Özeti' if executive else 'Teknik Güvenlik Değerlendirme Raporu',st['CoverTitleLightX']),
           HRFlowable(width='100%',thickness=3,color=TEAL,spaceAfter=14)]
    for key,value in [('MÜŞTERİ',meta.get('client')),('PROJE',meta.get('project')),('ÜRÜN',meta.get('product','UBDEN Cyber Security Systems')),('RAPOR TARİHİ',meta.get('finished_at',meta.get('started_at'))),('YETKİ REFERANSI',meta.get('authorization_reference')),('TEST SORUMLUSU',meta.get('tester')),('KAYIT KİMLİĞİ',meta.get('id'))]:
        story += [P(key,st['CoverLabelLightX']),P(value,st['CoverValueLightX'])]
    story += [Spacer(1,6*mm),P('GİZLİ • Müşteri ve görevlendirilmiş ekip ile sınırlı dağıtım',st['CoverNoticeLightX']),PageBreak()]
    toc=TableOfContents()
    toc.levelStyles=[st['TOCEntryX']]
    story.extend([P('İçindekiler',st['TOCTitleX']),
                  P('Aşağıdaki bölümler yalnız bu görevde kaydedilen kapsam ve kanıtlara göre oluşturulur.',st['BodyX']),
                  toc,PageBreak()])
    confirmed=[f for f in findings if f['status']=='doğrulandı']
    state=assess(root,review)
    pending=[f for f in findings if f['status']=='taslak']
    counts=Counter(f['severity'] for f in confirmed)
    story.append(P('Değerlendirme sınırları',st['SectionX']))
    story.append(P('Manuel pentest kaydı: '+('analist tarafından tamamlandı ve incelendi' if state['complete'] else 'eksik / inceleme bekliyor')+f". Bekleyen başlık: {state['pending']}. Kayda giren inceleyen: {state['reviewer'] or 'yok'}.",st['NoticeX']))
    story.append(P('Bu rapor kayıtlı otomatik kontrolleri ve analist tarafından ayrı olarak eklenen bulguları içerir. Açık portlar tek başına güvenlik açığı sayılmaz. Otomatik çıktıların yokluğu, güvenlik açığı bulunmadığı anlamına gelmez. Full profili de manuel penetrasyon testinin tamamlandığı anlamına gelmez.',st['BodyX']))
    story.append(P(f"Çalışma durumu: {meta.get('status','bilinmiyor')} • Başlangıç: {meta.get('started_at','')} • Bitiş: {meta.get('finished_at','')}",st['BodyX']))
    story.append(P('Yetkili hedefler: '+', '.join(meta.get('targets',[])),st['BodyX']))
    story.append(P('Hariç tutulanlar: '+(', '.join(meta.get('exclusions',[])) or 'Tanımlanmadı'),st['BodyX']))
    for line in platform_lines(root,meta,steps):
        if line.startswith(('Windows adaptörleri:', 'Seçilen Windows ağ yolları:')) and network_rows(meta):
            continue
        story.append(P(line,st['SmallX']))
    profile=meta.get('profile','external')
    coverage={'external':'DNS, servis keşfi, HTTP başlıkları, TLS','web':'Web portları, HTTP başlıkları, OPTIONS, TLS','network':'Servis keşfi, seçilmiş Nmap NSE kontrolleri','full':'DNS, servis, HTTP, TLS, OPTIONS ve seçilmiş NSE kontrolleri'}.get(profile,'Bilinmiyor')
    story.append(P(f'Planlanan otomatik profil ({profile}): {coverage}. Gerçek yürütme durumu aşağıdaki kontrol matrisinde gösterilir. Manuel test kayıtları: '+('tamamlandı' if state['complete'] else 'eksik veya inceleme bekliyor')+'.',st['BodyX']))
    story.extend(network_story(meta,st,doc.width))
    story.extend(ad_story(root,st,doc.width))
    story.extend(coverage_story(root,meta,steps,review,st,doc.width,executive))
    insights=json.loads((root/'UBDEN_INSIGHTS.json').read_text(encoding='utf-8')) if (root/'UBDEN_INSIGHTS.json').is_file() else {}
    preflight=json.loads((root/'PREFLIGHT.json').read_text(encoding='utf-8')) if (root/'PREFLIGHT.json').is_file() else {}
    if preflight:
        story.append(P('Görev ön kontrolü',st['SectionX']))
        story.append(P(f"Durum: {preflight.get('status', '?')}. {preflight.get('note', '')}",st['BodyX']))
        for item in preflight.get('checks',[])[:12]:
            story.append(P(f"{item.get('name','?')}: {item.get('status','?')} · {item.get('detail','')}",st['SmallX'],limit=300))
    if insights:
        story.append(P('Teknik eşleme ve düzeltme yol haritası',st['SectionX']))
        story.append(P(insights.get('meaning',''),st['BodyX']))
        story.append(P(f"ATT&CK eşlemesi: {len(insights.get('attck',[]))} kayıt. CVSS taslağı: {len(insights.get('cvss_suggestions',[]))}. Öncelikli düzeltme: {len(insights.get('remediation',[]))}. Çevrimdışı örnek: {len(insights.get('hash_samples',{}).get('files',[]))} dosya.",st['BodyX']))
        if not executive:
            for item in insights.get('attck',[])[:12]:
                story.append(P(f"{item['techniqueID']} · {item['techniqueName']} — {item['source']} ({item['status']})",st['SmallX']))
            for item in insights.get('cvss_suggestions',[])[:12]:
                story.append(P(f"CVSS önerisi {item['finding_id']}: {item['vector']} / {item['base_score']} · analist incelemesi gerekli",st['SmallX']))
        for item in insights.get('remediation',[])[:8]:
            story.append(P(f"{', '.join(item['findings'])} · {', '.join(item['assets'][:3])}: {item['recommendation']}",st['SmallX'],limit=420))
        story.append(P('Ayrıntılar: UBDEN_INSIGHTS.json, ATTACK_LAYER.json ve REMEDIATION_ROADMAP.md.',st['SmallX']))
    discovery=discovery_summaries(root)
    if discovery:
        story.append(P('CIDR host keşfi',st['SectionX']))
        for item in discovery:
            story.append(P(discovery_line(item),st['BodyX']))
    snmp=snmp_summaries(root)
    if snmp:
        story.append(P('SNMPv1 / public doğrulaması',st['SectionX']))
        for item in snmp:
            story.append(P(f"{item.get('target')}: {item.get('tested_count',0)} adrese tek salt okunur sorgu, {item.get('responding_count',0)} doğrulanmış yanıt. Kanıt: {item.get('evidence')}. Yanıtsız adreslerde SNMP'nin kapalı olduğu sonucuna varılmaz.",st['BodyX']))
            for device in item.get('responding',[])[:15]:
                story.append(P(f"Yanıt veren: {device.get('ip')} | Kanıt: {device.get('evidence')}",st['SmallX']))
    devices=device_inventory(root)
    if devices:
        story.append(P('Cihaz ve MAC analizi',st['SectionX']))
        story.append(P(f"{devices.get('host_count',0)} adres; MAC görülen {devices.get('mac_count',0)}; sınıfı belirsiz {devices.get('unknown_count',0)}. Kategoriler: "+', '.join(f'{label}: {count}' for label,count in devices.get('categories',{}).items()),st['BodyX']))
        for item in devices.get('local_interface_addresses',[]):
            story.append(P(f"Test bilgisayarı: {item['ip']} ({item['adapter']}); {item['status']}. Bu adres, yalnız Windows adaptör kaydıyla servis taraması yapılmış sayılmaz.",st['SmallX']))
        if devices.get('role_counts_lower_bound'):
            story.append(P('Gözlenen rol adaylarının alt sınırı: '+', '.join(f'{label}: {count}' for label,count in devices['role_counts_lower_bound'].items())+'. Güvenlik duvarı kimliği: '+devices.get('firewall_identity_status','doğrulanmadı')+'.',st['BodyX']))
        story.append(P(devices.get('limits',''),st['SmallX']))
        if devices.get('mac_count',0)==0:
            story.append(P('MAC görülmedi: hedefler yönlendirici arkasında olabilir; üretici/model bu raporda doğrulanmadı.',st['SmallX']))
        flagged=[item for item in devices['devices'] if item.get('notices') or item.get('review_notes')]
        story.append(P(f'MAC belirsizliği veya hizmet inceleme notu bulunan adres: {len(flagged)}. Bu işaretler doğrulanmış zafiyet değildir.',st['BodyX']))
        named=[item for item in devices['devices']
               if item.get('display_name') or item.get('hostnames')]
        if named:
            story.append(P('Hostname envanteri',st['SubX']))
            rows=[[P(x,st['SmallWhiteX']) for x in ('IP adresi','Hostname','Sınıf / MAC')]]
            for item in named[:60]:
                name=item.get('display_name') or (item.get('hostnames') or [''])[0] or '—'
                klass=(item.get('category') or item.get('category_key') or '—')
                rows.append([P(item.get('ip','—'),st['SmallX'],limit=48),
                             P(name,st['SmallX'],limit=90),
                             P(f"{klass}\n{item.get('mac') or 'MAC yok'}",st['SmallX'],limit=90)])
            story.append(grid_table(rows,[doc.width*.26,doc.width*.42,doc.width*.32]))
            if len(named)>60:
                story.append(P(f'... ve {len(named)-60} adres daha; tümü DEVICE_INVENTORY.json içinde.',st['SmallX']))
    if meta.get('auth_probes'):
        story.append(P(auth_summary(meta,steps),st['BodyX']))
    role_note,ai_note,ai_text=advanced_summary(root,meta,steps)
    if meta.get('role_scenarios') or any(str(s.get('step','')).startswith('role_') for s in steps):
        story.append(P(role_note,st['BodyX']))
    if (root/'AI_DURUM.json').is_file():
        story.append(P(ai_note,st['BodyX']))
    if ai_text:
        story.append(P('Claude AI analist yorumu — yalnızca taslak',st['SubX']))
        story.append(P(ai_text,st['BodyX'],limit=1200))
    if executive:
        tool_status=tool_rows(root,steps)
        if tool_status:
            story.append(P(f'Araç durumu: {sum(x[2]=="Çalıştırıldı" for x in tool_status)} araç için en az bir adım başlatıldı; başarılı ve başarısız adımlar çalışma günlüğünde ayrıdır.',st['BodyX']))
    if meta.get('nuclei_templates'):
        story.append(P(f"Nuclei şablon kaynağı: {meta.get('nuclei_profile','custom')} | {meta.get('nuclei_template_count','?')} şablon. Sabit içerik özeti nuclei_template_manifest.json içinde kayıtlıdır. Adım durumunu günlükten kontrol edin; eşleşmeler analist doğrulaması bekler.",st['BodyX']))
    story.append(P('Doğrulanmış bulgular',st['SectionX']))
    posture=max(0,100-(counts['critical']*25+counts['high']*12+counts['medium']*5+counts['low']*2))
    grade=V.grade_for_score(posture)
    tiles=[(str(counts['critical']),'Kritik',V.SEVERITY_COLORS['critical']),
           (str(counts['high']),'Yüksek',V.SEVERITY_COLORS['high']),
           (str(counts['medium']),'Orta',V.SEVERITY_COLORS['medium']),
           (str(counts['low']),'Düşük',V.SEVERITY_COLORS['low']),
           (str(len(confirmed)),'Doğrulanmış',NAVY)]
    story.append(V.stat_tiles(tiles,doc.width,'DVB','DV'))
    story.append(Spacer(1,5*mm))
    if confirmed:
        gauge=V.donut_gauge(posture,grade,'DVB','DV',size=34*mm,caption='NOT')
        narrative=P('Doğrulanmış bulgulara göre güvenlik duruşu skoru <b>%d/100</b> (Not %s). '
                    'Skor kritik/yüksek bulgu sayısıyla düşer ve yalnız analistçe doğrulanmış '
                    'bulguları yansıtır; otomatik gözlem adaylarını değil.'%(posture,grade),st['BodyX'])
        row=Table([[gauge,narrative]],colWidths=[40*mm,doc.width-40*mm])
        row.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                                 ('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(0,0),4*mm)]))
        story += [row,Spacer(1,4*mm),
                  V.hbars([(SEVERITIES[k],counts[k],V.SEVERITY_COLORS[k]) for k in SEVERITIES],
                          doc.width,st['SmallX'],st['ValueX']),Spacer(1,3*mm)]
        top=sorted(confirmed,key=lambda f:list(SEVERITIES).index(f['severity']))[:3]
        if top:
            story.append(P('Öne çıkan doğrulanmış riskler: '+'; '.join(
                f"{f['id']} · {SEVERITIES.get(f['severity'],'Bilgi')} · {f['title']} ({f.get('asset') or '—'})"
                for f in top),st['SmallX']))
    else:
        story.append(P('Analist tarafından doğrulanmış bulgu bulunmuyor; aşağıdaki gözlemler inceleme adayıdır.',st['BodyX']))
    _done=sum(s.get("status")=="ok" for s in steps)
    _hard=sum(s.get("status") in ("error","timeout","blocked") for s in steps)
    _benign=sum(s.get("status") in ("no_response","review","skipped","missing_tool","not_applicable","excluded","mismatch") for s in steps)
    story.append(P(f'Doğrulanmayı bekleyen bulgu: {len(pending)}. Tamamlanan adım: {_done}. '
                   f'Gerçek hata / zaman aşımı: {_hard}. Beklenen sonuç (servis yok / inceleme / atlanan): {_benign}. '
                   '“Servis yok” ve “TLS-IP uyuşmazlığı” geniş ağ taramasında normaldir; hata sayılmaz.',st['BodyX']))
    corr=json.loads((root/'UBDEN_CORRELATION.json').read_text(encoding='utf-8')) if (root/'UBDEN_CORRELATION.json').is_file() else {}
    if corr and (corr.get('correlations') or corr.get('graph',{}).get('nodes')):
        story.append(P('Çapraz-katman maruziyet analizi',st['SectionX']))
        story.append(P(corr.get('meaning',''),st['SmallX']))
        ei=corr.get('exposure_index',{})
        egauge=V.donut_gauge(ei.get('score',0),ei.get('grade','E'),'DVB','DV',size=32*mm,caption='MARUZİYET')
        etext=P('Maruziyet indeksi <b>%s/100</b> (Not %s). %s'%(ei.get('score','?'),ei.get('grade','?'),ei.get('comment','')),st['BodyX'])
        erow=Table([[egauge,etext]],colWidths=[36*mm,doc.width-36*mm])
        erow.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(0,0),4*mm)]))
        story += [erow,Spacer(1,3*mm)]
        if ei.get('human_score') is not None:
            story.append(P('İnsan-riski / e-posta duruşu skoru: <b>%s/100</b> (Not %s). Maruziyet indeksi ağ ve insan tarafının ortalamasıdır.'%(ei.get('human_score'),ei.get('human_grade','?')),st['SmallX']))
        cors=corr.get('correlations',[])
        if cors:
            cor_cells=[[P(x,st['SmallWhiteX']) for x in ('Önem','Maruziyet kesişimi','Ayrıntı')]]
            for c in cors:
                cor_cells.append([P(SEVERITIES.get(c.get('severity'),'Bilgi'),st['SmallX']),
                                  P(c.get('title',''),st['SmallX'],limit=140),
                                  P(c.get('detail',''),st['SmallX'],limit=280)])
            story.append(grid_table(cor_cells,[doc.width*.12,doc.width*.32,doc.width*.56]))
        if corr.get('graph',{}).get('nodes'):
            story += [P('Saldırı-yüzeyi ilişki ağı',st['SubX']),
                      V.relationship_graph(corr['graph'],doc.width,'DVB','DV'),Spacer(1,3*mm)]
        chains=corr.get('attack_chains',[])
        if chains and not executive:
            story.append(P('Olası saldırı zincirleri — analist doğrulaması gerekir',st['SubX']))
            for ch in chains:
                story.append(P(f"{ch.get('name','?')} — olasılık: {ch.get('likelihood','?')} · etki: {ch.get('impact','?')}",st['SmallX']))
                for index,stp in enumerate(ch.get('steps',[]),1):
                    story.append(P(f'{index}. {stp}',st['SmallX'],limit=220))
        if corr.get('combined_actions'):
            story.append(P('Öncelikli birleşik aksiyonlar',st['SubX']))
            act_cells=[[P(x,st['SmallWhiteX']) for x in ('Öncelik','Aksiyon','Gerekçe / efor')]]
            for a in corr['combined_actions'][:8]:
                act_cells.append([P(a.get('priority',''),st['SmallX']),P(a.get('action',''),st['SmallX'],limit=200),
                                  P((a.get('rationale','')+' · efor: '+a.get('effort','?')),st['SmallX'],limit=200)])
            story.append(grid_table(act_cells,[doc.width*.14,doc.width*.44,doc.width*.42]))
    tech=json.loads((root/'UBDEN_TECH_PROFILE.json').read_text(encoding='utf-8')) if (root/'UBDEN_TECH_PROFILE.json').is_file() else {}
    if tech and tech.get('matches'):
        story.append(P('Teknoloji ve platform tespiti',st['SectionX']))
        story.append(P(tech.get('note',''),st['SmallX']))
        story.append(P('Aile dağılımı: '+', '.join(f'{k}: {v}' for k,v in tech.get('families',{}).items()),st['BodyX']))
        tcells=[[P(x,st['SmallWhiteX']) for x in ('Platform / adres','Sürüm / güven','Yönetim portları','Doğrulanacak danışmalar')]]
        for m in tech['matches'][:20]:
            tcells.append([P(f"{m.get('family','')}\n{m.get('ip','')}",st['SmallX'],limit=120),
                           P((m.get('version') or 'sürüm gözlenmedi')+f"\n{m.get('confidence','')}",st['SmallX']),
                           P(', '.join(map(str,m.get('mgmt_ports_observed',[]))) or '—',st['SmallX']),
                           P('; '.join(m.get('advisories',[])[:2]),st['SmallX'],limit=280)])
        story.append(grid_table(tcells,[doc.width*.24,doc.width*.16,doc.width*.14,doc.width*.46]))
        if len(tech['matches'])>20:
            story.append(P(f"Diğer {len(tech['matches'])-20} eşleşme UBDEN_TECH_PROFILE.json içinde.",st['SmallX']))
    cve=json.loads((root/'UBDEN_CVE.json').read_text(encoding='utf-8')) if (root/'UBDEN_CVE.json').is_file() else {}
    if cve and cve.get('items'):
        story.append(P('NVD CVE adayları — analist doğrulaması gerekir',st['SubX']))
        story.append(P(cve.get('note','')+f" Sorgulanan platform: {cve.get('queried',0)}; kritik/yüksek aday: {cve.get('critical_high_count',0)}.",st['SmallX']))
        for it in cve['items']:
            story.append(P(f"{it['family']} {it['version']} — {it['cve_count']} CVE adayı · {', '.join(it.get('assets',[])[:4])}",st['SmallX'],limit=200))
            for c in it.get('cves',[])[:6]:
                story.append(P(f"{c['id']} · CVSS {c.get('cvss') or '?'} {c.get('severity') or ''} — {c.get('summary','')}",st['SmallX'],limit=280))
    story += [P('Yönetici değerlendirmesi',st['SectionX']),P(review.get('analyst_summary') or 'Analist değerlendirmesi henüz eklenmedi. Teslim öncesi iş etkisi, öncelik ve önerilen aksiyonlar doğrulanmalıdır.',st['BodyX'])]
    story.append(P('Önerilen yaklaşım',st['SectionX']))
    story.append(P('Doğrulanmış bulguları önce iş etkisine göre önceliklendirin. Her düzeltmeden sonra aynı hedefte yeniden test yapın. Kapsam dışındaki varlıklar veya çalışmayan kontroller için ayrı çalışma planlayın.',st['BodyX']))
    if executive:
        story += [P('Doğrulanmış bulgu listesi',st['SectionX'])]
        if not confirmed: story.append(P('Henüz analist onaylı bulgu bulunmuyor.',st['BodyX']))
        else:
            summary=[[P(x,st['SmallWhiteX']) for x in ('ID / önem','Bulgu ve varlık','Önerilen ilk aksiyon')]]
            for f in confirmed:
                summary.append([P(f"{f['id']}\n{SEVERITIES[f['severity']]}",st['SmallX']),
                                P(f"{f['title']}\n{f['asset']}",st['SmallX'],limit=220),
                                P(f.get('remediation_priority') or f.get('recommendation'),st['SmallX'],limit=220)])
            story.append(grid_table(summary,[doc.width*.17,doc.width*.39,doc.width*.44]))
        if devices and devices.get('devices'):
            story.append(P('Cihaz görünürlüğü ve aksiyonlar',st['SectionX']))
            story.append(P('Aşağıdaki cihaz türleri otomatik sınıflandırma adaylarıdır. Yüksek güven puanı dahi cihaz kimliğinin veya bir açığın insan tarafından doğrulandığı anlamına gelmez.',st['BodyX']))
            columns=[[P(v,st['SmallX']) for v in ('IP','Cihaz adayı','Güven','İnceleme')]]
            for device in devices['devices'][:12]:
                note=(device.get('notices') or device.get('review_notes') or ['Model/rol doğrulaması'])[:1][0]
                columns.append([P(device.get('ip',''),st['SmallX']),P(device.get('category',''),st['SmallX']),P(device.get('confidence',''),st['SmallX']),P(note,st['SmallX'],limit=110)])
            table=Table(columns,colWidths=[doc.width*.18,doc.width*.28,doc.width*.12,doc.width*.42],repeatRows=1)
            table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),PALE),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#dce5eb')),('VALIGN',(0,0),(-1,-1),'TOP')]))
            story.append(table)
            if len(devices['devices'])>12:
                story.append(P(f"Diğer {len(devices['devices'])-12} adresin tüm detayları teknik raporda ve DEVICE_INVENTORY.json dosyasındadır.",st['SmallX']))
    else:
        story += [P('Yöntem ve kapsam kontrolü',st['SectionX'])]
        story.append(P('Yazılı yetki referansı kaydedildi. Hedefler yalnızca açıkça girilen IP, FQDN veya sınırlandırılmış CIDR kapsamından işlendi. DNS ile bulunan adresler kayıt altına alındı. Web isteklerinde hedef IP sabitlendi ve yönlendirme takip edilmedi.',st['BodyX']))
        story.append(P(f"Profil: {meta.get('profile')} | Nmap hız sınırı: {meta.get('max_rate')} paket/sn | Port sayısı: {meta.get('top_ports')} | Sürüm: {meta.get('tool_version')}",st['BodyX']))
        for item in discovery:
            story.append(P(discovery_line(item)+f" Kanıt: {item.get('evidence','?')}. Yanıt veren IP'ler: {', '.join(item.get('responding_hosts',[])[:24]) or 'yok'}.",st['SmallX']))
        story.append(P('İlk otomatik kimlikli kontrol HTTPS HEAD durum kodlarını karşılaştırır. Seçilmiş rol/IDOR ve salt okunur iş kuralı testlerinde GET yanıt kodları karşılaştırılır; gerçek yetki veya iş etkisi ancak analist doğrularsa bulgu sayılır. SSH parola adımları yalnız açıkça verilen test hesabında iki adayla sınırlıdır. İşlem yapan iş akışları, iç ağ yanal hareketi, genel parola kırma, hizmet engelleme ve veri çıkarma otomatik yürütülmez.',st['BodyX']))
        story.append(P('Manuel test planı',st['SubX']))
        story.append(P('İnsan tarafından yürütülen testlerin durumları ve kanıtları review.json içinde kayıtlıdır; eksikler tamamlandı sayılmaz.',st['BodyX']))
        cov=CASE_COV.derive(root,meta,steps,findings)
        cs=cov['summary']
        story.append(P(f"Otomasyon kapsamı: {cs['total']} kategoriden {cs['covered']} tanesi otomatik + AI ile "
                       f"taslak kapsandı ({cs['automated']} otomatik, {cs['ai']} AI); {cs['analyst_only']} kategori "
                       "analist yürütmesi gerektiriyor. Otomasyon taslak üretir; doğrulandı yalnız analist + SHA-256 ile verilir.",st['BodyX']))
        for case in meta.get('role_scenarios',[]):
            attempt=[s for s in steps if str(s.get('step','')).startswith('role_'+str(case.get('id'))+'_')]
            story.append(P(f"{case.get('id')} | {case.get('kind')} | {case.get('owner')} → {case.get('challenger')} | HTTPS GET {case.get('target')}:{case.get('port')}{case.get('path')} | Durum: {', '.join(x.get('status','?') for x in attempt) or 'atlanmış'}",st['SmallX']))
        cov_cells=[[P(x,st['SmallWhiteX']) for x in ('Test','Analist','Otomatik / AI kapsamı')]]
        for row in review.get('cases',[]):
            if isinstance(row,dict):
                cc=cov['cases'].get(str(row.get('id','')).upper(),{})
                auto=cc.get('status_label','—')+(': '+cc.get('detail','') if cc.get('detail') else '')
                cov_cells.append([P(f"{row.get('id','?')} · {row.get('title','')}",st['SmallX'],limit=90),
                                  P(row.get('state','bekliyor'),st['SmallX'],limit=40),
                                  P(auto+(' ['+', '.join(str(x) for x in cc.get('finding_ids',[])[:6])+']' if cc.get('finding_ids') else ''),st['SmallX'],limit=260)])
        story.append(grid_table(cov_cells,[doc.width*.30,doc.width*.16,doc.width*.54]))
        for issue in state['errors'][:10]:
            story.append(P('Kayıt doğrulama uyarısı: '+issue,st['SmallX']))
        rows=tool_rows(root,steps)
        if rows:
            story.append(P('Bu sızma testinde gerçekten çalıştırılan araçlar',st['SubX']))
            used_rows=[row for row in rows if row[2]=='Çalıştırıldı']
            if used_rows:
                table=Table([[P(v,st['SmallX']) for v in ('Araç','Kategori','Durum','Proje adresi')]]+
                            [[P(v,st['SmallX']) for v in (row[0],row[3],row[2])]+
                             [Paragraph(f'<link href="{safe(row[4])}" color="#087483">{safe(row[4])}</link>',st['SmallX']) if row[4] else P('—',st['SmallX'])]
                             for row in used_rows],
                            colWidths=[doc.width*.19,doc.width*.24,doc.width*.22,doc.width*.35],repeatRows=1)
                table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),PALE),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#dce5eb')),('VALIGN',(0,0),(-1,-1),'TOP')]))
                story.append(table)
            else:
                story.append(P('Başarıyla çalıştırıldığı kayıtlı araç yok; adım günlüğünü inceleyin.',st['BodyX']))
            unused=[row[0] for row in rows if row[2]!='Çalıştırıldı' and row[1]=='Kurulu']
            if unused:
                story.append(P('Kurulu fakat bu görevde çalıştırılmayan uzman araçları: '+', '.join(unused)+'. Bunlar test gerçekleştirmiş gibi gösterilmez.',st['SmallX']))
        story.append(P('Varlık ve servis envanteri',st['SectionX']))
        if not hosts: story.append(P('Servis taraması XML çıktısı yok. CIDR keşif özetini ve adım günlüğünü inceleyin.',st['BodyX']))
        for host in hosts:
            story.append(P(f"{host['ip']} — {len(host['ports'])} açık TCP portu",st['SubX']))
            story.append(P('Kanıt: '+host['evidence'],st['SmallX']))
            if host['ports']:
                rows=[[P(x,st['SmallX']) for x in ('Port','Protokol','Servis / ürün')]]
                for port in host['ports']:
                    rows.append([P(port['port'],st['SmallX']),P(port['protocol'],st['SmallX']),P(' '.join([port['service'],port['product'],port['version']]),st['SmallX'])])
                table=Table(rows,colWidths=[25*mm,30*mm,doc.width-55*mm],repeatRows=1,hAlign='LEFT')
                table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),PALE),('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#dce5eb')),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),5)]))
                story.append(table)
        if devices:
            story.append(P('Cihaz kimliği ve sınıflandırma',st['SectionX']))
            local=devices.get('local_interface_addresses',[])
            if local:
                story.append(P('Test bilgisayarının kapsam içi IP adresleri',st['SubX']))
                for item in local:
                    story.append(P(f"{item['ip']} | {item['adapter']} | {item['status']} | kanıt: {item['evidence']}",st['SmallX']))
            summary=[[P(x,st['SmallWhiteX']) for x in ('Cihaz sınıfı adayı','Adres sayısı')]]
            summary.extend([[P(label,st['SmallX']),P(count,st['SmallX'])]
                            for label,count in sorted(devices.get('categories',{}).items(),key=lambda row:(-row[1],row[0]))])
            story.append(grid_table(summary,[doc.width*.72,doc.width*.28]))
            story.append(P('Cihaz envanteri matrisi',st['SubX']))
            device_cells=[[P(x,st['SmallWhiteX']) for x in ('IP / ad','Sınıf / üretici','MAC / OS tahmini','Açık servisler')]]
            for item in devices['devices']:
                device_cells.append([
                    P(item.get('ip','')+'\n'+(', '.join(item.get('hostnames',[])) or 'ad yok'),st['SmallX'],limit=150),
                    P(item.get('category','')+'\n'+item.get('vendor',''),st['SmallX'],limit=150),
                    P((item.get('mac') or 'MAC yok')+'\n'+(', '.join(x.get('name','') for x in item.get('os_matches',[])) or 'OS tahmini yok'),st['SmallX'],limit=150),
                    P(', '.join(f"{p.get('port')}/{p.get('protocol')} {p.get('service')}" for p in item.get('ports',[])) or 'açık port yok',st['SmallX'],limit=170)])
            story.append(grid_table(device_cells,[doc.width*.23,doc.width*.27,doc.width*.25,doc.width*.25]))
            if devices.get('services'):
                story.append(P('Servis dağılımı',st['SubX']))
                service_cells=[[P(x,st['SmallWhiteX']) for x in ('Port / protokol / servis','Adres sayısı')]]
                service_cells.extend([[P(name,st['SmallX']),P(count,st['SmallX'])]
                                      for name,count in sorted(devices['services'].items(),key=lambda row:(-row[1],row[0]))])
                story.append(grid_table(service_cells,[doc.width*.76,doc.width*.24]))
            for item in devices['devices']:
                story.append(P(f"{item.get('ip')} | {item.get('category')} | güven: {item.get('confidence')}",st['SubX']))
                story.append(P(f"Ad: {', '.join(item.get('hostnames',[])) or 'görülmedi'}; OS tahmini: {', '.join(x.get('name','')+' (%'+x.get('accuracy','?')+')' for x in item.get('os_matches',[])) or 'yok'}; MAC: {item.get('mac') or 'görülmedi'} ({item.get('mac_source')}); üretici: {item.get('vendor')} ({item.get('vendor_source')}); kanıt: {item.get('evidence')}",st['SmallX']))
                for clue in (item.get('signals',[])+item.get('notices',[])+item.get('review_notes',[]))[:12]:
                    story.append(P('• '+str(clue),st['SmallX']))
            if devices.get('parse_errors'):
                story.append(P('Okunamayan XML: '+', '.join(devices['parse_errors'][:8]),st['SmallX']))
        story.append(P('Doğrulanmış bulgular ve kanıtları',st['SectionX']))
        if not confirmed: story.append(P('Analist tarafından doğrulanmış bulgu kaydedilmedi.',st['BodyX']))
        for f in confirmed:
            story.extend(finding_story(root,f,st,doc.width))
        story.append(P('İnceleme gerektiren gözlemler',st['SectionX']))
        story.append(P('Bu kayıtlar otomatik eşleşme veya kanıtı henüz doğrulanmamış analist notudur. Aşağıdaki önem derecesi yalnız inceleme önceliği içindir.',st['BodyX']))
        if not pending: story.append(P('Açık inceleme adayı yok.',st['BodyX']))
        for f in pending:
            story.extend(finding_story(root,f,st,doc.width))
        disposed=[f for f in findings if f['status'] in ('yanlış pozitif','risk kabul edildi')]
        if disposed:
            story.append(P('Kapatılan veya kabul edilen kayıtlar',st['SectionX']))
            cells=[[P(x,st['SmallWhiteX']) for x in ('ID / varlık','Durum','Gerekçe')]]
            cells.extend([[P(f['id']+' · '+f['asset'],st['SmallX']),P(f['status'],st['SmallX']),
                           P(f.get('disposition_reason') or f.get('description'),st['SmallX'],limit=300)] for f in disposed])
            story.append(grid_table(cells,[doc.width*.28,doc.width*.20,doc.width*.52]))
        story.append(P('Adım günlüğü ve kanıt zinciri',st['SectionX']))
        story.append(P('Her otomatik adımın durumu ve çıktı SHA-256 özeti steps.json içinde bulunur. Rapor üretiminde kanıt dosyaları değiştirilmez. Tüm kanıtlar hassas kabul edilmeli ve erişimi sınırlandırılmalıdır.',st['BodyX']))
        for entry in steps:
            story.append(P(f"{entry.get('step','?')} | {entry.get('status','?')} | {entry.get('seconds','?')} sn | {entry.get('output',entry.get('detail',''))} | SHA-256: {entry.get('sha256','yok')}",st['SmallX']))
        story.append(P('Sınırlar ve takip: DNS değişiklikleri, erişilemeyen servisler, güvenlik cihazları, hız sınırları ve eksik araçlar görünürlüğü etkileyebilir. Hatalı veya zaman aşımına uğrayan adımlardan önce kapsam ve bakım penceresini yeniden doğrulayın. Düzeltme ve yeniden test tarihlerini müşteriyle kararlaştırın.',st['SmallX']))
    doc.multiBuild(story)

def _splice(doc, anchor, insertion):
    """Bölüm parçasını çapadan önce yerleştirir; çapa yoksa sessizce geçmez, hata verir.

    HTML tek parça üretilip bölümler çapa metinlerinden enjekte ediliyor. Şablon
    metni değişip çapa kaybolursa eski davranış sessiz no-op'tu (bölüm hiç eklenmezdi);
    bu guard onu erken ve görünür bir hataya çevirir.
    """
    if anchor not in doc:
        raise ValueError(f'HTML rapor şablonunda çapa bulunamadı: {anchor[:48]!r}')
    return doc.replace(anchor, insertion, 1)

def html_report(root,meta,steps,hosts,findings,review,report_errors=None):
    state=assess(root,review)
    discovery=discovery_summaries(root)
    snmp=snmp_summaries(root)
    role_note,ai_note,ai_text=advanced_summary(root,meta,steps)
    report_errors=report_errors or {}
    pdf_links=' · '.join(f'<a href="{name}">{title}</a>' for name,title in
                       (('YONETICI_OZETI.pdf','Yönetici PDF'),('TEKNIK_RAPOR.pdf','Teknik PDF'),
                        ('ANALIST_GOREV_RAPORU.pdf','Analist PDF'))
                       if name not in report_errors and (root/name).is_file())
    pdf_notice=('PDF üretim hatası: '+', '.join(f'{name}: {reason}' for name,reason in report_errors.items())) if report_errors else ''
    def li(v): return f'<li>{safe(v)}</li>'
    rows=''.join(f'<tr><td><a href="#bulgu-{i}">{safe(f.get("id"))}</a></td><td>{safe(f.get("title"))}</td><td>{safe(SEVERITIES.get(f.get("severity"),"Bilgi"))}</td><td>{safe(f.get("status"))}</td><td>{safe(f.get("asset"))}</td><td>{evidence_link(root,f.get("evidence"))}</td></tr>' for i,f in enumerate(findings,1))
    detail_fields=(('Kaynak','source'),('Durum','status'),('Varlık','asset'),('Diğer etkilenenler','affected_assets'),('Kategori','category'),('Erişim noktası','access_point'),('Kullanıcı profili','user_profile'),('Kök neden','root_cause'),('CVSS','cvss'),('CWE sınıfı','cwe'),('Açıklama','description'),('Tekrar üretim','reproduction'),('Doğrulayan','reviewed_by'),('İş etkisi','impact'),('Düzeltme önerisi','recommendation'),('Düzeltme önceliği','remediation_priority'),('Yeniden test','retest_status'),('Kapatma / kabul gerekçesi','disposition_reason'),('Referans','reference'))
    finding_details=''.join(
        f'<section class="finding" id="bulgu-{i}"><h3>{safe(f.get("id"))} · {safe(f.get("title"))}</h3>'
        f'<p><b>Şiddet:</b> {safe(SEVERITIES.get(f.get("severity"),"Bilgi"))} · <b>Doğrulama:</b> {safe(f.get("status"))}</p>'+
        ''.join(f'<p><b>{label}:</b> {safe(", ".join(f[key]) if isinstance(f.get(key),list) else f.get(key))}</p>' for label,key in detail_fields if f.get(key))+
        '<h4>Kanıt zinciri</h4><ul>'+''.join('<li>'+safe(item['caption'])+': '+evidence_link(root,item['path'])+
        (' · SHA-256 '+safe(item['sha256']) if item['sha256'] else '')+'</li>' for item in finding_evidence(f))+'</ul></section>'
        for i,f in enumerate(findings,1))
    inventory=''.join(f'<tr><td>{safe(h.get("ip"))}</td><td>{safe(", ".join(str(p.get("port",""))+"/"+str(p.get("service","")) for p in h.get("ports",[])))}</td><td>{evidence_link(root,h.get("evidence"))}</td></tr>' for h in hosts)
    devices=device_inventory(root)
    dev_list=devices.get('devices',[])

    def _meter(pct):
        pct=int(pct or 0)
        return f'<span class="cmeter"><i style="width:{max(4,min(100,pct))}%"></i></span> <b>%{pct}</b>'

    def _ports_tbl(item):
        ps=item.get('ports',[])
        if not ps:
            return '<p class="dim">Açık TCP portu görülmedi.</p>'
        rows=''.join('<tr><td><code>'+safe(p.get('port'))+'/'+safe(p.get('protocol'))+'</code></td><td>'+
                     safe(p.get('service') or '—')+'</td><td>'+
                     safe(' '.join(x for x in (p.get('product'),p.get('version'),p.get('extra_info')) if x) or '—')+
                     '</td></tr>' for p in ps)
        return '<table class="ports"><thead><tr><th>Port</th><th>Servis</th><th>Ürün / sürüm / banner</th></tr></thead><tbody>'+rows+'</tbody></table>'

    # Group by fixed taxonomy order (parsDedector-style category cards).
    order=[k for k in CATEGORY_ORDER if any(d.get('category_key')==k for d in dev_list)]
    for d in dev_list:
        k=d.get('category_key')
        if k and k not in order:
            order.append(k)
    group_html=''
    for key in order:
        members=[d for d in dev_list if d.get('category_key')==key]
        if not members:
            continue
        label=members[0].get('category') or key
        cards=''
        for item in members:
            name=item.get('display_name') or (item.get('hostnames') or [''])[0] or '—'
            os_txt=', '.join(x.get('name','')+' (%'+str(x.get('accuracy','?'))+')' for x in item.get('os_matches',[])) or '—'
            reason=' · '.join(item.get('signals',[])[:5])
            roles=', '.join(r.get('role','') for r in item.get('role_candidates',[]))
            notes=' · '.join(item.get('notices',[])+item.get('review_notes',[]))
            cards+=('<div class="devcard"><div class="devhead"><span class="dip"><code>'+safe(item.get('ip'))+'</code></span>'
                    '<span class="dname">'+safe(name)+'</span><span class="dconf">'+_meter(item.get('confidence_pct'))+'</span></div>'
                    '<div class="devmeta"><span>MAC <code>'+safe(item.get('mac') or 'görülmedi')+'</code></span>'
                    '<span>Üretici: '+safe(item.get('vendor'))+'</span><span>OS: '+safe(os_txt)+'</span>'
                    +('<span>Kanıt: '+evidence_link(root,item.get('evidence'))+'</span>' if item.get('evidence') else '')+'</div>'
                    +_ports_tbl(item)
                    +('<p class="devsig"><b>Sınıflandırma:</b> '+safe(reason)+'</p>' if reason else '')
                    +('<p class="devrole"><b>Rol adayları:</b> '+safe(roles)+'</p>' if roles else '')
                    +('<p class="devnote">'+safe(notes)+'</p>' if notes else '')
                    +'</div>')
        group_html+='<h3 class="catgroup">'+safe(CATEGORY_ICONS.get(key,'')+' '+label)+' <span class="pill">'+str(len(members))+'</span></h3>'+cards

    # Network overview: gateways + per-adapter IP counts + discovery totals.
    gateways=devices.get('observed_gateways',[])
    snap=meta.get('host_snapshot') if isinstance(meta.get('host_snapshot'),dict) else {}
    adp_rows=''.join('<tr><td>'+safe(a.get('name'))+'</td><td>'+safe(a.get('status'))+'</td><td>'+
                     str(len(a.get('addresses',[])))+'</td><td>'+
                     safe(', '.join(x.get('address','') for x in a.get('addresses',[])[:4]))+'</td></tr>'
                     for a in snap.get('adapters',[]) if a.get('addresses'))
    netov=('<h3>Ağ genel görünümü</h3><p>Kapsam: '+safe(', '.join(meta.get('targets',[])))+
           ' · Bulunan cihaz: <b>'+str(len(dev_list))+'</b> · MAC görülen: <b>'+safe(devices.get('mac_count'))+
           '</b> · Sınıflandırılmamış: '+safe(devices.get('unknown_count'))+
           ' · Ağ geçidi: '+safe(', '.join(gateways) or '—')+'</p>')
    if adp_rows:
        netov+='<table><thead><tr><th>Test makinesi adaptörü</th><th>Durum</th><th>IP sayısı</th><th>Adresler</th></tr></thead><tbody>'+adp_rows+'</tbody></table>'
    named_rows=''.join('<tr><td><code>'+safe(d.get('ip'))+'</code></td><td>'+
                       safe(d.get('display_name') or (d.get('hostnames') or [''])[0] or '—')+'</td><td>'+
                       safe(d.get('category') or d.get('category_key') or '—')+'</td><td><code>'+
                       safe(d.get('mac') or 'MAC yok')+'</code></td></tr>'
                       for d in dev_list if d.get('display_name') or d.get('hostnames'))
    if named_rows:
        netov+=('<h3>Hostname envanteri</h3><table><thead><tr><th>IP adresi</th><th>Hostname</th>'
                '<th>Sınıf</th><th>MAC</th></tr></thead><tbody>'+named_rows+'</tbody></table>')
    device_html=('<h2>Cihaz envanteri</h2><p>'+safe(devices.get('limits'))+'</p>'+netov+
                 '<p><a href="DEVICE_INVENTORY.json">Makine tarafından okunabilir envanter (JSON)</a></p>'+
                 group_html) if devices else ''
    if devices.get('local_interface_addresses'):
        local_rows=''.join('<tr><td>'+safe(item.get('ip'))+'</td><td>'+safe(item.get('adapter'))+'</td><td>'+
            safe(item.get('status'))+'</td><td>'+evidence_link(root,item.get('evidence'))+'</td></tr>'
            for item in devices['local_interface_addresses'])
        device_html+='<h3>Test bilgisayarının kapsam içi IP adresleri</h3><p>Windows adaptör kaydı servis testi kanıtı değildir.</p><table><thead><tr><th>IP</th><th>Adaptör</th><th>Doğrulama durumu</th><th>Kanıt</th></tr></thead><tbody>'+local_rows+'</tbody></table>'
    analyst_plan=json.loads((root/'ANALIST_GOREV_RAPORU.json').read_text(encoding='utf-8')) if (root/'ANALIST_GOREV_RAPORU.json').is_file() else {}
    analyst_html=('<h2>Analist çalışma raporu</h2><p>Bekleyen adım: '+safe(analyst_plan.get('pending_count'))+'. Her adım için hedef, tetikleyen gözlem, müşteri girdisi, uygulanacak kontrol ve kanıt listesi ayrı hazırlanmıştır.</p><p><a href="ANALIST_GOREV_RAPORU.md">Ayrıntılı çalışma ve komut rehberi</a> · <a href="ANALIST_GOREV_RAPORU.json">Yapılandırılmış görevler</a></p><table><thead><tr><th>Öncelik</th><th>Kontrol</th><th>Durum</th><th>Hedef</th></tr></thead><tbody>'+''.join('<tr><td>'+safe(t['priority'])+'</td><td>'+safe(t['id']+' · '+t['title'])+'</td><td>'+safe(t['status'])+'</td><td>'+safe(', '.join(t['targets'][:5]))+'</td></tr>' for t in analyst_plan.get('tasks',[]))+'</tbody></table>') if analyst_plan else ''
    event=''.join(f'<tr><td>{safe(s.get("step"))}</td><td>{safe(s.get("status"))}</td><td>{safe(s.get("seconds"))}</td><td>{evidence_link(root,s.get("output"))}<br>{safe(s.get("detail"))}</td></tr>' for s in steps)
    profile=meta.get('profile','external')
    coverage={'external':'DNS/WHOIS, TCP servis, HTTP başlıkları ve TLS','web':'Web portları, HTTP başlıkları, OPTIONS ve TLS','network':'TCP servis ve seçilmiş NSE kontrolleri','full':'DNS/WHOIS, TCP servis, HTTP/TLS, OPTIONS ve seçilmiş NSE kontrolleri'}.get(profile,'Bilinmiyor')
    nuclei_note=f"Nuclei: {meta.get('nuclei_profile','custom')} / {meta.get('nuclei_template_count','?')} şablon. Adım durumunu günlükte kontrol edin." if meta.get('nuclei_templates') else 'Nuclei şablon taraması seçilmedi.'
    auth_note=auth_summary(meta,steps)
    platform_summary=platform_lines(root,meta,steps)
    platform_html=('<h2>Windows, AD ve Wi-Fi ortamı</h2>'+''.join(
        f'<p>{safe(line)}</p>' for line in platform_summary)) if platform_summary else ''
    doc=f'''<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>UBDEN Cyber Security Systems | {safe(meta.get('client'))}</title><style>
    :root{{--navy:#101b32;--teal:#00b9bd}}body{{margin:0;background:#f0f4f8;color:#263249;font:15px/1.65 Arial,sans-serif}}main{{max-width:1080px;margin:35px auto;padding:40px;background:white;box-shadow:0 10px 35px #1112}}header{{background:var(--navy);color:white;padding:40px;margin:-40px -40px 35px}}header img{{max-width:230px;max-height:65px;object-fit:contain}}h1{{font-size:29px}}h2{{color:var(--navy);border-bottom:2px solid var(--teal);padding-bottom:8px}}h3{{color:var(--navy)}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #dce5eb;vertical-align:top;overflow-wrap:anywhere}}th{{background:#edf7f8}}.notice{{background:#fff2d4;padding:15px;border-left:4px solid #db9d27}}.finding{{padding:12px 18px;margin:18px 0;border:1px solid #dce5eb;border-left:4px solid var(--teal);overflow-wrap:anywhere}}.finding p{{margin:7px 0}}.meta{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}}a{{color:#087483}}small{{color:#65758b}}@media print{{body{{background:white}}main{{box-shadow:none;margin:0;padding:16mm}}header{{print-color-adjust:exact}}}}@media(max-width:700px){{main{{padding:20px;margin:0}}header{{margin:-20px -20px 20px}}.meta{{display:block}}}}</style></head><body><main><header>{'<img src="assets/ubden-logo.png" alt="UBDEN">' if logo() else 'UBDEN Cyber Security Systems'}<h1>Cyber Security Systems</h1><p>Ürün: UBDEN® · Test ekibi: {safe(meta.get('tester'))}</p><p>{safe(meta.get('client'))} · {safe(meta.get('project'))}</p></header><p class="notice">Analist doğrulaması bekleyen otomatik çıktılar kesinleşmiş güvenlik açığı değildir. Kapsam ve sınırlamaları okuyun.</p>{f'<p class="notice">{safe(pdf_notice)}</p>' if pdf_notice else ''}<div class="meta"><p>{pdf_links + '<br>' if pdf_links else ''}<b>Yetki:</b> {safe(meta.get('authorization_reference'))}<br><b>Durum:</b> {safe(meta.get('status'))}<br><b>Başlangıç:</b> {safe(meta.get('started_at'))}</p><p><b>Sorumlu:</b> {safe(meta.get('tester'))}<br><b>Kayıt:</b> {safe(meta.get('id'))}<br><b>Bitiş:</b> {safe(meta.get('finished_at'))}</p></div><h2>Otomatik kapsam ve manuel çalışma</h2><p><b>{safe(profile.upper())}:</b> {safe(coverage)}. {safe(nuclei_note)}</p><p>Seçili test hesabı ve rol kontrolleri sınırlı otomatik adımlardır. Diğer kimlik doğrulama, yetkilendirme, iş mantığı ve analist doğrulaması için <a href="MANUEL_TEST_PLANI.md">manuel test planını</a> kullanın. Atlanan adımlar tamamlanmış sayılmaz.</p><h2>Yönetici özeti</h2><p>{safe(review.get('analyst_summary') or 'Analist değerlendirmesi henüz eklenmedi.')}</p><p>Doğrulanmış: {sum(f['status']=='doğrulandı' for f in findings)} · Taslak: {sum(f['status']=='taslak' for f in findings)} · Kayıtlı varlık: {len(hosts)}</p><h2>Kapsam</h2><ul>{''.join(li(x) for x in meta.get('targets',[]))}</ul><p>Hariç: {safe(', '.join(meta.get('exclusions',[])) or 'Tanımlanmadı')}</p><h2>Analist bulguları</h2><table><thead><tr><th>ID</th><th>Bulgu</th><th>Seviye</th><th>Durum</th><th>Varlık</th><th>Kanıt</th></tr></thead><tbody>{rows}</tbody></table><h2>Bulgu detayları</h2>{finding_details}<h2>Varlık envanteri</h2><table><thead><tr><th>Adres</th><th>Açık servisler</th><th>Kanıt</th></tr></thead><tbody>{inventory}</tbody></table><h2>Çalışma günlüğü</h2><table><thead><tr><th>Adım</th><th>Durum</th><th>Süre (sn)</th><th>Kanıt / açıklama</th></tr></thead><tbody>{event}</tbody></table><h2>Sınırlar</h2><p>Otomasyonun kapsadığı servis, web, AD, test hesabı ve Wi-Fi adımları yalnız görevde seçilip gerçekten çalıştırıldığında günlüğe girer. Atlanan kontroller tamamlanmış test sayılmaz; manuel istismar doğrulaması analist kaydı gerektirir.</p><small>UBDEN Cyber Security Systems · {safe(meta.get('tester'))} · GİZLİ · Yalnızca yetkili alıcılar</small></main></body></html>'''
    inventory=tool_rows(root,steps)
    inventory_html=('<h2>Bu sızma testinde kullanılan araçlar ve hazır olanlar</h2><p>“Çalıştırıldı” en az bir sürecin başlatıldığını gösterir; başarılı ve hatalı adımlar çalışma günlüğünde ayrıdır. Kurulu fakat çalıştırılmadı ve eksik durumları ayrı gösterilir.</p><table><thead><tr><th>Araç</th><th>Kurulum</th><th>Bu görevde kullanım</th><th>Kategori / gerekçe</th><th>Proje adresi</th></tr></thead><tbody>'+
        ''.join('<tr>'+''.join(f'<td>{safe(v)}</td>' for v in row[:4])+
                (f'<td><a rel="noopener" href="{safe(row[4])}">{safe(row[4])}</a></td>' if row[4] else '<td>—</td>')+'</tr>'
                for row in inventory)+'</tbody></table>') if inventory else ''
    cov=CASE_COV.derive(root,meta,steps,findings)
    cs=cov['summary']
    review_table=('<h2>Manuel test kayıtları</h2>'
        f"<p><b>Otomasyon kapsamı:</b> {cs['total']} kategoriden <b>{cs['covered']}</b> tanesi "
        f"otomatik + AI ile taslak olarak kapsandı ({cs['automated']} otomatik, {cs['ai']} AI); "
        f"{cs['analyst_only']} kategori analist yürütmesi gerektiriyor. "
        "Otomasyon taslak üretir; <b>doğrulandı</b> yalnız analist + SHA-256 kanıtıyla verilir.</p>"
        '<p>Durum: '+('analist kayıtları tamamlandı' if state['complete'] else 'eksik veya inceleme bekliyor')
        +f"; bekleyen analist başlığı: {state['pending']}; inceleyen: {safe(state['reviewer'] or 'yok')}</p>"
        "<table><thead><tr><th>Test</th><th>Analist durumu</th><th>Otomatik / AI kapsamı</th>"
        "<th>Sonuç</th><th>Kanıt / SHA-256</th></tr></thead><tbody>")
    for c in review.get('cases',[]):
        if not isinstance(c,dict): continue
        cc=cov['cases'].get(str(c.get('id','')).upper(),{})
        auto=(safe(cc.get('status_label','—'))+(': '+safe(cc.get('detail','')) if cc.get('detail') else '')
              +(' ['+safe(', '.join(str(x) for x in cc.get('finding_ids',[])[:6]))+']' if cc.get('finding_ids') else ''))
        review_table+=(f'<tr><td>{safe(c.get("id"))}</td><td>{safe(c.get("state"))}</td>'
            f'<td>{auto}</td><td>{safe(c.get("note"))}</td>'
            f'<td>{evidence_link(root,c.get("evidence"))} / {safe(c.get("sha256"))}</td></tr>')
    review_table+='</tbody></table>'
    ai_html=('<h2>AI analist taslağı</h2><p>'+safe(ai_note)+'</p><p>'+safe(ai_text or 'Yorum yok')+'</p>') if (root/'AI_DURUM.json').is_file() else ''
    discover_html=('<h2>CIDR host keşfi</h2><table><thead><tr><th>Ağ</th><th>Durum</th><th>Uygun IP</th><th>Yanıt veren</th><th>Yanıt vermeyen</th></tr></thead><tbody>'+
        ''.join('<tr>'+''.join(f'<td>{safe(value)}</td>' for value in (x.get('target'),{'partial':'kısmi','ok':'tamamlandı','no_hosts':'yanıt alınamadı','error':'hata'}.get(x.get('status'),x.get('status')),x.get('eligible_count'),x.get('responding_count'),x.get('unresponsive_count') if x.get('unresponsive_count') is not None else 'bilinmiyor'))+'</tr>' for x in discovery)+'</tbody></table>'+
        ''.join(f'<p>{safe(discovery_line(x))} Kanıt: {evidence_link(root,x.get("evidence"))}</p>' for x in discovery)) if discovery else ''
    snmp_html=('<h2>SNMPv1 / public kontrolü</h2><p>Her izinli yanıt veren adrese tek salt okunur sysDescr isteği gönderildi. Yanıt yokluğu servisin güvenli olduğunu kanıtlamaz.</p><table><thead><tr><th>Hedef</th><th>Denendi</th><th>Yanıt</th><th>Kanıt</th></tr></thead><tbody>'+
        ''.join(f'<tr><td>{safe(x.get("target"))}</td><td>{safe(x.get("tested_count"))}</td><td>{safe(x.get("responding_count"))}</td><td>{evidence_link(root,x.get("evidence"))}</td></tr>' for x in snmp)+'</tbody></table>') if snmp else ''
    ledger=build_coverage(root,meta,steps,review)
    coverage_html='<h2>Test kapsamı ve yürütme matrisi</h2><p>'+safe(ledger['meaning'])+'</p><p>'+safe(' · '.join(f'{key}: {value}' for key,value in ledger['counts'].items()))+'</p><p><a href="ASSESSMENT_COVERAGE.json">Kapsam kaydı (JSON)</a></p><table><thead><tr><th>Grup</th><th>Kontrol</th><th>Durum</th><th>Yürütme / gerekçe</th><th>Kanıt</th></tr></thead><tbody>'+''.join(
        '<tr><td>'+safe(row['group'])+'</td><td>'+safe(row['id']+' · '+row['title'])+'</td><td>'+safe(row['status'])+'</td><td>'+safe(row['reason'] or f"{row['executed']}/{row['attempted']} kayıtlı adım")+'</td><td>'+'; '.join(evidence_link(root,path) for path in row['evidence'])+'</td></tr>'
        for row in ledger['controls'])+'</tbody></table>'
    network_html='<h2>Windows ağ yolları</h2><p>Adaptör bilgileri görev kaydıdır; hedef yetkisi yalnızca açık kapsamdan gelir.</p><table><thead><tr><th>Adaptör</th><th>Durum</th><th>Adresler</th><th>Ağ geçidi</th><th>DNS</th></tr></thead><tbody>'+''.join(
        '<tr><td>'+safe(row['name']+(' · seçili' if row['selected'] else '')+(' · VPN' if row['vpn'] else ''))+'</td><td>'+safe(row['status'])+'</td><td>'+safe(row['addresses'])+'</td><td>'+safe(row['gateway'])+'</td><td>'+safe(row['dns'])+'</td></tr>'
        for row in network_rows(meta))+'</tbody></table>' if network_rows(meta) else ''
    ad=ad_result(root)
    ad_html=('<h2>Etki alanı değerlendirmesi</h2><p>Durum: '+safe(ad.get('status'))+
        ' · Alan: '+safe(ad.get('domain'))+' · DC: '+safe(ad.get('domain_controller',ad.get('dc')))+
        ' · Kaynak: '+safe(ad.get('source'))+'</p><p>'+safe(ad.get('reason'))+'</p>'+
        '<table><thead><tr><th>Nesne türü</th><th>Gözlenen</th><th>Sorgu sınırı</th></tr></thead><tbody>'+
        ''.join('<tr><td>'+safe(kind)+'</td><td>'+safe(item.get('observed_count'))+'</td><td>'+safe(item.get('truncated_at'))+'</td></tr>'
                for kind,item in ad.get('inventory',{}).items() if isinstance(item,dict))+'</tbody></table>'+
        '<p>Dizin sayımları yetki, parola ilkesi veya paylaşım izni testinin tamamlandığını göstermez.</p>') if ad else ''
    counts=Counter(f['severity'] for f in findings)
    conf=Counter(f['severity'] for f in findings if f['status']=='doğrulandı')
    total=sum(counts.values())
    maxv=max(counts.values(),default=0) or 1
    level=('Kritik' if counts.get('critical') else 'Yüksek' if counts.get('high')
           else 'Orta' if counts.get('medium') else 'Düşük' if (counts.get('low') or counts.get('info'))
           else 'Bulgu yok')
    risk_html=('<h2>Bulguların önem dağılımı</h2>'
        '<p>Genel risk seviyesi: <b>'+safe(level)+'</b> &middot; Toplam bulgu: <b>'+str(total)+
        '</b> &middot; Doğrulanmış: '+str(sum(conf.values()))+' &middot; Taslak: '+str(total-sum(conf.values()))+'</p>'
        '<div class="riskbars">'+''.join(
        f'<div class="riskrow"><span>{safe(label)}</span><div class="risktrack"><i style="width:{max(2,round(100*counts.get(key,0)/maxv))}%;background:{SEVERITY_COLORS[key]}"></i></div>'
        f'<b>{counts.get(key,0)}</b></div>'
        for key,label in SEVERITIES.items())+'</div>'
        '<p class="dim">Çubuklar tüm bulguları (taslak + doğrulanmış) gösterir; kesinleşmiş güvenlik açığı için analist doğrulaması gerekir.</p>')
    prio=[f for f in findings if f['status']=='doğrulandı' or f['severity'] in ('critical','high')]
    priority_html='<h2>Düzeltme öncelikleri</h2><table><thead><tr><th>ID</th><th>Önem</th><th>Durum</th><th>Varlık</th><th>İlk aksiyon</th></tr></thead><tbody>'+''.join(
        '<tr><td>'+safe(f['id'])+'</td><td>'+safe(SEVERITIES[f['severity']])+'</td><td>'+safe(f['status'])+'</td><td>'+safe(f['asset'])+'</td><td>'+safe(f.get('remediation_priority') or f.get('recommendation'))+'</td></tr>'
        for f in prio)+'</tbody></table>' if prio else ''
    auth_html=f'<p class="notice">{safe(auth_note)}</p>' if meta.get('auth_probes') else ''
    role_html=(f'<p class="notice">{safe(role_note)}</p>' if meta.get('role_scenarios') or
               any(str(s.get('step','')).startswith('role_') for s in steps) else '')
    doc=_splice(doc,'</p><h2>Yönetici özeti</h2>',f'</p>{auth_html}{role_html}{platform_html}{discover_html}{snmp_html}{ai_html}{review_table}{inventory_html}<h2>Yönetici özeti</h2>')
    corr=json.loads((root/'UBDEN_CORRELATION.json').read_text(encoding='utf-8')) if (root/'UBDEN_CORRELATION.json').is_file() else {}
    correlation_html=''
    if corr and (corr.get('correlations') or corr.get('graph',{}).get('nodes')):
        ei=corr.get('exposure_index',{})
        correlation_html=('<h2>Çapraz-katman maruziyet analizi</h2><p>'+safe(corr.get('meaning'))+'</p>'+
            '<p><b>Maruziyet indeksi:</b> '+safe(ei.get('score'))+'/100 (Not '+safe(ei.get('grade'))+'). '+safe(ei.get('comment'))+
            ' · <a href="UBDEN_CORRELATION.json">Korelasyon kaydı</a></p>'+
            (('<p><b>İnsan-riski / e-posta duruşu:</b> '+safe(ei.get('human_score'))+'/100 (Not '+safe(ei.get('human_grade'))+
              '). <a href="UBDEN_OSINT.json">OSINT kaydı</a></p>') if ei.get('human_score') is not None else '')+
            '<table><thead><tr><th>Önem</th><th>Maruziyet kesişimi</th><th>Ayrıntı</th></tr></thead><tbody>'+
            ''.join('<tr><td>'+safe(SEVERITIES.get(c.get('severity'),'Bilgi'))+'</td><td>'+safe(c.get('title'))+'</td><td>'+safe(c.get('detail'))+'</td></tr>'
                    for c in corr.get('correlations',[]))+'</tbody></table>')
        chains=corr.get('attack_chains',[])
        if chains:
            correlation_html+='<h3>Olası saldırı zincirleri — analist doğrulaması gerekir</h3>'+''.join(
                '<p><b>'+safe(ch.get('name'))+'</b> — olasılık: '+safe(ch.get('likelihood'))+' · etki: '+safe(ch.get('impact'))+'</p><ol>'+
                ''.join('<li>'+safe(s)+'</li>' for s in ch.get('steps',[]))+'</ol>' for ch in chains)
        if corr.get('combined_actions'):
            correlation_html+=('<h3>Öncelikli birleşik aksiyonlar</h3><table><thead><tr><th>Öncelik</th><th>Aksiyon</th><th>Gerekçe / efor</th></tr></thead><tbody>'+
                ''.join('<tr><td>'+safe(a.get('priority'))+'</td><td>'+safe(a.get('action'))+'</td><td>'+safe(a.get('rationale'))+' · efor: '+safe(a.get('effort'))+'</td></tr>'
                        for a in corr['combined_actions'])+'</tbody></table>')
    tech=json.loads((root/'UBDEN_TECH_PROFILE.json').read_text(encoding='utf-8')) if (root/'UBDEN_TECH_PROFILE.json').is_file() else {}
    tech_html=''
    if tech and tech.get('matches'):
        tech_html=('<h2>Teknoloji ve platform tespiti</h2><p>'+safe(tech.get('note'))+
            ' · <a href="UBDEN_TECH_PROFILE.json">Platform kaydı</a></p>'+
            '<p>Aile dağılımı: '+safe(', '.join(f'{k}: {v}' for k,v in tech.get('families',{}).items()))+'</p>'+
            '<table><thead><tr><th>Platform</th><th>Adres</th><th>Sürüm</th><th>Güven</th><th>Yönetim portları</th><th>Doğrulanacak danışmalar</th></tr></thead><tbody>'+
            ''.join('<tr><td>'+safe(m.get('family'))+'</td><td>'+safe(m.get('ip'))+'</td><td>'+safe(m.get('version') or '—')+
                    '</td><td>'+safe(m.get('confidence'))+'</td><td>'+safe(', '.join(map(str,m.get('mgmt_ports_observed',[]))) or '—')+
                    '</td><td>'+safe('; '.join(m.get('advisories',[])))+'</td></tr>' for m in tech['matches'])+'</tbody></table>')
    cve=json.loads((root/'UBDEN_CVE.json').read_text(encoding='utf-8')) if (root/'UBDEN_CVE.json').is_file() else {}
    cve_html=''
    if cve and cve.get('items'):
        cve_html=('<h2>NVD CVE adayları — analist doğrulaması gerekir</h2><p>'+safe(cve.get('note'))+
            ' Sorgulanan platform: '+safe(cve.get('queried',0))+'; kritik/yüksek aday: '+safe(cve.get('critical_high_count',0))+
            ' · <a href="UBDEN_CVE.json">NVD kaydı</a></p>')
        for it in cve['items']:
            cve_html+=('<h3>'+safe(it.get('family'))+' '+safe(it.get('version'))+' — '+safe(it.get('cve_count',0))+
                ' CVE adayı</h3><p>Varlıklar: '+safe(', '.join(it.get('assets',[])[:8]) or '—')+' · CPE: '+safe(it.get('cpe'))+
                '</p><table><thead><tr><th>CVE</th><th>CVSS</th><th>Şiddet</th><th>Özet</th></tr></thead><tbody>'+
                ''.join('<tr><td>'+safe(c.get('id'))+'</td><td>'+safe(c.get('cvss') or '?')+'</td><td>'+safe(c.get('severity'))+
                        '</td><td>'+safe(c.get('summary'))+'</td></tr>' for c in it.get('cves',[]))+'</tbody></table>')
    insights=json.loads((root/'UBDEN_INSIGHTS.json').read_text(encoding='utf-8')) if (root/'UBDEN_INSIGHTS.json').is_file() else {}
    preflight=json.loads((root/'PREFLIGHT.json').read_text(encoding='utf-8')) if (root/'PREFLIGHT.json').is_file() else {}
    preflight_html=''
    if preflight:
        preflight_html=('<h2>Görev ön kontrolü</h2><p>'+safe(preflight.get('note',''))+
            ' · <a href="PREFLIGHT.json">Ön kontrol kaydı</a></p><table><thead><tr><th>Kontrol</th><th>Durum</th><th>Ayrıntı</th></tr></thead><tbody>'+
            ''.join('<tr><td>'+safe(item.get('name',''))+'</td><td>'+safe(item.get('status',''))+'</td><td>'+safe(item.get('detail',''))+'</td></tr>' for item in preflight.get('checks',[]))+'</tbody></table>')
    insight_html=''
    if insights:
        insight_html=('<h2>ATT&CK, CVSS ve düzeltme yol haritası</h2><p>'+safe(insights.get('meaning'))+'</p>'+
            '<p><a href="UBDEN_INSIGHTS.json">Analiz kayıtları</a> · <a href="ATTACK_LAYER.json">ATT&CK Navigator katmanı</a> · <a href="REMEDIATION_ROADMAP.md">Düzeltme yol haritası</a></p>'+
            '<p>Teknik eşleme: '+safe(len(insights.get('attck',[])))+' · CVSS taslağı: '+safe(len(insights.get('cvss_suggestions',[])))+' · Çevrimdışı örnek dosyası: '+safe(len(insights.get('hash_samples',{}).get('files',[])))+'</p>'+
            '<h3>ATT&CK eşlemeleri</h3><table><thead><tr><th>Teknik</th><th>Kaynak</th><th>Durum</th></tr></thead><tbody>'+
            ''.join('<tr><td>'+safe(item.get('techniqueID',''))+' · '+safe(item.get('techniqueName',''))+'</td><td>'+safe(item.get('source',''))+'</td><td>'+safe(item.get('status',''))+'</td></tr>' for item in insights.get('attck',[]))+'</tbody></table>'+
            '<h3>CVSS önerileri</h3><table><thead><tr><th>Bulgu</th><th>Vektör</th><th>Taban puan</th></tr></thead><tbody>'+
            ''.join('<tr><td>'+safe(item.get('finding_id',''))+'</td><td>'+safe(item.get('vector',''))+'</td><td>'+safe(item.get('base_score',''))+'</td></tr>' for item in insights.get('cvss_suggestions',[]))+'</tbody></table>'+
            '<table><thead><tr><th>Bulgu</th><th>Varlık</th><th>Önerilen düzeltme</th></tr></thead><tbody>'+''.join('<tr><td>'+safe(', '.join(item['findings']))+'</td><td>'+safe(', '.join(item['assets'][:6]))+'</td><td>'+safe(item['recommendation'])+'</td></tr>' for item in insights.get('remediation',[]))+'</tbody></table>')
    doc=_splice(doc,'<h2>Analist bulguları</h2>',correlation_html+tech_html+cve_html+risk_html+priority_html+network_html+ad_html+coverage_html+preflight_html+insight_html+analyst_html+'<h2>Analist bulguları</h2>')
    doc=_splice(doc,'<h2>Çalışma günlüğü</h2>',device_html+'<h2>Çalışma günlüğü</h2>')
    if (root/'STEP_AUDIT.json').is_file():
        doc=_splice(doc,'<h2>Çalışma günlüğü</h2>',
            '<p class="notice">Önceki adım durumları ham kanıta göre yeniden değerlendirildi. Orijinal steps.json korunmuştur. <a href="STEP_AUDIT.json">Yeniden değerlendirme kaydı</a></p><h2>Çalışma günlüğü</h2>')
    doc=_splice(doc,'</style></head>', '.riskbars{max-width:700px}.riskrow{display:grid;grid-template-columns:70px 1fr 32px;gap:12px;align-items:center;margin:7px 0}.risktrack{height:12px;background:#edf1f6;border-radius:7px}.risktrack i{height:12px;display:block;border-radius:7px}'
        '.catgroup{margin-top:26px;display:flex;align-items:center;gap:10px}.pill{background:var(--navy);color:#fff;border-radius:999px;padding:1px 11px;font-size:12px}'
        '.devcard{border:1px solid #dce5eb;border-left:4px solid var(--teal);border-radius:8px;padding:12px 16px;margin:10px 0;background:#fbfdff}'
        '.devhead{display:flex;align-items:center;gap:14px;flex-wrap:wrap}.dip code{background:#0d1b33;color:#7fe0e4;padding:2px 8px;border-radius:5px;font-size:13px}'
        '.dname{font-weight:700;color:var(--navy);font-size:15px}.dconf{margin-left:auto;font-size:12px;color:#4a5a72}'
        '.cmeter{display:inline-block;width:90px;height:9px;background:#e3ebf2;border-radius:6px;vertical-align:middle;overflow:hidden}'
        '.cmeter i{display:block;height:9px;background:linear-gradient(90deg,#00b9bd,#22d3a0)}'
        '.devmeta{display:flex;flex-wrap:wrap;gap:16px;color:#4a5a72;font-size:12.5px;margin:8px 0}.devmeta code{background:#eef4f8;padding:1px 6px;border-radius:4px}'
        'table.ports{margin:6px 0;font-size:12.5px}table.ports th{background:#f2f8f9}.devsig,.devrole,.devnote{margin:6px 0;font-size:12.5px;color:#4a5a72}'
        '.devnote{color:#9a6b1a}.dim{color:#8494ab;font-size:12.5px}</style></head>')
    if not (root/'MANUEL_TEST_PLANI.md').is_file():
        doc=doc.replace('<a href="MANUEL_TEST_PLANI.md">manuel test planını</a>','manuel test planını')
    (root/'REPORT.html').write_text(doc,encoding='utf-8')
    asset=root/'assets';asset.mkdir(exist_ok=True)
    if logo():
        import shutil;shutil.copy2(logo(),asset/logo().name)

def main():
    if len(sys.argv)!=2: raise SystemExit('Kullanım: python3 report_v2.py RUN_DIZINI')
    root=Path(sys.argv[1]).resolve()
    meta,steps,hosts,findings,review=read_data(root)
    steps,audit=audit_recorded_steps(root,steps)
    if audit:
        (root/'STEP_AUDIT.json').write_text(json.dumps({'schema':1,
            'note':'Orijinal steps.json ve ham kanitlar degistirilmedi; raporda bu duzeltilmis durumlar kullanildi.',
            'changes':audit},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if not (root/'DEVICE_INVENTORY.json').is_file() and hosts:
        try:
            # An old run has no reliable current neighbour cache: use saved XML only.
            build_inventory(root,meta,neighbours={})
        except (OSError,ValueError) as exc:
            print(f'Cihaz envanteri eski kanıttan çıkarılamadı: {exc}',file=sys.stderr)
    write_coverage(root,meta,steps,review)
    plan=write_plan(root,meta,steps,review,device_inventory(root),findings)
    write_insights(root,meta,steps,findings,review)
    try:
        import osint_facts, tech_fingerprint
        osint=osint_facts.build(root,meta)
        temp=root/'.UBDEN_OSINT.pending.json'
        temp.write_text(json.dumps(osint,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        temp.replace(root/'UBDEN_OSINT.json')
        tech=tech_fingerprint.write(root,meta,hosts,device_inventory(root))
        import cve_enrich
        cached=json.loads((root/'UBDEN_CVE.json').read_text(encoding='utf-8')) if (root/'UBDEN_CVE.json').is_file() else None
        if not cached or (not cached.get('items') and not cached.get('queried')):
            cve_enrich.write(root,tech)  # NVD'ye canlı, best-effort; sonuç önbelleğe yazılır
        CORR.write(root,meta,hosts,findings,device_inventory(root),ad_result(root),osint=osint,tech=tech)
    except (OSError,ValueError,TypeError) as exc:
        print(f'Korelasyon/OSINT/teknoloji üretilemedi: {type(exc).__name__}: {exc}',file=sys.stderr)
    errors={}
    for filename,executive in (('YONETICI_OZETI.pdf',True),('TEKNIK_RAPOR.pdf',False)):
        temp=root/('.'+filename+'.pending.pdf')
        try:
            pdf(root,temp.name,meta,steps,hosts,findings,review,executive=executive)
            if not temp.is_file() or not temp.stat().st_size:
                raise ValueError('PDF dosyası oluşturulamadı')
            temp.replace(root/filename)
        except Exception as exc:
            errors[filename]=f'{type(exc).__name__}: {exc}'
            temp.unlink(missing_ok=True)
            print(f'PDF üretim hatası ({filename}): {errors[filename]}',file=sys.stderr)
    filename='ANALIST_GOREV_RAPORU.pdf'
    temp=root/('.'+filename+'.pending.pdf')
    try:
        analyst_pdf(root,temp.name,plan,meta)
        if not temp.is_file() or not temp.stat().st_size:
            raise ValueError('Analist PDF dosyası oluşturulamadı')
        temp.replace(root/filename)
    except Exception as exc:
        errors[filename]=f'{type(exc).__name__}: {exc}'
        temp.unlink(missing_ok=True)
        print(f'PDF üretim hatası ({filename}): {errors[filename]}',file=sys.stderr)
    html_report(root,meta,steps,hosts,findings,review,errors)
    manifest=[]
    for path in root.rglob('*'):
        if path.is_file() and path.name!='SHA256SUMS.txt':
            manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}")
    (root/'SHA256SUMS.txt').write_text('\n'.join(sorted(manifest))+'\n',encoding='utf-8')
    print('Raporlar:',*(root/name for name in ('YONETICI_OZETI.pdf','TEKNIK_RAPOR.pdf','ANALIST_GOREV_RAPORU.pdf') if name not in errors),root/'REPORT.html')
    if errors:
        raise SystemExit('PDF hataları yukarıda gösterildi; HTML rapor ve sağlam PDF dosyaları oluşturuldu.')

if __name__=='__main__': main()
