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
from device_inventory import build_inventory

BASE = Path(__file__).resolve().parent
NAVY = colors.HexColor('#101b32')
TEAL = colors.HexColor('#00b9bd')
TEXT = colors.HexColor('#263249')
PALE = colors.HexColor('#edf7f8')
GRAY = colors.HexColor('#65758b')
SEVERITIES = {'critical':'Kritik','high':'Yüksek','medium':'Orta','low':'Düşük','info':'Bilgi'}
SEVERITY_COLORS = {'critical':'#9d174d','high':'#d84734','medium':'#e49722','low':'#337ec6','info':'#73859c'}
pdfmetrics.registerFont(TTFont('DV',str(BASE/'assets'/'DejaVuSans.ttf')))
pdfmetrics.registerFont(TTFont('DVB',str(BASE/'assets'/'DejaVuSans-Bold.ttf')))

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
    return (f"{summary.get('target','?')}: durum {status_label}; "
            f"uygun {summary.get('eligible_count','?')}; yanıt veren {summary.get('responding_count','?')}; "
            f"yanıt vermeyen {count if count is not None else 'bilinmiyor'}. "
            'Yanıt vermemesi sistemin kapalı olduğunu kanıtlamaz.'+method+coverage+anomaly)

def tool_rows(root, steps):
    path=root/'TOOL_ENVIRONMENT.json'
    if not path.exists():
        return []
    data=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(data.get('tools'),list):
        ran={str(step.get('tool','')).lower() for step in steps if step.get('status')=='ok'}
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
            executed=any(any(str(s.get('step','')).startswith(prefix) for prefix in used.get(name,())) and s.get('status')=='ok' for s in steps)
            category,url=info.get(name,('Uzman aracı',''))
            rows.append((name,'Kurulu' if available else 'Eksik', 'Çalıştırıldı' if executed else 'Çalıştırılmadı',category,url))
    return sorted(rows,key=lambda item:(item[2]!='Çalıştırıldı',item[0]))


def platform_lines(root, meta, steps):
    if int(meta.get('schema',0) or 0)<8:
        return []
    snapshot=meta.get('host_snapshot',{})
    lines=[]
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
    if ad.get('forest') or ad.get('domain_mode'):
        result.append(P(f"Orman: {ad.get('forest','?')} · Orman modu: {ad.get('forest_mode','?')} · Alan modu: {ad.get('domain_mode','?')}",st['SmallX']))
    if ad.get('dc_dns_records'):
        result.append(P('DC DNS kayıtları: '+', '.join(str(x.get('name',''))+':'+str(x.get('port',''))
                     for x in ad['dc_dns_records'] if isinstance(x,dict)),st['SmallX']))
    result.append(P('Bu bölüm dizin envanteridir. Ayrıcalık, parola ilkesi ve paylaşım izinleri ancak ayrıca kaydedilen kontrollerle değerlendirilmiş sayılır.',st['SmallX']))
    return result

def finding_story(root,f,st,width):
    result=[P(f"{f['id']}  ·  {f['title']}",st['FindingTitleX'])]
    metadata=[('Önem derecesi',SEVERITIES.get(f.get('severity'),'Bilgi')),
              ('Durum',f.get('status','')),('Etkilenen varlık',f.get('asset','')),
              ('Diğer etkilenenler',', '.join(f.get('affected_assets',[]))),
              ('Kategori',f.get('category','')),('Erişim noktası',f.get('access_point','')),
              ('Kullanıcı profili',f.get('user_profile','')),('Kök neden',f.get('root_cause','')),
              ('CVSS / referans', ' · '.join(x for x in (f.get('cvss',''),f.get('reference','')) if x))]
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
                        ports.append({'port':port.get('portid',''),'protocol':port.get('protocol',''), 'service':service.get('name','') if service is not None else '', 'product':service.get('product','') if service is not None else '', 'version':service.get('version','') if service is not None else ''})
                hosts.append({'ip':ip,'ports':ports,'evidence':str(path.relative_to(root))})
        except ET.ParseError:
            steps.append({'step':'parse','status':'error','detail':f'Bozuk Nmap XML: {path.name}'})
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
        if not isinstance(item,dict) or item.get('confirmed_response') is not True or item.get('version')!='1' or item.get('community')!='public':
            continue
        observations.append({'title':'SNMPv1 varsayılan public topluluğuyla bilgi okunabiliyor',
                             'severity':'medium','asset':str(item.get('target','')),
                             'description':'Tek salt okunur sysDescr sorgusuna SNMPv1/public yanıtı alındı. Erişim sınırları ve yanıtın kaynak cihazı analistçe doğrulanmalıdır.',
                             'impact':'Varsayılan toplulukla cihaz ve sürüm bilgisi edinilebilir; SNMPv1 trafik şifrelemez.',
                             'recommendation':'SNMPv1/v2c ve varsayılan toplulukları kapatın; gerekliyse SNMPv3, erişim kontrolü ve sınırlandırılmış yönetim ağı kullanın.',
                             'evidence':str(path.relative_to(root))})
    deduplicated={}
    for item in observations:
        key=(item['title'],item['asset'],item['severity'])
        if key not in deduplicated:
            deduplicated[key]=item
        elif item['evidence'] not in deduplicated[key]['evidence']:
            deduplicated[key]['evidence']+='; '+item['evidence']
    for i, item in enumerate(deduplicated.values(),1):
        findings.append({'id':f'OBS-{i:03d}','status':'taslak','source':'Otomatik gözlem','reference':'','cvss':'',**item})
    for i,item in enumerate(review.get('findings',[]),1):
        if not isinstance(item,dict): continue
        finding={'id':str(item.get('id') or f'PX-{i:03d}'),'title':str(item.get('title') or 'Başlıksız bulgu'), 'severity':str(item.get('severity') or 'info').lower(), 'status':str(item.get('status') or 'taslak').lower(), 'asset':str(item.get('asset') or ''), 'affected_assets':[str(x) for x in item.get('affected_assets',[]) if isinstance(x,str)] if isinstance(item.get('affected_assets',[]),list) else [], 'description':str(item.get('description') or ''), 'impact':str(item.get('impact') or ''), 'recommendation':str(item.get('recommendation') or ''), 'evidence':str(item.get('evidence') or ''), 'evidence_sha256':str(item.get('evidence_sha256') or ''), 'evidence_items':item.get('evidence_items',[]) if isinstance(item.get('evidence_items',[]),list) else [], 'reference':str(item.get('reference') or ''), 'cvss':str(item.get('cvss') or ''), 'reproduction':str(item.get('reproduction') or ''), 'reviewed_by':str(item.get('reviewed_by') or ''), 'category':str(item.get('category') or ''), 'access_point':str(item.get('access_point') or ''), 'user_profile':str(item.get('user_profile') or ''), 'root_cause':str(item.get('root_cause') or ''), 'remediation_priority':str(item.get('remediation_priority') or ''), 'retest_status':str(item.get('retest_status') or ''), 'disposition_reason':str(item.get('disposition_reason') or ''), 'source':'Analist'}
        if finding['severity'] not in SEVERITIES: finding['severity']='info'
        if finding['status'] not in ('doğrulandı','taslak','yanlış pozitif','risk kabul edildi'): finding['status']='taslak'
        if finding['status']=='doğrulandı' and not verified_finding(root,item):
            finding['status']='taslak'
            finding['description'] += '\nKanıt / doğrulama alanları eksik veya dosya özeti değişmiş; doğrulandı sayılmadı.'
        findings.append(finding)
    findings.sort(key=lambda f:(list(SEVERITIES).index(f['severity']),f['id']))
    return meta,steps,hosts,findings,review

def footer(canvas,doc):
    canvas.saveState()
    w,h=A4
    canvas.setStrokeColor(TEAL);canvas.setLineWidth(1)
    canvas.line(18*mm,h-17*mm,w-18*mm,h-17*mm)
    canvas.setFont('DV',8);canvas.setFillColor(GRAY)
    canvas.drawString(18*mm,13*mm,'UBDEN CYBER SECURITY SYSTEMS  |  GIZLI - YETKILI ALICILAR')
    canvas.drawRightString(w-18*mm,13*mm,f'Sayfa {doc.page}')
    canvas.restoreState()

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
    story=[]
    if logo():
        from PIL import Image as PILImage
        with PILImage.open(logo()) as im:
            ratio=im.height/im.width
        story.extend([Spacer(1,12*mm),Image(str(logo()),width=64*mm,height=min(64*mm*ratio,26*mm)),Spacer(1,23*mm)])
    else:
        story.append(P('UBDEN Cyber Security Systems',st['CoverTitleX']))
    story.append(P(f"{meta.get('tester') or 'Test ekibi'} tarafından UBDEN Cyber Security Systems ile hazırlanmıştır.",st['SmallX']))
    story.append(P('Yönetici Özeti' if executive else 'Teknik Güvenlik Değerlendirme Raporu',st['CoverTitleX']))
    story.append(HRFlowable(width='100%',thickness=3,color=TEAL,spaceAfter=13))
    for key,value in [('MÜŞTERİ',meta.get('client')),('PROJE',meta.get('project')),('ÜRÜN',meta.get('product','UBDEN Cyber Security Systems')),('RAPOR TARİHİ',meta.get('finished_at',meta.get('started_at'))),('YETKİ REFERANSI',meta.get('authorization_reference')),('TEST SORUMLUSU',meta.get('tester')),('KAYIT KİMLİĞİ',meta.get('id'))]:
        story += [P(key,st['LabelX']),P(value,st['ValueX'])]
    story += [Spacer(1,10*mm),P('GİZLİ • Müşteri ve görevlendirilmiş ekip ile sınırlı dağıtım',st['NoticeX']),PageBreak()]
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
        story.append(P(devices.get('limits',''),st['SmallX']))
        if devices.get('mac_count',0)==0:
            story.append(P('MAC görülmedi: hedefler yönlendirici arkasında olabilir; üretici/model bu raporda doğrulanmadı.',st['SmallX']))
        flagged=[item for item in devices['devices'] if item.get('notices') or item.get('review_notes')]
        story.append(P(f'MAC belirsizliği veya hizmet inceleme notu bulunan adres: {len(flagged)}. Bu işaretler doğrulanmış zafiyet değildir.',st['BodyX']))
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
    cells=[[P(x,st['SmallX']) for x in ('Kritik','Yüksek','Orta','Düşük','Bilgi')],[P(str(counts[x]),st['ValueX']) for x in SEVERITIES]]
    t=Table(cells,colWidths=[doc.width/5]*5)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PALE),('BOX',(0,0),(-1,-1),0.5,TEAL),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),8)]))
    story += [t,Spacer(1,5*mm)]
    if confirmed:
        story.append(severity_chart(counts,doc.width))
    story.append(P(f'Doğrulanmayı bekleyen bulgu: {len(pending)}. Tamamlanan adım: {sum(s.get("status")=="ok" for s in steps)}. Hatalı/eksik/atlanan adım: {sum(s.get("status") not in ("ok","excluded") for s in steps)}.',st['BodyX']))
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
        for case in meta.get('role_scenarios',[]):
            attempt=[s for s in steps if str(s.get('step','')).startswith('role_'+str(case.get('id'))+'_')]
            story.append(P(f"{case.get('id')} | {case.get('kind')} | {case.get('owner')} → {case.get('challenger')} | HTTPS GET {case.get('target')}:{case.get('port')}{case.get('path')} | Durum: {', '.join(x.get('status','?') for x in attempt) or 'atlanmış'}",st['SmallX']))
        for row in review.get('cases',[]):
            if isinstance(row,dict):
                story.append(P(f"{row.get('id','?')} | {row.get('title','')} | {row.get('state','bekliyor')} | {row.get('note','') or 'Sonuç yok'} | Kanıt: {row.get('evidence','yok') or 'yok'} | SHA-256: {row.get('sha256','yok') or 'yok'}",st['SmallX']))
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

def html_report(root,meta,steps,hosts,findings,review,report_errors=None):
    state=assess(root,review)
    discovery=discovery_summaries(root)
    snmp=snmp_summaries(root)
    role_note,ai_note,ai_text=advanced_summary(root,meta,steps)
    report_errors=report_errors or {}
    pdf_links=' · '.join(f'<a href="{name}">{title}</a>' for name,title in
                       (('YONETICI_OZETI.pdf','Yönetici PDF'),('TEKNIK_RAPOR.pdf','Teknik PDF'))
                       if name not in report_errors and (root/name).is_file())
    pdf_notice=('PDF üretim hatası: '+', '.join(f'{name}: {reason}' for name,reason in report_errors.items())) if report_errors else ''
    def li(v): return f'<li>{safe(v)}</li>'
    rows=''.join(f'<tr><td><a href="#bulgu-{i}">{safe(f.get("id"))}</a></td><td>{safe(f.get("title"))}</td><td>{safe(SEVERITIES.get(f.get("severity"),"Bilgi"))}</td><td>{safe(f.get("status"))}</td><td>{safe(f.get("asset"))}</td><td>{evidence_link(root,f.get("evidence"))}</td></tr>' for i,f in enumerate(findings,1))
    detail_fields=(('Kaynak','source'),('Durum','status'),('Varlık','asset'),('Diğer etkilenenler','affected_assets'),('Kategori','category'),('Erişim noktası','access_point'),('Kullanıcı profili','user_profile'),('Kök neden','root_cause'),('CVSS','cvss'),('Açıklama','description'),('Tekrar üretim','reproduction'),('Doğrulayan','reviewed_by'),('İş etkisi','impact'),('Düzeltme önerisi','recommendation'),('Düzeltme önceliği','remediation_priority'),('Yeniden test','retest_status'),('Kapatma / kabul gerekçesi','disposition_reason'),('Referans','reference'))
    finding_details=''.join(
        f'<section class="finding" id="bulgu-{i}"><h3>{safe(f.get("id"))} · {safe(f.get("title"))}</h3>'
        f'<p><b>Şiddet:</b> {safe(SEVERITIES.get(f.get("severity"),"Bilgi"))} · <b>Doğrulama:</b> {safe(f.get("status"))}</p>'+
        ''.join(f'<p><b>{label}:</b> {safe(", ".join(f[key]) if isinstance(f.get(key),list) else f.get(key))}</p>' for label,key in detail_fields if f.get(key))+
        '<h4>Kanıt zinciri</h4><ul>'+''.join('<li>'+safe(item['caption'])+': '+evidence_link(root,item['path'])+
        (' · SHA-256 '+safe(item['sha256']) if item['sha256'] else '')+'</li>' for item in finding_evidence(f))+'</ul></section>'
        for i,f in enumerate(findings,1))
    inventory=''.join(f'<tr><td>{safe(h.get("ip"))}</td><td>{safe(", ".join(str(p.get("port",""))+"/"+str(p.get("service","")) for p in h.get("ports",[])))}</td><td>{evidence_link(root,h.get("evidence"))}</td></tr>' for h in hosts)
    devices=device_inventory(root)
    device_rows=''.join('<tr>'+
        ''.join(f'<td>{safe(value)}</td>' for value in (item.get('ip'),', '.join(item.get('hostnames',[])) or '—',
                ', '.join(x.get('name','')+' (%'+x.get('accuracy','?')+')' for x in item.get('os_matches',[])) or '—',
                item.get('mac') or 'görülmedi',item.get('vendor'),item.get('category'),item.get('confidence')))+
        '<td>'+safe(' · '.join(item.get('signals',[])+item.get('notices',[])+item.get('review_notes',[])))+'</td><td>'+evidence_link(root,item.get('evidence'))+'</td></tr>'
        for item in devices.get('devices',[]))
    category_rows=''.join(f'<tr><td>{safe(name)}</td><td>{count}</td></tr>' for name,count in sorted(devices.get('categories',{}).items(),key=lambda row:(-row[1],row[0])))
    service_rows=''.join(f'<tr><td>{safe(name)}</td><td>{count}</td></tr>' for name,count in sorted(devices.get('services',{}).items(),key=lambda row:(-row[1],row[0])))
    device_html=('<h2>Cihaz ve MAC envanteri</h2><p>'+safe(devices.get('limits'))+'</p><p>Adres: '+safe(devices.get('host_count'))+' · MAC görülen: '+safe(devices.get('mac_count'))+' · Belirsiz sınıf: '+safe(devices.get('unknown_count'))+'</p><p>OUI kaynakları: '+safe(', '.join(devices.get('oui_sources',[])) or 'yüklenemedi')+'</p><p><a href="DEVICE_INVENTORY.json">Makine tarafından okunabilir envanter (JSON)</a></p><h3>Cihaz sınıfları</h3><table><thead><tr><th>Sınıf adayı</th><th>Adres</th></tr></thead><tbody>'+category_rows+'</tbody></table><h3>Servis dağılımı</h3><table><thead><tr><th>Port / servis</th><th>Adres</th></tr></thead><tbody>'+service_rows+'</tbody></table><h3>Cihaz kayıtları</h3><table><thead><tr><th>IP</th><th>Ad</th><th>OS tahmini</th><th>MAC</th><th>Üretici</th><th>Cihaz adayı</th><th>Güven</th><th>Gerekçe ve inceleme</th><th>Kanıt</th></tr></thead><tbody>'+device_rows+'</tbody></table>') if devices else ''
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
    review_table='<h2>Manuel test kayıtları</h2><p>Durum: '+('analist kayıtları tamamlandı' if state['complete'] else 'eksik veya inceleme bekliyor')+f"; bekleyen başlık: {state['pending']}; inceleyen: {safe(state['reviewer'] or 'yok')}</p><table><thead><tr><th>Test</th><th>Durum</th><th>Sonuç</th><th>Kanıt / SHA-256</th></tr></thead><tbody>"
    review_table+=''.join(f'<tr><td>{safe(c.get("id"))}</td><td>{safe(c.get("state"))}</td><td>{safe(c.get("note"))}</td><td>{evidence_link(root,c.get("evidence"))} / {safe(c.get("sha256"))}</td></tr>' for c in review.get('cases',[]) if isinstance(c,dict))+'</tbody></table>'
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
    counts=Counter(f['severity'] for f in findings if f['status']=='doğrulandı')
    risk_html='<h2>Doğrulanmış bulguların önem dağılımı</h2><div class="riskbars">'+''.join(
        f'<div class="riskrow"><span>{safe(label)}</span><div class="risktrack"><i style="width:{max(2,round(100*counts[key]/max(max(counts.values(),default=0),1)))}%;background:{SEVERITY_COLORS[key]}"></i></div><b>{counts[key]}</b></div>'
        for key,label in SEVERITIES.items())+'</div>'
    priority_html='<h2>Düzeltme öncelikleri</h2><table><thead><tr><th>ID</th><th>Önem</th><th>Varlık</th><th>İlk aksiyon</th></tr></thead><tbody>'+''.join(
        '<tr><td>'+safe(f['id'])+'</td><td>'+safe(SEVERITIES[f['severity']])+'</td><td>'+safe(f['asset'])+'</td><td>'+safe(f.get('remediation_priority') or f.get('recommendation'))+'</td></tr>'
        for f in findings if f['status']=='doğrulandı')+'</tbody></table>'
    auth_html=f'<p class="notice">{safe(auth_note)}</p>' if meta.get('auth_probes') else ''
    role_html=(f'<p class="notice">{safe(role_note)}</p>' if meta.get('role_scenarios') or
               any(str(s.get('step','')).startswith('role_') for s in steps) else '')
    doc=doc.replace('</p><h2>Yönetici özeti</h2>',f'</p>{auth_html}{role_html}{platform_html}{discover_html}{snmp_html}{ai_html}{review_table}{inventory_html}<h2>Yönetici özeti</h2>')
    doc=doc.replace('<h2>Analist bulguları</h2>',risk_html+priority_html+network_html+ad_html+coverage_html+'<h2>Analist bulguları</h2>')
    doc=doc.replace('<h2>Çalışma günlüğü</h2>',device_html+'<h2>Çalışma günlüğü</h2>')
    doc=doc.replace('</style></head>', '.riskbars{max-width:700px}.riskrow{display:grid;grid-template-columns:70px 1fr 32px;gap:12px;align-items:center;margin:7px 0}.risktrack{height:12px;background:#edf1f6;border-radius:7px}.risktrack i{height:12px;display:block;border-radius:7px}</style></head>')
    doc=doc.replace('Kimlik doğrulamalı iş akışları ve manuel istismar doğrulaması bu çıktıda yer almaz.', 'Otomatik kimlikli erişim kontrolü yalnızca durum kodlarını karşılaştırır. İnsan tarafından yapılan testler yalnızca yukarıdaki manuel test kayıtlarıyla belgelenmişse bu rapora dahildir.')
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
    if not (root/'DEVICE_INVENTORY.json').is_file() and hosts:
        try:
            # An old run has no reliable current neighbour cache: use saved XML only.
            build_inventory(root,meta,neighbours={})
        except (OSError,ValueError) as exc:
            print(f'Cihaz envanteri eski kanıttan çıkarılamadı: {exc}',file=sys.stderr)
    write_coverage(root,meta,steps,review)
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
    html_report(root,meta,steps,hosts,findings,review,errors)
    manifest=[]
    for path in root.rglob('*'):
        if path.is_file() and path.name!='SHA256SUMS.txt':
            manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}")
    (root/'SHA256SUMS.txt').write_text('\n'.join(sorted(manifest))+'\n',encoding='utf-8')
    print('Raporlar:',*(root/name for name in ('YONETICI_OZETI.pdf','TEKNIK_RAPOR.pdf') if name not in errors),root/'REPORT.html')
    if errors:
        raise SystemExit('PDF hataları yukarıda gösterildi; HTML rapor ve sağlam PDF dosyaları oluşturuldu.')

if __name__=='__main__': main()
