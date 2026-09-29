/* Offline, dependency-free UBDEN report explorer. All report text is escaped before display. */
(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const token = $('meta[name="csrf-token"]').content;
  const titles = {overview:'Genel Bakış',findings:'Gözlemler',assets:'Cihazlar & Servisler',ad:'Active Directory',
    surfaces:'Teknik Yüzeyler',cve:'CVE Adayları',correlation:'Korelasyon',coverage:'Kapsam & Adımlar',
    tasks:'Analist Görevleri',evidence:'Kanıt & Dosyalar',reports:'Rapor Çıktıları'};
  const colors = ['#25d5ca','#4ca7ee','#ffbd69','#fb7084','#a891ef','#6de2ab','#74a7bc','#d9b575','#e989ce','#7fd1da'];
  const state = {model:null,page:'overview',search:'',executive:false,private:false,surface:'web',
    filters:{severity:'',findingStatus:'',subnet:'',category:'',stepStatus:'',fileType:''},drawer:null};
  let toastTimer;

  function esc(value){return String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
  function mask(value){let s=String(value ?? '');if(!state.private)return s;
    return s.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,'•••.•••.•••.•••')
      .replace(/\b(?:[\da-f]{2}:){5}[\da-f]{2}\b/gi,'••:••:••:••:••:••');}
  function txt(value){return esc(mask(value));}
  function arr(value){return Array.isArray(value)?value:[];}
  function ds(name){return state.model?.datasets?.[name] || {};}
  function review(kind,id){return state.model?.reviews?.[kind]?.[id] || {};}
  function fstatus(item){return review('findings',item.id).status || item.status || 'taslak';}
  function tstatus(item){return review('tasks',item.id).status || item.status || 'bekliyor';}
  function match(value){return !state.search || String(value ?? '').toLocaleLowerCase('tr').includes(state.search);}
  function icon(name){return `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;}
  function badge(value){const v=String(value ?? '—');let cls='muted';
    if(/kritik|critical|yüksek|high/i.test(v))cls='high';else if(/orta|medium|kısmi|incelemede|devam/i.test(v))cls='medium';
    else if(/doğrulandı|tamamlandı|çalıştı|ok|eşleşiyor/i.test(v))cls='verified';else if(/bilgi|info/i.test(v))cls='info';
    return `<span class="badge ${cls}">${esc(v)}</span>`;}
  function notice(message,info=false){return `<div class="notice ${info?'info':''}">${esc(message)}</div>`;}
  function linkFile(path,label){if(!path)return '<span class="muted">—</span>';
    return `<button type="button" class="btn-link filepath" data-action="file" data-path="${esc(path.replaceAll('\\','/'))}">${txt(label || path)}</button>`;}
  function links(paths){const list=Array.isArray(paths)?paths:(typeof paths==='string'?paths.split(';').map(x=>x.trim()).filter(Boolean):[]);
    return list.length?`<div class="evidence-links">${list.map(p=>linkFile(p)).join('')}</div>`:'<span class="muted">Kanıt bağlantısı yok</span>';}
  function table(headings,rows){if(!rows.length)return '<div class="empty">Bu görünüm için kayıt yok.</div>';
    return `<div class="table-wrap"><table class="data-table"><thead><tr>${headings.map(v=>`<th>${esc(v)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(v=>`<td>${v}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;}
  function intro(title,description,meta=''){return `<div class="page-intro"><div><h2>${esc(title)}</h2><p>${esc(description)}</p></div>${meta?`<div class="page-meta">${meta}</div>`:''}</div>`;}
  function empty(title,subtitle){return `<div class="empty">${icon('folder')}<h3>${esc(title)}</h3><p>${esc(subtitle)}</p></div>`;}
  function keyValues(pairs){return `<dl class="kv">${pairs.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;}
  function chips(values){const list=arr(values);if(!list.length)return '<span class="muted">—</span>';
    return `<div class="chip-cloud">${list.map(v=>`<span class="name-chip mono">${txt(v)}</span>`).join('')}</div>`;}
  function nameList(title,values,noun){const all=arr(values);if(!all.length)return '';
    const list=all.filter(v=>match(v)),shown=list.slice(0,300);
    return `<details class="folder-group name-group" ${state.search&&list.length?'open':''}><summary>${icon('list')}${esc(title)}<small>${list.length}${list.length!==all.length?'/'+all.length:''} ${esc(noun)}</small></summary>
      <div class="chip-pad">${shown.map(v=>`<span class="name-chip mono">${txt(v)}</span>`).join('')||'<span class="muted small">Arama ile eşleşen kayıt yok.</span>'}${list.length>shown.length?`<span class="muted small"> +${list.length-shown.length} daha</span>`:''}</div></details>`;}
  function barLines(entries,max=10){const list=entries.slice(0,max);const m=Math.max(1,...list.map(x=>Number(x[1])||0));
    return list.map(([name,n],i)=>`<div class="barline"><span class="barname" title="${esc(name)}">${txt(name)}</span><span class="bartrack"><b style="width:${Math.max(3,100*(Number(n)||0)/m)}%;background:${colors[i%colors.length]}"></b></span><span class="barnum">${esc(n)}</span></div>`).join('') || '<span class="muted">Veri yok</span>';}
  function donut(entries,label=''){const data=entries.filter(x=>Number(x[1])>0);const total=data.reduce((n,x)=>n+Number(x[1]),0);
    if(!total)return '<div class="empty">Grafik verisi yok.</div>';
    if(data.length===1)return `<svg class="chart" viewBox="0 0 200 200" role="img" aria-label="${esc(label)} grafiği"><circle cx="100" cy="100" r="59" fill="none" stroke="${colors[0]}" stroke-width="21"/><text x="100" y="101" text-anchor="middle" style="font-size:27px;fill:#efffff;font-weight:800">${total}</text><text x="100" y="119" text-anchor="middle">${esc(label)}</text></svg><div class="legend"><span><i style="background:${colors[0]}"></i>${esc(data[0][0])} ${esc(data[0][1])}</span></div>`;
    let angle=-Math.PI/2;const cx=100,cy=100,r=69,inner=48;
    const polar=(rad,rr)=>[cx+Math.cos(rad)*rr,cy+Math.sin(rad)*rr];
    const paths=data.map(([name,n],i)=>{const start=angle,end=angle+Math.PI*2*Number(n)/total;angle=end;
      const [x1,y1]=polar(start,r),[x2,y2]=polar(end,r),[x3,y3]=polar(end,inner),[x4,y4]=polar(start,inner);
      const large=end-start>Math.PI?1:0;
      return `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${x3} ${y3} A ${inner} ${inner} 0 ${large} 0 ${x4} ${y4} Z" fill="${colors[i%colors.length]}"><title>${esc(name)}: ${esc(n)}</title></path>`;}).join('');
    return `<svg class="chart" viewBox="0 0 200 200" role="img" aria-label="${esc(label)} grafiği">${paths}<text x="100" y="101" text-anchor="middle" style="font-size:27px;fill:#efffff;font-weight:800">${total}</text><text x="100" y="119" text-anchor="middle" style="font-size:10px">${esc(label)}</text></svg><div class="legend">${data.map(([name,n],i)=>`<span><i style="background:${colors[i%colors.length]}"></i>${esc(name)} ${esc(n)}</span>`).join('')}</div>`;}
  function topPorts(){const c=new Map();for(const dev of arr(ds('DEVICE_INVENTORY').devices))for(const p of arr(dev.ports)){
    const key=`${p.port}/${p.protocol||'tcp'}`;c.set(key,(c.get(key)||0)+1);}return [...c].sort((a,b)=>b[1]-a[1]);}
  function subnet(ip){const toNumber=value=>{const parts=String(value).split('.').map(Number);if(parts.length!==4||parts.some(n=>!Number.isInteger(n)||n<0||n>255))return null;
      return (((parts[0]<<24)>>>0)|(parts[1]<<16)|(parts[2]<<8)|parts[3])>>>0;};
    const address=toNumber(ip);if(address===null)return 'Diğer';
    for(const target of arr(ds('engagement').targets)){const [network,bitsText]=String(target).split('/'),bits=Number(bitsText),base=toNumber(network);
      if(base===null||!Number.isInteger(bits)||bits<0||bits>32)continue;
      const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;
      if((address&mask)===(base&mask))return target;}
    return 'Diğer';}
  function pageWarnings(){return state.model.warnings.map(w=>notice(w)).join('')+
    state.model.load_errors.map(w=>notice(w)).join('');}
  function stat(label,value,extra,color,iconName,page){return `<button class="card stat-card ${color}" data-action="page" data-target="${page}" type="button" style="text-align:left;width:100%"><span class="label">${esc(label)}</span><strong>${esc(value)}</strong><span class="delta">${esc(extra)}</span><span class="glyph">${icon(iconName)}</span></button>`;}

  function renderExecutive(){const m=state.model,o=m.overview,e=ds('engagement'),c=ds('UBDEN_CORRELATION');
    const actions=arr(c.combined_actions).slice(0,5);
    const confirmed=m.findings.filter(f=>fstatus(f)==='doğrulandı');
    return `<div class="hero"><div><span class="eyebrow">YÖNETİCİ GÖRÜNÜMÜ</span><h2>${esc(e.client||m.root_name)} / ${esc(e.project||'PENTEST')}</h2>
      <p>${o.hosts} gözlenen cihaz ve ${o.findings} otomatik gözlem için analist incelemesi sürüyor. Resmi bulgu sayısı yalnız kanıtla doğrulanan kayıtları içerir.</p>
      <div class="scope">${arr(e.targets).map(t=>`<span class="meta-chip">${txt(t)}</span>`).join('')}</div></div>
      <div class="score"><strong>${c.exposure_index?.score??'—'}</strong><small>Kaynak endeksi<br>${esc(c.exposure_index?.grade||'')}</small></div></div>
      <div class="grid cols-4">${stat('Gözlenen cihaz',o.hosts,'Kapsam içi görünürlük','teal','server','assets')}${stat('Analistçe doğrulandı',o.confirmed,'Resmi bulgu','blue','check','findings')}${stat('İnceleme adayı',o.findings-o.confirmed,'Henüz kesin değil','amber','alert','findings')}${stat('Görev',o.tasks,'Analist iş listesi','red','list','tasks')}</div>
      <div class="section-head"><h3>Yorum sınırları</h3></div><div class="notice-list">${pageWarnings()}</div>
      <div class="grid cols-2"><div class="card"><div class="card-header"><h3>Öncelikli aksiyonlar</h3><small>Kaynak korelasyon önerileri</small></div>
      ${actions.map((a,i)=>`<div class="card" style="margin:8px 0;padding:12px"><div class="status-strip">${badge(a.priority)}<span class="small muted">${esc(a.effort||'')}</span></div><p>${esc(a.action)}</p><small class="muted">${esc(a.rationale)}</small></div>`).join('')||'<p class="muted">Aksiyon kaydı yok.</p>'}</div>
      <div class="card"><div class="card-header"><h3>Karar özeti</h3><small>Rapor kaynaklı</small></div>
      ${keyValues([['Yetkili kapsam',txt(arr(e.targets).join(', '))],['Başlangıç',esc(e.started_at||'—')],['Bitiş',esc(e.finished_at||'—')],['Kapsam kontrolü',esc(arr(ds('ASSESSMENT_COVERAGE').controls).length)],['CVE adayı',esc(o.cve_candidates)]])}
      <div class="divider"></div><h3>Doğrulanmış bulgular</h3>${confirmed.length?confirmed.map(f=>`<p><button class="btn-link" data-action="finding" data-id="${esc(f.id)}">${esc(f.id)} · ${esc(f.title)}</button></p>`).join(''):'<p class="muted">Henüz analistçe doğrulanmış bulgu yok.</p>'}</div></div>`;}
  function renderSearchResults(){const findings=state.model.findings.filter(f=>match(`${f.id} ${f.title} ${f.asset} ${f.description}`));
    const devices=arr(ds('DEVICE_INVENTORY').devices).filter(d=>match(`${d.ip} ${d.display_name} ${d.vendor} ${d.category}`));
    const tasks=arr(ds('ANALIST_GOREV_RAPORU').tasks).filter(t=>match(`${t.id} ${t.title} ${arr(t.targets).join(' ')}`));
    const files=state.model.manifest.files.filter(f=>match(f.path)).slice(0,30);
    return intro(`“${state.search}” arama sonuçları`,'Tüm raporun gözlem, cihaz, görev ve dosya kayıtları üzerinde eşleşmeler.',
      `<span class="meta-chip">${findings.length+devices.length+tasks.length+files.length} sonuç</span>`)+
      `<div class="section-head"><h3>Gözlemler (${findings.length})</h3></div>${table(['ID','Başlık','Varlık','Durum'],findings.slice(0,30).map(f=>[
        `<button class="btn-link" data-action="finding" data-id="${esc(f.id)}">${esc(f.id)}</button>`,esc(f.title),txt(f.asset),badge(fstatus(f))]))}`+
      `<div class="section-head"><h3>Cihazlar (${devices.length})</h3></div>${table(['IP','Kategori','Üretici'],devices.slice(0,30).map(d=>[
        `<button class="btn-link mono" data-action="asset" data-ip="${esc(d.ip)}">${txt(d.ip)}</button>`,esc(d.category),esc(d.vendor)]))}`+
      `<div class="section-head"><h3>Görevler (${tasks.length})</h3></div>${table(['ID','Başlık','Durum'],tasks.slice(0,30).map(t=>[
        `<button class="btn-link" data-action="task" data-id="${esc(t.id)}">${esc(t.id)}</button>`,esc(t.title),badge(tstatus(t))]))}`+
      `<div class="section-head"><h3>Dosyalar (${files.length})</h3></div>${table(['Yol','Bütünlük'],files.map(f=>[linkFile(f.path),badge(f.sha_status)]))}`;}
  function renderOverview(){if(state.executive)return renderExecutive();const m=state.model,o=m.overview,e=ds('engagement'),c=ds('UBDEN_CORRELATION'),inv=ds('DEVICE_INVENTORY');
    const cats=Object.entries(inv.categories||{}).sort((a,b)=>b[1]-a[1]);const cov=Object.entries(o.coverage||{});
    const score=c.exposure_index?.score;const grade=c.exposure_index?.grade;
    return `<div class="hero"><div><span class="eyebrow">RAPOR İSTİHBARAT MERKEZİ</span><h2>${esc(e.client||m.root_name)} <span class="muted">/ ${esc(e.project||'PENTEST')}</span></h2>
      <p>Yetkili kapsamdan derlenen cihazlar, otomatik gözlemler, analist görevleri ve kanıt zincirleri tek çalışma alanında. Taslak kayıtlar doğrulanmış bulgu sayılmaz.</p>
      <div class="scope">${arr(e.targets).map(t=>`<span class="meta-chip">${txt(t)}</span>`).join('')}<span class="meta-chip">${esc(e.status||'—')}</span><span class="meta-chip">${esc(e.profile||'—')} profil</span></div></div>
      <div class="score" title="Rapor kaynaklı maruziyet endeksi; doğrulanmış açık sayısı değil"><strong>${score??'—'}</strong><small>Kaynak endeksi<br>${esc(grade||'')}</small></div></div>
      <div class="grid cols-4">${stat('Gözlenen cihaz',o.hosts,`${arr(e.targets).length} hedef ağda gözlendi`,'teal','server','assets')}${stat('İnceleme adayı',o.findings,'Analist onayı bekler','amber','alert','findings')}${stat('Doğrulanmış bulgu',o.confirmed,'İnceleme kaydıyla','blue','check','findings')}${stat('Analist görevi',o.tasks,'Görev iş listesi','red','list','tasks')}</div>
      <div class="section-head"><h3>Kaynak gerçekleri</h3><span class="sub">Kayıtların anlamı ve sınırları</span></div><div class="notice-list">${pageWarnings()}</div>
      <div class="grid cols-3"><div class="card"><div class="card-header"><h3>Gözlem önem dağılımı</h3><small>${o.findings} otomatik gözlem</small></div>${donut(Object.entries(o.severity||{}),'gözlem')}</div>
      <div class="card"><div class="card-header"><h3>Cihaz kategorileri</h3><small>En çok görülenler</small></div>${barLines(cats,8)}</div>
      <div class="card"><div class="card-header"><h3>Yürütme kapsamı</h3><small>${arr(ds('ASSESSMENT_COVERAGE').controls).length} kontrol</small></div>${donut(cov,'kontrol')}</div></div>
      <div class="grid cols-2" style="margin-top:16px"><div class="card"><div class="card-header"><h3>En sık gözlenen portlar</h3><small>Varlık bazında</small></div>${barLines(topPorts(),9)}</div>
      <div class="card"><div class="card-header"><h3>Rapor bütünlüğü</h3><small>SHA-256</small></div>
      ${keyValues([['Dosya',esc(o.files)],['Hash listesi',esc(m.manifest.listed_count)],['Eşleşen',badge(m.manifest.hash_counts['eşleşiyor']||0)],['Uyuşmayan',badge(m.manifest.hash_counts['uyuşmuyor']||0)],['Listede olmayan',esc(m.manifest.hash_counts['listede yok']||0)]])}
      <div class="divider"></div><button class="btn btn-outline" data-action="page" data-target="evidence">Kanıt ağacını aç ${icon('arrow')}</button></div></div>`;}

  function filteredFindings(){return arr(state.model.findings).filter(f=>{
    const r=fstatus(f);if(state.filters.severity && f.severity!==state.filters.severity)return false;
    if(state.filters.findingStatus && r!==state.filters.findingStatus)return false;
    if(state.filters.subnet && subnet(f.asset)!==state.filters.subnet)return false;
    return match([f.id,f.title,f.asset,f.description,f.cwe,r].join(' '));});}
  function renderFindings(){const list=filteredFindings();const all=state.model.findings;
    const rows=list.map(f=>[`<button class="btn-link strong" data-action="finding" data-id="${esc(f.id)}">${esc(f.id)}</button><div class="small muted">${esc(f.source)}</div>`,
      `<span class="strong">${esc(f.title)}</span>`, `<button class="btn-link mono" data-action="asset" data-ip="${esc(String(f.asset).split(':')[0])}">${txt(f.asset)}</button>`,badge(f.severity),badge(fstatus(f)),
      `<button class="btn btn-small" data-action="edit" data-kind="findings" data-id="${esc(f.id)}">İncele</button>`]);
    const statusCounts={};for(const f of all)statusCounts[fstatus(f)]=(statusCounts[fstatus(f)]||0)+1;
    return intro('Gözlem incelemesi','Otomatik gözlemler taslaktır. Analist doğrulaması, seçilmiş kanıt ve inceleme notu resmi duruma geçiş için gereklidir.',
      `<span class="meta-chip">${list.length} / ${all.length} kayıt</span>`)+
      `<div class="status-strip" style="margin-bottom:16px">${Object.entries(statusCounts).map(([k,n])=>`${badge(k)} <span class="small muted">${n}</span>`).join(' ')}</div>`+
      `<div class="toolbar"><select id="filter-severity" class="select" aria-label="Önem filtresi"><option value="">Tüm önemler</option>${[...new Set(all.map(x=>x.severity))].map(v=>`<option ${state.filters.severity===v?'selected':''}>${esc(v)}</option>`).join('')}</select>
      <select id="filter-finding-status" class="select" aria-label="Durum filtresi"><option value="">Tüm durumlar</option>${['taslak','inceleniyor','doğrulandı','yanlış pozitif','giderildi'].map(v=>`<option ${state.filters.findingStatus===v?'selected':''}>${v}</option>`).join('')}</select>
      <select id="filter-subnet" class="select" aria-label="Ağ filtresi"><option value="">Tüm ağlar</option>${arr(ds('engagement').targets).map(v=>`<option ${state.filters.subnet===v?'selected':''}>${esc(v)}</option>`).join('')}</select></div>`+
      table(['ID / Kaynak','Gözlem','Varlık','Önem','İnceleme','İşlem'],rows);}

  function isGateway(ip){return arr(ds('DEVICE_INVENTORY').observed_gateways).includes(ip);}
  function assetName(d){const names=[...new Set([d.display_name,d.netbios?.name,...arr(d.hostnames)].map(x=>_clean(x)).filter(Boolean))];
    return names[0]||'';}
  function _clean(v){return String(v??'').trim();}
  function gatewayCard(){const inv=ds('DEVICE_INVENTORY');const gws=arr(inv.observed_gateways);
    const devByIp=new Map(arr(inv.devices).map(d=>[d.ip,d]));
    const rows=gws.map(ip=>{const d=devByIp.get(ip)||{ip,category:'Bilinmiyor'};
      const name=assetName(d);
      return `<div class="gw-row"><div><button class="btn-link mono" data-action="asset" data-ip="${esc(ip)}">${txt(ip)}</button>${name?`<div class="small muted">${txt(name)}</div>`:''}</div>
        <div class="status-strip">${badge(d.category||'Bilinmiyor')}<span class="meta-chip">${esc(d.vendor||'—')}</span>${arr(d.ports).length?`<span class="meta-chip">${arr(d.ports).length} port</span>`:''}</div></div>`;}).join('');
    const fwStatus=inv.firewall_identity_status||'doğrulanmadı';
    return `<div class="card gw-card"><div class="card-header"><div><span class="eyebrow">AĞ OMURGASI</span><h3>Ana yönlendirici / ağ geçidi</h3></div><span class="meta-chip">${gws.length} geçit</span></div>
      ${gws.length?rows:'<p class="muted">Varsayılan ağ geçidi kaydı bulunamadı. Rota anlık görüntüsü (default route) olmayan taramalarda gözlenmez.</p>'}
      <div class="divider"></div>${keyValues([['Güvenlik duvarı kimliği',badge(fwStatus)]])}
      <p class="small muted">Ağ geçidi, ana bilgisayarın varsayılan rotasından türetilir. DNS dağıtan, çok sayıda yönetim portu açan bir geçit yönlendirici-güvenlik duvarı (UTM) adayıdır; ürün kimliği analistçe doğrulanmalıdır.</p></div>`;}
  function renderAssets(){const inv=ds('DEVICE_INVENTORY');const devices=arr(inv.devices);const categories=[...new Set(devices.map(d=>d.category))].sort();
    const list=devices.filter(d=>(!state.filters.category||d.category===state.filters.category)&&(!state.filters.subnet||subnet(d.ip)===state.filters.subnet)&&
      match([d.ip,d.display_name,d.netbios?.name,...arr(d.hostnames),d.vendor,d.category,...arr(d.ports).map(p=>`${p.port} ${p.service}`)].join(' ')));
    const rows=list.map(d=>{const name=assetName(d),gw=isGateway(d.ip);
      return [`<button class="btn-link mono" data-action="asset" data-ip="${esc(d.ip)}">${txt(d.ip)}</button>${gw?' <span class="badge gw">Ağ geçidi</span>':''}<div class="small muted">${name?txt(name):'<span class="dim">ad çözülemedi</span>'}</div>`,
      esc(d.category),esc(d.vendor||'—'),`${esc(arr(d.ports).length)} <span class="muted">port</span>`,
      `${esc(d.confidence_pct||0)}% <div class="progress"><span style="width:${Math.min(100,Number(d.confidence_pct)||0)}%"></span></div>`,
      `<button class="btn btn-small" data-action="asset" data-ip="${esc(d.ip)}">Detay</button>`];});
    const named=devices.filter(d=>assetName(d)).length,unknown=inv.unknown_count??devices.filter(d=>d.category==='Bilinmiyor').length;
    const adJoined=inv.ad_joined_count??devices.filter(d=>d.ad_joined).length;
    return intro('Cihazlar & servisler','Sınıflandırma ve rol adayları otomatik işaretlerdir; üretici ve açık port tek başına zafiyet kanıtı değildir.',
      `<span class="meta-chip">${list.length} / ${devices.length} cihaz</span><span class="meta-chip">${named} adlandırıldı</span>${adJoined?`<span class="meta-chip">${adJoined} AD üyesi</span>`:''}${unknown?`<span class="meta-chip warn">${unknown} sınıflandırılamadı</span>`:''}`)+
      gatewayCard()+
      `<div class="grid cols-3" style="margin:16px 0"><div class="card"><h3>Hedef ağlar</h3>${barLines(Object.entries(devices.reduce((a,d)=>(a[subnet(d.ip)]=(a[subnet(d.ip)]||0)+1,a),{})))}</div>
      <div class="card"><h3>Kategori dağılımı</h3>${donut(Object.entries(inv.categories||{}),'cihaz')}</div>
      <div class="card"><h3>Servis yoğunluğu</h3>${barLines(topPorts(),7)}</div></div>`+
      `<div class="toolbar"><select id="filter-category" class="select" aria-label="Kategori filtresi"><option value="">Tüm kategoriler</option>${categories.map(v=>`<option ${state.filters.category===v?'selected':''}>${esc(v)}</option>`).join('')}</select>
      <select id="filter-asset-subnet" class="select" aria-label="Ağ filtresi"><option value="">Tüm ağlar</option>${arr(ds('engagement').targets).map(v=>`<option ${state.filters.subnet===v?'selected':''}>${esc(v)}</option>`).join('')}</select></div>`+
      table(['IP / Ad','Kategori','Üretici','Gözlenen','Sınıflandırma güveni','İşlem'],rows);}

  function renderAD(){const ad=ds('AD_ASSESSMENT');const policy=ad.password_policy||{},inventory=ad.inventory||{},root=ad.root_dse||{};
    if(!Object.keys(ad).length)return intro('Active Directory','AD kaydı mevcut değil.')+empty('AD verisi yok','Bu raporda AD_ASSESSMENT.json bulunamadı.');
    if(ad.status && ad.status!=='ok')
      return intro('Active Directory','Dizin değerlendirmesi tamamlanamadı.',`<span class="meta-chip warn">${esc(ad.status)}</span>`)+
        notice(ad.reason||'AD sorgusu başarısız oldu; DC, kimlik veya taşıma ayarlarını kontrol edin.')+`<div class="section-head"><h3>İlgili kaynak</h3></div>${linkFile('AD_ASSESSMENT.json')}`;
    const admins=ad.domain_admins||null,me=ad.test_account_membership||null;
    return intro('Active Directory','Dizin gözlemleri, hesap/grup adları ve parola politikası kayıtları. Yetki ve iş etkisi analist değerlendirmesi gerektirir.',`<span class="meta-chip">${esc(ad.status||'—')}</span>`)+
      `<div class="notice-list">${ad.security_warning?notice(ad.security_warning):''}${notice('Adlar salt okunur LDAP sorgusuyla listelenir; parola içermez. Ayrıcalık ve tüm parola kurallarının test edildiği anlamına gelmez.',true)}</div>`+
      `<div class="grid cols-4">${stat('Kullanıcı',inventory.users?.observed_count??arr(ad.user_names).length??'—','Gözlenen adlar','teal','lock','ad')}${stat('Grup',inventory.groups?.observed_count??arr(ad.group_names).length??'—','Gözlenen adlar','blue','layers','ad')}${stat('Bilgisayar',inventory.computers?.observed_count??arr(ad.computer_names).length??'—','Gözlenen adlar','amber','server','ad')}${stat('MachineAccountQuota',ad.machine_account_quota??'—','Kaynak politika değeri','red','alert','ad')}</div>`+
      `<div class="grid cols-2" style="margin-top:16px"><div class="card"><h3>Etki alanı</h3>${keyValues([['Alan',txt(ad.domain)],['DC',txt(ad.dc)],['Taşıma',txt(ad.transport)],['Kaynak',txt(ad.source)],['Root DN',txt(root.rootDomainNamingContext)],['DNS adı',txt(root.dnsHostName)],['Alan işlevi',esc(root.domainFunctionality)],['Orman işlevi',esc(root.forestFunctionality)]])}</div>
      <div class="card"><h3>Parola ve kilitlenme politikası</h3>${keyValues([['Minimum uzunluk',esc(policy.min_length)],['Karmaşıklık',badge(policy.complexity_enabled?'Açık':'Kapalı')],['Geçmiş',esc(policy.history_length)],['Kilitlenme eşiği',badge(policy.lockout_threshold??'—')],['Kilitlenme süresi',esc(policy.lockout_duration_min)+' dakika'],['Azami parola yaşı',esc(policy.max_pwd_age_days)+' gün']])}</div></div>`+
      ((me||admins)?`<div class="grid cols-2" style="margin-top:16px">${me?`<div class="card"><div class="card-header"><h3>Test hesabımızın üyelikleri</h3><small>Kullandığımız hesap</small></div>${keyValues([['Hesap',`<span class="mono">${txt(me.account)}</span>`],['Görünen ad',txt(me.display_name||'—')],['Üye olunan grup',esc(arr(me.groups).length)]])}<div class="divider"></div>${me.note?notice(me.note):chips(me.groups)}</div>`:''}
      ${admins?`<div class="card"><div class="card-header"><h3>Domain Admins üyeleri</h3><small>${esc(admins.count??arr(admins.members).length)} üye</small></div>${keyValues([['Grup',txt(admins.group||'Domain Admins')],['Toplam üye',badge(admins.count??arr(admins.members).length)]])}<div class="divider"></div>${chips(admins.members)}${admins.count>arr(admins.members).length?`<p class="small muted">İlk ${arr(admins.members).length} üye gösteriliyor.</p>`:''}</div>`:''}</div>`:'')+
      ((arr(ad.user_names).length||arr(ad.group_names).length||arr(ad.computer_names).length)?
        `<div class="section-head"><h3>Dizin adları</h3><span class="sub">Üstteki aramayı bu listelerde de kullanabilirsiniz</span></div>
        ${nameList('Kullanıcı adları',ad.user_names,'kullanıcı')}${nameList('Grup adları',ad.group_names,'grup')}${nameList('Bilgisayar adları',ad.computer_names,'bilgisayar')}`:'')+
      adDeep(ad)+
      `<div class="section-head"><h3>İlgili kaynak</h3></div>${linkFile('AD_ASSESSMENT.json')} · ${state.model.manifest.files.filter(f=>f.name==='ad_rootdse_summary.json').map(f=>linkFile(f.path)).join(' · ')||'<span class="muted">RootDSE özeti yok</span>'}`;}
  function adDeep(ad){const UAC={disabled:'Devre dışı',passwd_notreqd:'Parola gerekmiyor',reversible_encryption:'Tersinir şifreleme',password_never_expires:'Parolası hiç bitmiyor',unconstrained_delegation:'Kısıtlanmamış yetkilendirme',asrep_roastable:'AS-REP roast',constrained_delegation_proto:'Protokol geçişli yetkilendirme'};
    const risky=ad.risky_accounts||{},groups=ad.sensitive_groups||{},kerb=arr(ad.kerberoastable),asrep=arr(ad.asrep_roastable),osx=ad.computer_os_summary||{},stale=arr(ad.stale_computers);
    const rk=Object.entries(risky).filter(([k,v])=>arr(v).length),gk=Object.entries(groups).filter(([k,v])=>arr(v).length);
    if(!(rk.length||gk.length||kerb.length||asrep.length||Object.keys(osx).length||stale.length||ad.ldap_cleartext_bind===true))return '';
    let h=`<div class="section-head"><h3>Derin AD analizi</h3><span class="sub">Taslak bulgular · analist doğrulaması gerekir</span></div>`;
    if(ad.ldap_cleartext_bind===true)h+=notice('LDAP imzalama/kanal bağlama zorlanmıyor: 389 üzerinde şifresiz SIMPLE bağlanma kabul edildi (kimlik ağda açık; NTLM relay-to-LDAP riski).');
    if(kerb.length||asrep.length)h+=`<div class="grid cols-2" style="margin-bottom:12px">${kerb.length?`<div class="card"><div class="card-header"><h3>Kerberoast edilebilir</h3><small>${kerb.length} SPN hesabı</small></div>${chips(kerb.map(k=>String(k.account||'?')+(k.admin?' ★':'')))}</div>`:''}${asrep.length?`<div class="card"><div class="card-header"><h3>AS-REP roast edilebilir</h3><small>${asrep.length} hesap</small></div>${chips(asrep)}</div>`:''}</div>`;
    if(rk.length)h+=`<div class="card" style="margin-bottom:12px"><div class="card-header"><h3>Hesap risk bayrakları</h3><small>userAccountControl</small></div>${rk.map(([k,v])=>`<div class="uac-row"><span class="badge ${/notreqd|reversible|unconstrained|asrep/.test(k)?'high':'medium'}">${esc(UAC[k]||k)} · ${arr(v).length}</span><div class="chip-cloud">${arr(v).slice(0,60).map(x=>`<span class="name-chip mono">${txt(x)}</span>`).join('')}</div></div>`).join('')}</div>`;
    if(gk.length)h+=`${gk.map(([g,m])=>`<details class="folder-group name-group"><summary>${icon('lock')}${esc(g)}<small>${arr(m).length} üye</small></summary><div class="chip-pad">${chips(m)}</div></details>`).join('')}`;
    if(Object.keys(osx).length||stale.length)h+=`<div class="grid cols-2" style="margin:12px 0">${Object.keys(osx).length?`<div class="card"><div class="card-header"><h3>Bilgisayar OS dağılımı</h3><small>AD kaydı</small></div>${barLines(Object.entries(osx).sort((a,b)=>b[1]-a[1]),8)}</div>`:''}${stale.length?`<div class="card"><div class="card-header"><h3>Bayat bilgisayar hesapları</h3><small>90+ gün · ${stale.length}</small></div>${chips(stale)}</div>`:''}</div>`;
    return h;}

  function surfaceWeb(){const dsx=arr(ds('DEVICE_INVENTORY').devices).filter(d=>arr(d.ports).some(p=>[80,81,443,8080,8443,5000,5001].includes(Number(p.port))));
    return notice('Web veya yönetim portu görülmesi, kimlik doğrulama ya da güvenlik açığı doğrulaması değildir.',true)+
      table(['Varlık','Kategori','Web portları','Kaynak'],dsx.filter(d=>match(`${d.ip} ${d.category}`)).map(d=>[
        `<button class="btn-link mono" data-action="asset" data-ip="${esc(d.ip)}">${txt(d.ip)}</button>`,esc(d.category),
        arr(d.ports).filter(p=>[80,81,443,8080,8443,5000,5001].includes(Number(p.port))).map(p=>badge(`${p.port}/${p.protocol}`)).join(' '),
        linkFile(d.evidence?.split(';')[0]?.trim()||'','Nmap kanıtı')]));}
  function surfaceTLS(){const steps=arr(ds('steps')).filter(s=>/tls|ssl/i.test(`${s.step} ${s.tool}`));
    return notice('TLS kimlik uyuşmazlığı veya sertifika bilgisi, HTTP hizmetinin kimliğiyle otomatik eşitlenmez.',true)+
      table(['Adım','Durum','Araç','Çıktı'],steps.filter(s=>match(`${s.step} ${s.status} ${s.output}`)).map(s=>[txt(s.step),badge(s.status),esc(s.tool||'—'),s.output?linkFile(s.output):'—']));}
  function surfaceSNMP(){const files=state.model.manifest.files.filter(f=>/snmp/i.test(f.name));
    return notice('SNMPv1/public yanıtı bilgi erişimini gösterir; kapsam dışı cihazlara genellenmez.',true)+
      table(['Dosya','Tür','Boyut','Bütünlük'],files.filter(f=>match(f.path)).map(f=>[linkFile(f.path),esc(f.type),esc(f.size)+' B',badge(f.sha_status)]));}
  function surfaceSQL(){const rows=arr(ds('ANALIST_GOREV_RAPORU').observed_sql_instances).map(x=>[
    `<button class="btn-link mono" data-action="asset" data-ip="${esc(x.ip)}">${txt(x.ip)}</button>`,txt(x.name),esc(x.port),esc(x.version),links(x.evidence)]);
    return notice('Veritabanı servisi erişimi, hesap yetkisi veya veri erişimi doğrulaması değildir.',true)+table(['IP','Örnek','Port','Sürüm','Kanıt'],rows);}
  function surfaceWifi(){const wifi=ds('WIFI_SCAN');const networks=arr(wifi.networks);
    return `${wifi.available?notice('Kablosuz tarama yakındaki ağları gösterir; SSID sahipliği ve kapsam ayrıca doğrulanmalıdır.',true):notice('Kablosuz tarama kullanılamadı.')}`+
      `<div class="grid cols-3" style="margin-bottom:16px">${stat('Görülen ağ',wifi.network_count??'—','SSID','teal','network','surfaces')}${stat('Görülen AP',wifi.ap_count??'—','BSSID','blue','server','surfaces')}${stat('Açık ağ',arr(wifi.open_networks).length,'Kaynak listesi','amber','alert','surfaces')}</div>`+
      table(['SSID','Kimlik doğrulama','Şifreleme','BSSID / Kanal'],networks.filter(n=>match(`${n.ssid} ${n.auth}`)).map(n=>[
        txt(n.ssid),esc(n.auth),esc(n.encryption),arr(n.bssids).map(b=>`${txt(b.bssid)} <span class="muted">ch ${esc(b.channel)} · ${esc(b.signal)}</span>`).join('<br>')]));}
  function renderSurfaces(){const tabs=[['web','Web'],['tls','TLS'],['snmp','SNMP'],['sql','SQL'],['wifi','Wi-Fi']];
    const body={web:surfaceWeb,tls:surfaceTLS,snmp:surfaceSNMP,sql:surfaceSQL,wifi:surfaceWifi}[state.surface]();
    return intro('Teknik yüzeyler','Servis, sertifika, SNMP, SQL ve kablosuz kayıtları kanıt türüne göre ayrılmıştır.')+
      `<div class="toolbar">${tabs.map(([key,label])=>`<button class="btn ${state.surface===key?'btn-primary':'btn-outline'}" data-action="surface" data-target="${key}">${label}</button>`).join('')}</div>${body}`;}

  function renderCVE(){const data=ds('UBDEN_CVE'),items=arr(data.items),all=items.flatMap(x=>arr(x.cves));const counts={};for(const c of all)counts[c.severity]=(counts[c.severity]||0)+1;
    return intro('CVE adayları','CPE ve görülen sürüm eşleşmeleri analist doğrulaması bekler; CVE listesi mevcut zafiyet iddiası değildir.',`<span class="meta-chip warn">${all.length} aday / ${items.length} platform</span>`)+
      notice(data.note||'CVE adayları teyit gerektirir.')+
      `<div class="grid cols-3" style="margin-bottom:16px"><div class="card"><h3>Önem dağılımı</h3>${donut(Object.entries(counts),'CVE adayı')}</div><div class="card"><h3>Sorgu özeti</h3>${keyValues([['Sorgulanan',esc(data.queried??'—')],['Platform adayı',esc(data.candidate_platforms??'—')],['Hata',esc(data.errors??'—')],['Yüksek/kritik',esc(data.critical_high_count??'—')]])}</div><div class="card"><h3>Kaynak dosya</h3>${linkFile('UBDEN_CVE.json')}<p class="small muted">Güncel ürün sürümü ve uygulanabilirlik ayrıca doğrulanmalıdır.</p></div></div>`+
      items.map(item=>`<div class="card" style="margin-bottom:16px"><div class="card-header"><div><span class="eyebrow">PLATFORM ADAYI</span><h3>${esc(item.family)} ${esc(item.version)}</h3></div>${badge(`${arr(item.cves).length} CVE`)}</div>
      <div class="status-strip" style="margin-bottom:13px"><span class="meta-chip mono">${esc(item.cpe)}</span>${arr(item.assets).map(ip=>`<button class="btn btn-small" data-action="asset" data-ip="${esc(ip)}">${txt(ip)}</button>`).join('')}</div>`+
      table(['CVE','CVSS','Önem','Kaynak özeti'],arr(item.cves).filter(c=>match(`${c.id} ${c.summary} ${item.family}`)).map(c=>[
        `<span class="strong mono">${esc(c.id)}</span>`,esc(c.cvss),badge(c.severity),esc(c.summary)]))+'</div>').join('');}

  function graphSVG(graph){const nodes=arr(graph.nodes),edges=arr(graph.edges);if(!nodes.length)return empty('Grafik yok','Korelasyon grafiği bulunamadı.');
    const byId=new Map(nodes.map(n=>[n.id,n])),degree=new Map();for(const edge of edges){degree.set(edge.source,(degree.get(edge.source)||0)+1);degree.set(edge.target,(degree.get(edge.target)||0)+1);}
    const hub=[...degree].sort((a,b)=>b[1]-a[1])[0];
    if(!hub||hub[1]<edges.length/2)return table(['Düğüm','Tür','Kaynak bağı'],nodes.map(n=>[esc(n.label||n.id),esc(n.type),esc(edges.filter(x=>x.source===n.id||x.target===n.id).map(x=>x.label).join(', '))]));
    const groups=new Map();for(const edge of edges){if(edge.source!==hub[0]&&edge.target!==hub[0])continue;
      const target=byId.get(edge.source===hub[0]?edge.target:edge.source);if(!target)continue;
      const label=edge.label||'İlişki';if(!groups.has(label))groups.set(label,[]);groups.get(label).push(target);}
    const columns=[...groups],width=Math.max(1000,columns.length*300+40),height=Math.max(470,200+Math.max(...columns.map(x=>x[1].length))*56),center=width/2;
    const placed=[];const headers=columns.map(([label,list],i)=>{const x=35+i*300;list.forEach((n,j)=>placed.push({n,x,y:175+j*56,group:i,label}));
      return `<text x="${x+135}" y="148" text-anchor="middle" class="group-title">${esc(label.toLocaleUpperCase('tr'))} · ${list.length}</text>`;}).join('');
    const lines=placed.map(p=>`<path class="edge" d="M ${center} 83 Q ${center} ${Math.min(150,p.y)} ${p.x+135} ${p.y+21}"><title>${esc(p.label)}</title></path>`).join('');
    const cards=placed.map(p=>{const color=p.n.risk==='high'?'#ef7890':p.n.risk==='medium'?'#ffc36b':'#34d7c8';
      return `<g data-action="graph-node" data-id="${esc(p.n.id)}" tabindex="0" role="button" aria-label="${esc(p.n.label||p.n.id)}"><rect class="graph-card" x="${p.x}" y="${p.y}" width="270" height="42" rx="8" fill="#17384c" stroke="${color}"/><circle cx="${p.x+15}" cy="${p.y+21}" r="4" fill="${color}"/><text x="${p.x+28}" y="${p.y+26}">${txt(p.n.label||p.n.id)}</text><title>${esc(p.n.label||p.n.id)}</title></g>`;}).join('');
    return `<svg class="network-graph" viewBox="0 0 ${width} ${height}" role="img" aria-label="Kural tabanlı korelasyon grafiği">${lines}<rect x="${center-105}" y="27" width="210" height="56" rx="11" fill="#0d4b55" stroke="#27d6cc" stroke-width="2"/><text x="${center}" y="61" text-anchor="middle" class="hub-title">${txt(byId.get(hub[0])?.label||hub[0])}</text>${headers}${cards}</svg>`;}
  function renderCorrelation(){const c=ds('UBDEN_CORRELATION'),index=c.exposure_index||{};
    return intro('Çapraz katman korelasyonu','Graf düğüm ve kenarları kaynak JSON’dan alınır; fiziksel ağ topolojisi veya saldırı başarısı göstermez.',
      `<span class="meta-chip">${arr(c.graph?.nodes).length} düğüm · ${arr(c.graph?.edges).length} bağ</span>`)+
      notice(c.meaning||'Korelasyonlar hipotezdir.')+`<div class="grid cols-3" style="margin-bottom:16px">${stat('Maruziyet endeksi',index.score??'—',`Kaynak notu · ${index.grade||''}`,'teal','graph','correlation')}${stat('Ağ endeksi',index.network_score??'—',index.network_grade||'—','blue','network','correlation')}${stat('İnsan endeksi',ds('UBDEN_OSINT').available?index.human_score:'—',ds('UBDEN_OSINT').available?'Kaynak puanı':'OSINT kullanılamaz','amber','alert','correlation')}</div>`+
      `<div class="card"><div class="card-header"><h3>Kaynak korelasyon grafiği</h3><small>Düğüme tıklayarak ilişkiyi açın</small></div><div class="graph-wrap">${graphSVG(c.graph||{})}</div></div>`+
      `<div class="section-head"><h3>Maruziyet kesişimleri</h3></div>`+
      table(['Önem','Başlık','Ayrıntı'],arr(c.correlations).filter(x=>match(`${x.title} ${x.detail}`)).map(x=>[badge(x.severity),`<span class="strong">${esc(x.title)}</span>`,txt(x.detail)]))+
      `<div class="section-head"><h3>Olası zincirler</h3></div><div class="grid cols-3">${arr(c.attack_chains).map(chain=>`<div class="card"><h3>${esc(chain.name)}</h3><p class="small muted">Olasılık: ${esc(chain.likelihood)} · Etki: ${esc(chain.impact)}</p><div class="flow-steps">${arr(chain.steps).map(step=>`<div class="flow-step">${txt(typeof step==='string'?step:JSON.stringify(step))}</div>`).join('')}</div></div>`).join('')}</div>`+
      `<div class="section-head"><h3>Birleşik aksiyonlar</h3></div>${table(['Öncelik','Aksiyon','Gerekçe'],arr(c.combined_actions).map(a=>[badge(a.priority),esc(a.action),esc(a.rationale)]))}`;}

  function renderCoverage(){const cov=ds('ASSESSMENT_COVERAGE'),steps=arr(ds('steps'));
    const controls=arr(cov.controls).filter(x=>match(`${x.id} ${x.title} ${x.status}`));
    const list=steps.filter(x=>(!state.filters.stepStatus||x.status===state.filters.stepStatus)&&match(`${x.step} ${x.tool} ${x.status} ${x.output}`));
    return intro('Kapsam & adım günlüğü','Planlanan profil ile gerçekten kaydedilen yürütme durumu ayrıdır. Hata, kısmi veya kayıtsız adımlar tamamlanmış sayılmaz.',
      `<span class="meta-chip">${controls.length} kontrol · ${list.length} adım</span>`)+notice(cov.meaning||'Yürütme kaydı güvenlik açığı doğrulaması değildir.',true)+
      `<div class="grid cols-2" style="margin-bottom:16px"><div class="card"><h3>Kapsam kontrolü</h3>${donut(Object.entries(cov.counts||{}),'kontrol')}</div><div class="card"><h3>Adım durumları</h3>${barLines(Object.entries(state.model.overview.step_status||{}).sort((a,b)=>b[1]-a[1]))}</div></div>`+
      `<div class="section-head"><h3>Kontrol matrisi</h3></div>${table(['Grup','ID / Kontrol','Durum','Yürütme','Kanıt'],controls.map(x=>[
        esc(x.group),`<span class="strong">${esc(x.id)}</span><div class="small muted">${esc(x.title)}</div>`,badge(x.status),esc(`${x.executed||0}/${x.attempted||0}`),links(x.evidence)]))}`+
      `<div class="section-head"><h3>Adım günlüğü</h3><span class="sub">${list.length} / ${steps.length}</span></div>
      <div class="toolbar"><select id="filter-step-status" class="select" aria-label="Adım durumu filtresi"><option value="">Tüm durumlar</option>${Object.keys(state.model.overview.step_status||{}).map(v=>`<option ${state.filters.stepStatus===v?'selected':''}>${esc(v)}</option>`).join('')}</select></div>`+
      table(['Adım','Araç','Durum','Başlangıç','Süre','Çıktı'],list.map(x=>[txt(x.step),esc(x.tool||'—'),badge(x.status),esc(x.started_at),esc(x.seconds??'—')+' s',x.output?linkFile(x.output):'—']));}

  function renderTasks(){const tasks=arr(ds('ANALIST_GOREV_RAPORU').tasks).filter(t=>match(`${t.id} ${t.title} ${t.priority} ${t.status} ${t.targets?.join(' ')}`));
    const rows=tasks.map(t=>[`<button class="btn-link strong" data-action="task" data-id="${esc(t.id)}">${esc(t.id)} · ${esc(t.title)}</button>`,badge(t.priority),
      badge(tstatus(t)),txt(arr(t.targets).slice(0,4).join(', '))+ (arr(t.targets).length>4?` <span class="muted">+${arr(t.targets).length-4}</span>`:''),
      `<button class="btn btn-small" data-action="edit" data-kind="tasks" data-id="${esc(t.id)}">Güncelle</button>`]);
    return intro('Analist görevleri','Kaydedilmiş gözlemlerden üretilen iş listesi. Görev varlığı, testin yapıldığı veya zafiyetin doğrulandığı anlamına gelmez.',
      `<span class="meta-chip">${tasks.length} / ${arr(ds('ANALIST_GOREV_RAPORU').tasks).length} görev</span>`)+
      `<div class="grid cols-3" style="margin-bottom:16px">${stat('P1',tasks.filter(x=>x.priority==='P1').length,'Yüksek öncelikli','red','alert','tasks')}${stat('P2',tasks.filter(x=>x.priority==='P2').length,'İkinci sıra','amber','list','tasks')}${stat('Tamamlanan',tasks.filter(x=>tstatus(x)==='tamamlandı').length,'Analist kaydıyla','teal','check','tasks')}</div>`+
      table(['Görev','Öncelik','Durum','İlgili varlıklar','İşlem'],rows);}

  function fileGroups(files){const groups=new Map();for(const f of files){const parts=f.path.split('/');const key=parts.length===1?'Rapor kökü':parts.slice(0,-1).join('/');
    if(!groups.has(key))groups.set(key,[]);groups.get(key).push(f);}return [...groups].sort((a,b)=>a[0].localeCompare(b[0],'tr'));}
  function renderEvidence(){const manifest=state.model.manifest;const types=[...new Set(manifest.files.map(f=>f.type))].sort();const files=manifest.files.filter(f=>(!state.filters.fileType||f.type===state.filters.fileType)&&match(f.path));
    return intro('Kanıt & dosya gezgini','Rapor klasöründeki tüm kaynaklar ve SHA-256 eşleşmeleri. JSON dosyaları ağaç görünümünde; XML/TXT dosyaları düz metin olarak açılır.',
      `<span class="meta-chip">${files.length} / ${manifest.files.length} dosya</span>`)+
      `<div class="grid cols-4" style="margin-bottom:16px">${stat('Listelenen',manifest.listed_count,'SHA256SUMS kaydı','teal','file','evidence')}${stat('Eşleşen',manifest.hash_counts['eşleşiyor']||0,'Bütünlük doğrulandı','blue','check','evidence')}${stat('Uyuşmayan',manifest.hash_counts['uyuşmuyor']||0,'İnceleme gerekli','red','alert','evidence')}${stat('Eksik',manifest.hash_counts['eksik']||0,'Hashte var, dosya yok','amber','folder','evidence')}</div>`+
      `<div class="toolbar"><select id="filter-file-type" class="select" aria-label="Dosya türü filtresi"><option value="">Tüm dosya türleri</option>${types.map(v=>`<option ${state.filters.fileType===v?'selected':''}>${esc(v)}</option>`).join('')}</select><span class="small muted">Dosya yolu: rapor köküne göre</span></div>`+
      fileGroups(files).map(([name,list])=>`<details class="folder-group" ${name==='Rapor kökü'?'open':''}><summary>${icon('folder')}${txt(name)}<small>${list.length} dosya</small></summary>${list.map(f=>`<div class="file-row">${icon('file')}<span class="file-name">${txt(f.name)}</span>${badge(f.sha_status)}<span class="file-size">${Math.round(f.size/1024)} KB</span><button class="btn btn-small file-action" data-action="file" data-path="${esc(f.path)}">Aç</button></div>`).join('')}</details>`).join('') || empty('Dosya bulunamadı','Arama veya tür filtresini değiştirmeyi deneyin.');}

  function renderReports(){const files=state.model.manifest.files;const names=['REPORT.html','YONETICI_OZETI.pdf','TEKNIK_RAPOR.pdf','ANALIST_GOREV_RAPORU.pdf','ANALIST_GOREV_RAPORU.md','REMEDIATION_ROADMAP.md','SHA256SUMS.txt','WEBUI_PUBLISHED_REVIEW.json'];
    const rows=names.map(name=>{const f=files.find(x=>x.path===name);return [linkFile(name),f?`${Math.round(f.size/1024)} KB`:'—',f?badge(f.sha_status):badge('Henüz yok'),
      f?`<button class="btn btn-small" data-action="file" data-path="${esc(name)}">Aç</button>`:'—'];});
    const reviewCount=Object.keys(state.model.reviews.findings||{}).length+Object.keys(state.model.reviews.tasks||{}).length;
    return intro('Rapor çıktıları','İncelemeler önce ayrı çalışma kaydına yazılır. Yayınla işlemi HTML, üç PDF, analist görevleri, yol haritası ve hash listesini birlikte günceller.')+
      `<div class="grid cols-2"><div class="card"><span class="eyebrow">YAYINLAMA</span><h3>Raporu yenile</h3><p class="muted">${reviewCount} inceleme kaydı yayınlanmaya hazır. Doğrulanmış bulgular yalnız analist, not ve kanıtla rapora geçer.</p>
      <div class="notice info">Eski çıktılar <code>.webui/backups</code> altında korunur. PDF'ler yeni Ubden düzeninde oluşturulur.</div>
      <button class="btn btn-primary" data-action="publish">${icon('check')} Raporu yayınla</button></div>
      <div class="card"><span class="eyebrow">BÜTÜNLÜK</span><h3>Kaynak kontrolü</h3>${keyValues([['SHA listesi',esc(state.model.manifest.listed_count)],['Eşleşen',esc(state.model.manifest.hash_counts['eşleşiyor']||0)],['Uyuşmayan',esc(state.model.manifest.hash_counts['uyuşmuyor']||0)],['Listede olmayan',esc(state.model.manifest.hash_counts['listede yok']||0)],['İnceleme geçmişi',esc(arr(state.model.reviews.history).length)]])}</div></div>
      <div class="section-head"><h3>Çıktı dosyaları</h3></div>${table(['Dosya','Boyut','Hash','İşlem'],rows)}`;}

  const renderers={overview:renderOverview,findings:renderFindings,assets:renderAssets,ad:renderAD,surfaces:renderSurfaces,cve:renderCVE,
    correlation:renderCorrelation,coverage:renderCoverage,tasks:renderTasks,evidence:renderEvidence,reports:renderReports};
  function render(){if(!state.model)return;$('.nav-item.active')?.classList.remove('active');$(`.nav-item[data-page="${state.page}"]`)?.classList.add('active');
    $('#page-title').textContent=titles[state.page];$('#crumb').textContent=titles[state.page].toLocaleUpperCase('tr');
    $('#content').innerHTML=(state.page==='overview'&&state.search)?renderSearchResults():renderers[state.page]();$('#nav-findings').textContent=state.model.findings.length;
    $('#nav-tasks').textContent=arr(ds('ANALIST_GOREV_RAPORU').tasks).length;
    $('#side-client').textContent=ds('engagement').client||state.model.root_name;
    $('#side-id').textContent=ds('engagement').id||'—';
    $('#mode-toggle').textContent=state.executive?'Yönetici':'Teknik';$('#mode-toggle').setAttribute('aria-pressed',String(state.executive));
    $('#privacy-toggle').setAttribute('aria-pressed',String(state.private));}
  function navigate(page){if(!renderers[page])return;state.page=page;history.replaceState(null,'',`#${page}`);render();
    window.scrollTo({top:0,behavior:'smooth'});$('#sidebar').classList.remove('open');}
  function toast(message,error=false){const el=$('#toast');el.textContent=message;el.classList.toggle('error',error);el.classList.remove('hidden');
    clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.add('hidden'),4500);}
  async function api(path,options={}){const response=await fetch(path,{cache:'no-store',...options});let data;
    try{data=await response.json();}catch{throw new Error(`Sunucu yanıtı okunamadı (${response.status})`);}
    if(!response.ok)throw new Error(data.error||`İstek başarısız (${response.status})`);return data;}
  async function post(path,payload){return api(path,{method:'POST',headers:{'Content-Type':'application/json','X-Review-Token':token},body:JSON.stringify(payload)});}
  async function load(){try{state.model=await api('/api/report');$('#report-picker').classList.add('hidden');$('#app').classList.remove('hidden');
      const hash=location.hash.slice(1);if(renderers[hash])state.page=hash;render();}
    catch(error){$('#app').classList.add('hidden');$('#report-picker').classList.remove('hidden');$('#picker-error').textContent=error.message.includes('Pentest Raporu')?'':error.message;}}
  async function chooseFolder(path=''){try{const data=await post('/api/select-report',path?{path}:{});if(data.selected){toast(`${data.name} açıldı`);await load();}}
    catch(error){$('#picker-error').textContent=error.message;}}

  function openDrawer(title,content){$('#drawer-title').textContent=title;$('#drawer-body').innerHTML=content;
    $('#drawer').classList.remove('hidden');$('#drawer-backdrop').classList.remove('hidden');state.drawer=title;$('#drawer-close').focus();}
  function closeDrawer(){$('#drawer').classList.add('hidden');$('#drawer-backdrop').classList.add('hidden');state.drawer=null;}
  function detailFinding(id){const f=state.model.findings.find(x=>x.id===id);if(!f)return;const r=review('findings',id);
    const assetIP=String(f.asset).split(':')[0];
    const related=arr(ds('ANALIST_GOREV_RAPORU').tasks).filter(t=>arr(t.targets).some(target=>target===assetIP||target===subnet(assetIP))).slice(0,6);
    openDrawer(`${id} · ${f.title}`,`<div class="status-strip">${badge(f.severity)} ${badge(fstatus(f))}<span class="meta-chip">${txt(f.asset)}</span></div>
      <h3>Açıklama</h3><p>${txt(f.description)}</p><h3>İş etkisi</h3><p>${txt(f.impact)}</p><h3>Düzeltme önerisi</h3><p>${txt(f.remediation)}</p>
      <h3>Kaynak ve sınıflandırma</h3>${keyValues([['Kaynak',esc(f.source)],['CWE',esc(f.cwe)],['Varlık',`<button class="btn-link" data-action="asset" data-ip="${esc(String(f.asset).split(':')[0])}">${txt(f.asset)}</button>`]])}
      <h3>Birincil kanıt</h3>${links(f.evidence)}<h3>Analist incelemesi</h3><p>${r.note?txt(r.note):'<span class="muted">Henüz inceleme notu yok.</span>'}</p>
      ${r.reviewer?`<p class="small muted">${esc(r.reviewer)} · ${esc(r.updated_at)}</p>`:''}${r.retest_evidence?.length?`<h3>Yeniden test</h3>${links(r.retest_evidence)}`:''}
      ${related.length?`<h3>İlgili görevler</h3>${related.map(t=>`<button class="btn btn-small" data-action="task" data-id="${esc(t.id)}">${esc(t.id)}</button>`).join(' ')}`:''}
      <div class="divider"></div><button class="btn btn-primary" data-action="edit" data-kind="findings" data-id="${esc(id)}">${icon('check')} İncelemeyi düzenle</button>`);}
  function detailAsset(ip){const d=arr(ds('DEVICE_INVENTORY').devices).find(x=>x.ip===ip);if(!d)return;
    const related=state.model.findings.filter(f=>String(f.asset).split(':')[0]===ip);
    const gw=isGateway(ip);const allNames=[...new Set([d.display_name,d.netbios?.name,...arr(d.hostnames)].map(x=>_clean(x)).filter(Boolean))];
    openDrawer(`${mask(ip)} · ${d.category}`,`<div class="status-strip">${badge(d.category)}<span class="meta-chip">Sınıflandırma güveni ${esc(d.confidence_pct)}%</span>${gw?'<span class="badge gw">Ağ geçidi</span>':''}${d.is_scanner?'<span class="meta-chip">Test makinesi</span>':''}</div>
      <h3>Kimlik</h3>${keyValues([['IP',txt(d.ip)],['Ana ad',txt(d.display_name||'—')],['NetBIOS adı',txt(d.netbios?.name||'—')],['MAC',txt(d.mac||'—')],['MAC kaynağı',esc(d.mac_source)],['Üretici',esc(d.vendor)],['Üretici kaynağı',esc(d.vendor_source)],['Alt ağ',txt(subnet(d.ip))],['Ağ geçidi',gw?badge('Evet · varsayılan rota'):'<span class="muted">Hayır</span>']])}
      ${allNames.length?`<h3>Çözülen adlar</h3>${chips(allNames)}`:''}
      <h3>Gözlenen servisler</h3>${table(['Port','Servis','Ürün / Sürüm'],arr(d.ports).map(p=>[esc(`${p.port}/${p.protocol}`),esc(p.service),txt(`${p.product||''} ${p.version||''}`)]))}
      ${arr(d.notices).length?`<h3>Uyarılar</h3><ul>${arr(d.notices).map(v=>`<li>${txt(v)}</li>`).join('')}</ul>`:''}
      <h3>Rol adayları</h3>${arr(d.role_candidates).map(x=>`<p>${badge(x.confidence)} <b>${esc(x.role)}</b><br><span class="muted">${txt(x.reason)}</span></p>`).join('')||'<p class="muted">Rol adayı yok.</p>'}
      <h3>Sinyaller</h3><ul>${arr(d.signals).map(v=>`<li>${txt(v)}</li>`).join('')}</ul><h3>İnceleme notları</h3><ul>${arr(d.review_notes).map(v=>`<li>${txt(v)}</li>`).join('')||'<li>—</li>'}</ul>
      <h3>Kanıt</h3>${links(String(d.evidence||'').split(';').map(x=>x.trim()).filter(Boolean))}
      <h3>İlişkili gözlemler (${related.length})</h3>${related.map(f=>`<p><button class="btn-link" data-action="finding" data-id="${esc(f.id)}">${esc(f.id)} · ${esc(f.title)}</button> ${badge(fstatus(f))}</p>`).join('')||'<p class="muted">Kayıt yok.</p>'}`);}
  function detailTask(id){const t=arr(ds('ANALIST_GOREV_RAPORU').tasks).find(x=>x.id===id);if(!t)return;const r=review('tasks',id);
    openDrawer(`${id} · ${t.title}`,`<div class="status-strip">${badge(t.priority)} ${badge(tstatus(t))}</div>
      <h3>Gerekçe</h3><p>${txt(t.trigger)}</p><h3>Varlıklar</h3><p>${arr(t.targets).map(x=>`<span class="meta-chip">${txt(x)}</span>`).join(' ')}</p>
      <h3>Adımlar</h3><ol>${arr(t.steps).map(v=>`<li>${txt(v)}</li>`).join('')}</ol><h3>Gerekli kanıt</h3><ul>${arr(t.evidence_required).map(v=>`<li>${txt(v)}</li>`).join('')}</ul>
      <h3>Müşteriden gereken</h3><p>${txt(t.customer_input)}</p><h3>Kaynak kanıt</h3>${links(t.source_evidence)}
      ${arr(t.commands).length?`<h3>Örnek komutlar</h3><pre>${arr(t.commands).map(esc).join('\n')}</pre>`:''}
      <h3>İnceleme sonucu</h3><p>${r.note?txt(r.note):'<span class="muted">Henüz not yok.</span>'}</p><div class="divider"></div>
      <button class="btn btn-primary" data-action="edit" data-kind="tasks" data-id="${esc(id)}">${icon('check')} Görevi güncelle</button>`);}
  function detailNode(id){const g=ds('UBDEN_CORRELATION').graph||{},n=arr(g.nodes).find(x=>x.id===id);if(!n)return;
    const edges=arr(g.edges).filter(x=>x.source===id||x.target===id);
    openDrawer(n.label||id,`<div class="status-strip">${badge(n.type||'düğüm')} ${badge(n.risk||'—')}</div><h3>Kaynak bağları</h3>${table(['İlişkili düğüm','Bağ'],edges.map(x=>[esc(x.source===id?x.target:x.source),esc(x.label||'—')]))}<p class="muted">Graf, UBDEN_CORRELATION.json içindeki kural kaynaklı bağlantıları gösterir.</p>`);}
  function jsonTree(value,depth=0){if(value===null||typeof value!=='object')return `<span class="json-value">${esc(JSON.stringify(value))}</span>`;
    const keys=Array.isArray(value)?value.map((_,i)=>i):Object.keys(value);if(depth>9)return `<span class="muted">${esc(JSON.stringify(value).slice(0,500))}…</span>`;
    return `<details class="json-node" ${depth<1?'open':''}><summary>${Array.isArray(value)?`Array [${keys.length}]`:`Object {${keys.length}}`}</summary><div class="json-child">${keys.map(key=>`<div><span class="json-key">${esc(key)}</span>: ${jsonTree(value[key],depth+1)}</div>`).join('')}</div></details>`;}
  async function detailFile(path){try{const response=await fetch(`/api/file?path=${encodeURIComponent(path)}`,{cache:'no-store'});if(!response.ok){const err=await response.json();throw new Error(err.error||'Dosya açılamadı');}
      if(path.toLowerCase().endsWith('.pdf')){window.open(`/api/file?path=${encodeURIComponent(path)}`,'_blank','noopener');return;}
      const content=await response.text();let body;if(path.toLowerCase().endsWith('.json')){
        try{body=jsonTree(JSON.parse(content));}catch{body=`<pre>${esc(content)}</pre>`;}}
      else body=`<pre>${esc(content)}</pre>`;
      const f=state.model.manifest.files.find(x=>x.path===path);openDrawer(path,`<div class="status-strip">${f?badge(f.sha_status):''}<span class="meta-chip">${f?Math.round(f.size/1024)+' KB':'—'}</span></div><div class="divider"></div>${body}`);
    }catch(error){toast(error.message,true);}}

  function openReview(kind,id){const item=kind==='findings'?state.model.findings.find(x=>x.id===id):arr(ds('ANALIST_GOREV_RAPORU').tasks).find(x=>x.id===id);if(!item)return;
    const r=review(kind,id),paths=kind==='findings'?arr(item.evidence):arr(item.source_evidence);
    $('#review-form').dataset.kind=kind;$('#review-form').dataset.id=id;
    $('#modal-title').textContent=`${id} · ${item.title}`;
    const statuses=kind==='findings'?['taslak','inceleniyor','doğrulandı','yanlış pozitif','giderildi']:['bekliyor','devam ediyor','tamamlandı','engellendi'];
    $('#modal-fields').innerHTML=`<div class="form-field"><label for="review-status">Durum</label><select id="review-status" class="select">${statuses.map(s=>`<option ${s===(r.status||item.status)?'selected':''}>${esc(s)}</option>`).join('')}</select></div>
      <div class="form-field"><label for="reviewer">Analist adı</label><input id="reviewer" type="text" maxlength="120" value="${esc(r.reviewer||'')}" placeholder="Ad Soyad"></div>
      <div class="form-field"><label for="review-note">İnceleme notu</label><textarea id="review-note" maxlength="5000" placeholder="Yapılan doğrulama ve sonuç">${esc(r.note||'')}</textarea></div>
      <div class="form-field"><label>Kaynak kanıtı seçin</label><div class="checkbox-list">${paths.length?paths.map((p,i)=>`<label><input type="checkbox" name="evidence" value="${esc(p)}" ${arr(r.evidence).includes(p)?'checked':''}><span>${txt(p)}</span></label>`).join(''):'<span class="muted small">Kaynakta kanıt yolu yok; aşağıya rapor içi yol yazın.</span>'}</div>
      <span class="form-help">Doğrulanmış gözlem için en az bir kanıtı işaretleyin.</span></div>
      <div class="form-field"><label for="extra-evidence">Ek kanıt yolları</label><textarea id="extra-evidence" style="min-height:62px" placeholder="Rapor köküne göre her satıra bir dosya yolu">${esc(arr(r.evidence).filter(p=>!paths.includes(p)).join('\n'))}</textarea></div>
      ${kind==='findings'?`<div class="form-field"><label for="retest-evidence">Yeniden test kanıt yolları</label><textarea id="retest-evidence" style="min-height:62px" placeholder="Giderildi durumu için her satıra bir rapor içi dosya yolu">${esc(arr(r.retest_evidence).join('\n'))}</textarea></div>`:''}
      <p class="form-help">“Doğrulandı” için analist, not ve kanıt; “giderildi” için ayrıca yeniden test kanıtı gerekir. Bu kimlik doğrulama değildir.</p>`;
    $('#review-modal').classList.remove('hidden');$('#modal-backdrop').classList.remove('hidden');$('#review-status').focus();}
  function closeModal(){$('#review-modal').classList.add('hidden');$('#modal-backdrop').classList.add('hidden');}
  async function saveReview(event){event.preventDefault();const form=$('#review-form');const lines=(selector)=>$(selector)?.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)||[];
    const evidence=[...$$('input[name="evidence"]:checked').map(x=>x.value),...lines('#extra-evidence')];
    const payload={kind:form.dataset.kind,id:form.dataset.id,status:$('#review-status').value,reviewer:$('#reviewer').value,
      note:$('#review-note').value,evidence,retest_evidence:lines('#retest-evidence')};
    try{await post('/api/review',payload);closeModal();await load();toast('İnceleme kaydedildi');}
    catch(error){toast(error.message,true);}}
  async function doPublish(){const button=$('[data-action="publish"]');if(button){button.disabled=true;button.textContent='PDF ve raporlar hazırlanıyor…';}
    try{const result=await post('/api/publish',{signature:state.model.signature});await load();toast(`Rapor yayınlandı. Yedek: ${result.backup}`);}
    catch(error){toast(error.message,true);if(button){button.disabled=false;button.textContent='Raporu yayınla';}}}

  function eventClick(event){const target=event.target.closest('[data-action]');if(!target)return;
    const action=target.dataset.action;if(action==='page')navigate(target.dataset.target);
    else if(action==='surface'){state.surface=target.dataset.target;render();}
    else if(action==='finding')detailFinding(target.dataset.id);
    else if(action==='asset')detailAsset(target.dataset.ip);
    else if(action==='task')detailTask(target.dataset.id);
    else if(action==='file')detailFile(target.dataset.path);
    else if(action==='edit')openReview(target.dataset.kind,target.dataset.id);
    else if(action==='graph-node')detailNode(target.dataset.id);
    else if(action==='publish')doPublish();}
  function eventChange(event){const map={'filter-severity':'severity','filter-finding-status':'findingStatus','filter-subnet':'subnet',
    'filter-category':'category','filter-asset-subnet':'subnet','filter-step-status':'stepStatus','filter-file-type':'fileType'};
    const key=map[event.target.id];if(key){state.filters[key]=event.target.value;render();}}

  function bind(){for(const button of $$('.nav-item'))button.addEventListener('click',()=>navigate(button.dataset.page));
    window.addEventListener('hashchange',()=>{const page=location.hash.slice(1);if(renderers[page]&&page!==state.page){state.page=page;render();}});
    $('#content').addEventListener('click',eventClick);$('#content').addEventListener('change',eventChange);
    $('#drawer-body').addEventListener('click',eventClick);$('#global-search').addEventListener('input',event=>{
      state.search=event.target.value.toLocaleLowerCase('tr').trim();render();});
    $('#mode-toggle').addEventListener('click',()=>{state.executive=!state.executive;render();toast(state.executive?'Yönetici görünümü seçildi':'Teknik görünüm seçildi');});
    $('#privacy-toggle').addEventListener('click',()=>{state.private=!state.private;render();if(state.drawer)closeDrawer();});
    $('#refresh-btn').addEventListener('click',async()=>{await load();toast('Rapor verileri yenilendi');});
    $('#menu-toggle').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
    $('#drawer-close').addEventListener('click',closeDrawer);$('#drawer-backdrop').addEventListener('click',closeDrawer);
    $('#modal-close').addEventListener('click',closeModal);$('#modal-cancel').addEventListener('click',closeModal);
    $('#modal-backdrop').addEventListener('click',closeModal);$('#review-form').addEventListener('submit',saveReview);
    $('#choose-folder').addEventListener('click',()=>chooseFolder());$('#path-form').addEventListener('submit',event=>{event.preventDefault();chooseFolder($('#report-path').value.trim());});
    document.addEventListener('keydown',event=>{if(event.key==='Escape'){closeModal();closeDrawer();$('#sidebar').classList.remove('open');}
      if((event.key==='Enter'||event.key===' ')&&event.target.matches('[data-action="graph-node"]')){event.preventDefault();detailNode(event.target.dataset.id);}});}
  async function start(){bind();if(location.protocol==='file:'){$('#offline').classList.remove('hidden');return;}
    try{const session=await api('/api/session');if(!session.has_report){$('#report-picker').classList.remove('hidden');return;}await load();}
    catch(error){$('#report-picker').classList.remove('hidden');$('#picker-error').textContent=error.message;}}
  start();
})();
