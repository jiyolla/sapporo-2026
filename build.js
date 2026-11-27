// 평문 원본을 AES-256-GCM 으로 암호화해 index.html(로더) 를 만든다.
// 평문·비밀번호는 저장소 밖에 둔다.  사용: node build.js
// 비밀번호는 PRIV/password(600) → PW 환경변수 → 숨김 입력 순으로 찾는다.
const fs = require('fs'), crypto = require('crypto'), path = require('path');

const PRIV = process.env.PRIV || `${process.env.HOME}/personal/.sapporo-private`;
const SRC = process.env.SRC || `${PRIV}/index.html`;
const PWFILE = `${PRIV}/password`;
const ITER = 600000;                       // OWASP 권고치

function askHidden(q) {              // stdin raw mode — 터미널에 문자를 남기지 않는다
  return new Promise((res, rej) => {
    const fd = process.stdin;
    if (!fd.isTTY) return rej(new Error('TTY가 아닙니다. 터미널에서 실행하세요.'));
    const prev = fd.isRaw;
    const restore = () => { try { fd.setRawMode(prev); } catch (_) {} fd.pause(); };
    process.stdout.write(q);
    fd.setRawMode(true); fd.resume(); fd.setEncoding('utf8');
    let buf = '';
    const onData = ch => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') { fd.off('data', onData); restore(); process.stdout.write('\n'); return res(buf); }
        if (c === '\u0003') { fd.off('data', onData); restore(); process.stdout.write('\n'); return rej(new Error('취소됨')); }
        if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); continue; }
        if (c >= ' ') buf += c;
      }
    };
    fd.on('data', onData);
    process.once('SIGINT', restore);
  });
}

async function password() {
  if (fs.existsSync(PWFILE)) {
    const st = fs.statSync(PWFILE);
    if (st.mode & 0o077) { console.error(`${PWFILE} 권한이 너무 넓습니다 (600 이어야 함)`); process.exit(1); }
    return fs.readFileSync(PWFILE, 'utf8').trim();
  }
  if (process.env.PW) { console.warn('경고: PW 환경변수 사용 — 셸 히스토리·프로세스 환경에 남을 수 있습니다'); return process.env.PW; }
  return askHidden('비밀번호: ');
}

(async () => {
  const pw = (await password()).trim().normalize('NFC');   // 브라우저도 trim 하므로 모든 입력 경로를 맞춘다
  if (pw.length < 12) { console.error('비밀번호가 너무 짧습니다'); process.exit(1); }

  const plain = fs.readFileSync(SRC);
  // 빌드마다 평문 스냅샷을 남긴다 (편집 사고 복구용, 최근 20개 유지)
  try {
    const bdir = path.join(path.dirname(SRC), 'backups');
    fs.mkdirSync(bdir, { recursive: true, mode: 0o700 });
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 15);
    fs.writeFileSync(path.join(bdir, `index-${stamp}.html`), plain, { mode: 0o600 });
    const old = fs.readdirSync(bdir).filter(f => f.startsWith('index-')).sort().slice(0, -20);
    old.forEach(f => fs.unlinkSync(path.join(bdir, f)));
  } catch (e) { console.warn('  백업 실패(계속 진행):', e.message); }
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);   // WebCrypto: ciphertext || tag

  // 왕복 검증 — 복호화해서 원문과 바이트 단위로 같은지 확인
  const dc = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  dc.setAuthTag(ct.subarray(ct.length - 16));
  const back = Buffer.concat([dc.update(ct.subarray(0, ct.length - 16)), dc.final()]);
  if (!back.equals(plain)) { console.error('왕복 검증 실패'); process.exit(1); }

  // 평문에 실제로 존재하는 태그만 허용한다 (allowlist 는 빌드 때 원본에서 뽑는다)
  // 위험 태그는 평문에 들어 있더라도 절대 허용하지 않는다 (denylist 가 allowlist 를 이긴다)
  const DENY = new Set(['script','iframe','object','embed','base','form','input','button',
    'textarea','select','frame','frameset','applet','portal','noscript','link','meta','style']);
  const HEAD_OK = new Set(['link','meta','style']);   // head 전용 요소는 별도로 검사한다
  const ALLOW = [...new Set([...plain.toString('utf8').matchAll(/<([a-zA-Z][a-zA-Z0-9-]*)/g)]
    .map(m => m[1].toLowerCase()))].filter(t => !DENY.has(t) || HEAD_OK.has(t)).sort();

  const P = JSON.stringify({ s: salt.toString('base64'), i: iv.toString('base64'),
                             c: ct.toString('base64'), n: ITER });

  // 복호화 뒤의 동작(지금 모드 · D-day · 체크리스트 · 핀)은 전부 여기에 있다.
  // 본문은 sanitizer 를 거친 순수 마크업이고 스크립트를 담지 않는다.
  const SCRIPT = `
const P=${P},ALLOW=${JSON.stringify(ALLOW)},
  DENY=['script','iframe','object','embed','base','form','input','button','textarea','select','frame','frameset','applet','portal'];
const LK='ok'+location.pathname, CK='ck'+location.pathname;   // 경로별 분리 — 같은 origin의 다른 여행 페이지와 안 섞이게
const d=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
async function unlock(pw){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw.normalize('NFC')),'PBKDF2',false,['deriveKey']);
  const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:d(P.s),iterations:P.n,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.i),tagLength:128},k,d(P.c));
  return new TextDecoder().decode(pt);
}
let done=false;   // 자동 해제와 수동 입력이 겹쳐도 한 번만 그린다
function render(html){
  if(done) return; done=true;
  const doc=new DOMParser().parseFromString(html,'text/html');
  doc.querySelectorAll('template').forEach(n=>n.remove());
  for(const n of [...doc.querySelectorAll('*')]){
    const t=n.tagName.toLowerCase();
    if(DENY.includes(t)||!ALLOW.includes(t)){n.remove();continue;}
    if(t==='meta'&&n.hasAttribute('http-equiv')){n.remove();continue;}
    if(t==='link'&&!/^(icon|apple-touch-icon|shortcut icon)$/i.test(n.getAttribute('rel')||'')){n.remove();continue;}
    for(const a of [...n.attributes]){
      const an=a.name.toLowerCase();
      if(/^on/.test(an)||an==='srcdoc'||an==='formaction'||an==='ping'){n.removeAttribute(a.name);continue;}
      if(/^(href|src|action|xlink:href|poster|data)$/.test(an)){
        const v=[...a.value].filter(ch=>ch.charCodeAt(0)>32).join('');
        const sch=(v.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)||[])[1];
        if(sch&&!/^https$/i.test(sch)) n.removeAttribute(a.name);
      }
    }
  }
  // 교체 전에 새 문서 쪽 아이콘을 먼저 정리해 둔다 (교체 순간 아이콘 공백을 없앤다)
  var stamp='?v='+Date.now();
  doc.querySelectorAll('link[rel="icon"],link[rel="apple-touch-icon"]').forEach(function(n){n.remove();});
  var i1=doc.createElement('link'); i1.rel='icon'; i1.type='image/svg+xml'; i1.href='favicon.svg'+stamp;
  var a1=doc.createElement('link'); a1.rel='apple-touch-icon'; a1.href='apple-touch-icon.png'+stamp;
  doc.head.append(i1,a1);
  document.replaceChild(doc.documentElement,document.documentElement);
  // 교체 후 한 번 더 갱신 — 일부 브라우저는 교체 시점 head 를 재평가하지 않는다
  document.querySelectorAll('link[rel="icon"],link[rel="apple-touch-icon"]').forEach(function(n){n.remove();});
  var i2=document.createElement('link'); i2.rel='icon'; i2.type='image/svg+xml'; i2.href='favicon.svg'+stamp;
  var a2=document.createElement('link'); a2.rel='apple-touch-icon'; a2.href='apple-touch-icon.png'+stamp;
  document.head.append(i2,a2);
  enhance();
}
// ── 복호화 뒤 동작 ──
function enhance(){
  const B=document.body, S=B.dataset.start, E=B.dataset.end, $=(q,r)=>(r||document).querySelector(q),
    $$=(q,r)=>[...(r||document).querySelectorAll(q)];
  // 체크리스트 — 이 기기에만 저장
  let st={}; try{st=JSON.parse(localStorage.getItem(CK)||'{}')||{};}catch(_){st={};}
  $$('.ck[data-k]').forEach(li=>{
    const k=li.dataset.k, set=()=>{li.classList.toggle('done',!!st[k]); li.setAttribute('aria-checked',String(!!st[k]));};
    const tg=()=>{ if(st[k]) delete st[k]; else st[k]=1; try{localStorage.setItem(CK,JSON.stringify(st));}catch(_){} set(); };
    set(); li.addEventListener('click',tg);
    li.addEventListener('keydown',ev=>{ if(ev.key===' '||ev.key==='Enter'){ev.preventDefault();tg();} });
  });
  // 지도 핀 — 터치 기기는 hover 가 없으니 탭으로 이름표를 연다
  document.addEventListener('click',ev=>{
    const pin=ev.target.closest&&ev.target.closest('.pin');
    $$('.pin.on').forEach(p=>{ if(p!==pin) p.classList.remove('on'); });
    if(pin) pin.classList.toggle('on');
  });
  // 일본어 보여 주기 — 문장(.jaj)을 누르면 흰 화면 가득 크게 띄운다. 아무 데나 누르거나 Esc 로 닫는다
  const jaOpen=el=>{
    const li=el.closest('li'), k=li&&li.querySelector('.jak');
    const ov=document.createElement('div'); ov.className='jafs'; ov.setAttribute('role','dialog'); ov.setAttribute('aria-modal','true'); ov.tabIndex=-1;
    const pj=document.createElement('p'); pj.className='jafs-j'; pj.lang='ja'; pj.textContent=el.textContent;
    const pk=document.createElement('p'); pk.className='jafs-k'; pk.textContent=k?k.textContent:'';
    const ph=document.createElement('p'); ph.className='jafs-h'; ph.textContent='화면을 누르면 닫힙니다';
    ov.append(pj,pk,ph);
    const close=()=>{ ov.remove(); document.removeEventListener('keydown',esc,true); if(el.focus) el.focus({preventScroll:true}); };
    const esc=ev=>{ if(ev.key==='Escape'){ ev.preventDefault(); close(); } };
    ov.addEventListener('click',close); document.addEventListener('keydown',esc,true);
    B.append(ov); ov.focus({preventScroll:true});
  };
  document.addEventListener('click',ev=>{ const el=ev.target.closest&&ev.target.closest('.jaj'); if(el) jaOpen(el); });
  document.addEventListener('keydown',ev=>{
    if((ev.key==='Enter'||ev.key===' ')&&ev.target.classList&&ev.target.classList.contains('jaj')){ ev.preventDefault(); jaOpen(ev.target); }
  });
  // 리뷰 스레드 — 스레드 하나 = GitHub 이슈 하나. 메시지는 리뷰 키(이 평문 페이지 안에만 있음)로 암호화돼
  // reviews 브랜치 reviews/t<이슈 번호>/ 에 쌓인다. 누가 썼는지는 파일 이름으로만 정한다:
  // -r<번호> = 리뷰(워크플로가 기록) · -a = 답변(저장소 주인만 기록). 이슈에는 암호문만 남는다.
  const RV=$('#review[data-tk][data-repo][data-rk]');
  if(RV){
    const API='https://api.github.com/repos/'+RV.dataset.repo, TK=RV.dataset.tk;
    const hd=acc=>({'Authorization':'Bearer '+TK,'Accept':acc,'X-GitHub-Api-Version':'2022-11-28'});
    const b64=u=>{let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s);};
    const keyP=crypto.subtle.importKey('raw',d(RV.dataset.rk),'AES-GCM',false,['encrypt','decrypt']);
    const pipe=(bytes,ts)=>new Response(new Blob([bytes]).stream().pipeThrough(ts)).arrayBuffer();
    const kst=ms=>{const t=new Date(ms+9*36e5).toISOString();return t.slice(5,10).replace('-','/')+' '+t.slice(11,16);};
    const fnTime=n=>Date.UTC(+n.slice(0,4),+n.slice(4,6)-1,+n.slice(6,8),+n.slice(9,11),+n.slice(11,13),+n.slice(13,15));
    const mk=(t,c,x)=>{const n=document.createElement(t); if(c) n.className=c; if(x!=null) n.textContent=x; return n;};
    // 화면: 위 막대 · 스레드 목록 · 대화 · 입력
    const back=mk('button','rvback','← 목록'), ttl=mk('b','rvttl','스레드'), rf=mk('button','rvr','새로고침');
    const del=mk('button','rvdel','삭제'); back.type=rf.type=del.type='button'; const top=mk('div','rvtop'); top.append(back,ttl,del,rf);
    // 스레드 삭제 — 따로 승인은 없고 확인 한 번만 받는다. 이슈를 닫으면 워크플로가 그 스레드 파일을 지운다.
    const cf=mk('div','rvcf'), cfY=mk('button','rvcfy','삭제'), cfN=mk('button','rvcfn','취소'); cfY.type=cfN.type='button';
    cf.append(mk('span',null,'이 스레드를 통째로 삭제할까요? 되돌릴 수 없습니다.'),cfY,cfN); cf.hidden=true;
    const listV=mk('div','rvlist'), log=mk('div','rvl');
    const NK='rvname'+location.pathname, nm=mk('input','rvti rvnm'); nm.placeholder='작성자 이름 (스스로 적습니다 · 이 기기에 기억)'; nm.maxLength=30;
    try{ nm.value=localStorage.getItem(NK)||''; }catch(_){}
    // 내 글 구분 — 이 브라우저의 임의 기기 ID(1순위) 또는 지금 입력칸의 이름과 같은 이름(보완). 표시용일 뿐 인증이 아니다.
    const DK='rvdev'+location.pathname; let DEV='';
    try{ DEV=localStorage.getItem(DK)||''; if(!DEV){ DEV=b64(crypto.getRandomValues(new Uint8Array(12))); localStorage.setItem(DK,DEV); } }
    catch(_){ DEV=b64(crypto.getRandomValues(new Uint8Array(12))); }
    const mine=(name,dev)=>!!((dev&&dev===DEV)||(name&&nm.value.trim()&&name.trim()===nm.value.trim()));
    const tIn=mk('input','rvti'); tIn.placeholder='스레드 제목 (예: DAY 2 저녁 동선)'; tIn.maxLength=80;
    const ta=mk('textarea','rvt'); ta.rows=7; ta.placeholder='내용 — 일정 내용을 그대로 써도 됩니다. 암호화해서 올립니다.';
    const bt=mk('button','rvb'); bt.type='button';
    const msg=mk('p','rvm'); msg.setAttribute('role','status');
    const comp=mk('div','rv'); comp.append(nm,tIn,ta,bt,msg);
    const newB=mk('button','rvnew','+ 새 스레드'); newB.type='button';
    RV.append(top,cf,listV,log,comp);
    let tree=[], cur=null, pend=[]; const gone=new Set();   // gone: 삭제 요청한 스레드 (파일이 지워질 때까지 숨김)   // cur: null=목록 · 'new'=새 스레드 · 숫자=스레드 / pend: [{t,text,title}]
    const blobs=new Map();
    async function dec(body){
      const L=body.replace(/\\r/g,'').trim().split('\\n');
      if(L.length!==3||L[0]!=='sapporo-review v2') throw new Error('fmt');
      const z=await crypto.subtle.decrypt({name:'AES-GCM',iv:d(L[1]),tagLength:128},await keyP,d(L[2]));
      return JSON.parse(new TextDecoder().decode(await pipe(z,new DecompressionStream('deflate-raw'))));
    }
    async function blob(sha){
      if(blobs.has(sha)) return blobs.get(sha);
      let m=null;
      try{ const r=await fetch(API+'/git/blobs/'+sha,{headers:hd('application/vnd.github.raw')}); if(r.ok) m=await dec(await r.text()); }catch(_){}
      blobs.set(sha,m); return m;
    }
    async function loadTree(){
      const r=await fetch(API+'/git/trees/reviews?recursive=1',{headers:hd('application/vnd.github+json'),cache:'no-store'});
      if(r.status===404||r.status===409){ tree=[]; return; }
      if(!r.ok) throw new Error('HTTP '+r.status);
      tree=[];
      for(const x of (await r.json()).tree||[]){
        const m=x.type==='blob'&&/^reviews\\/t(\\d+)\\/(\\d{8}-\\d{6}-(r\\d+|a)\\.txt)$/.exec(x.path);
        if(m) tree.push({t:+m[1],name:m[2],who:m[3]==='a'?'a':'r',sha:x.sha});
      }
      tree.sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
      pend=pend.filter(p=>!tree.some(f=>f.t===p.t&&f.name.endsWith('-r'+p.id+'.txt')));
    }
    const threads=()=>{ const g=new Map(); for(const f of tree){ if(gone.has(f.t)) continue; if(!g.has(f.t)) g.set(f.t,[]); g.get(f.t).push(f); }
      for(const p of pend) if(!g.has(p.t)) g.set(p.t,[]);
      return [...g].map(([t,fs])=>({t,fs})).sort((a,b)=>last(b)-last(a)); };
    const last=th=>Math.max(th.fs.length?fnTime(th.fs[th.fs.length-1].name):0,...pend.filter(p=>p.t===th.t).map(p=>p.ms));
    const headOf=async th=>{ const p=pend.find(x=>x.t===th.t&&x.title); if(!th.fs.length) return p?{title:p.title,name:p.name}:{title:'(기록 중)'};
      const m=await blob(th.fs[0].sha); if(!m) return {title:'(읽을 수 없음)'}; return {title:m.title||m.text.split('\\n')[0].slice(0,40),name:m.name}; };
    function bubble(who,ms,text,pending,name,dev){
      const el=mk('div','rvmsg '+(who==='a'?'a':mine(name,dev)?'me':'r')+(pending?' pending':'')); el.append(mk('small',null,[who==='a'?'Claude':name,kst(ms),pending?'기록 중':''].filter(Boolean).join(' · ')),mk('p',null,text)); return el;   // 답변 이름은 경로로 확인된 고정값
    }
    async function draw(){
      const inList=cur===null, isNew=cur==='new';
      del.hidden=inList||isNew; if(inList||isNew) cf.hidden=true;
      back.hidden=inList; listV.hidden=!inList; log.hidden=inList||isNew; comp.hidden=inList;
      tIn.hidden=!isNew; bt.textContent=isNew?'스레드 만들기':'답글 올리기';
      if(inList){
        ttl.textContent='스레드';
        const ths=threads(), rows=await Promise.all(ths.map(async th=>{
          const row=mk('button','rvrow'); row.type='button';
          const lastF=th.fs[th.fs.length-1], waiting=pend.some(p=>p.t===th.t)||(lastF&&lastF.who==='r');
          const h=await headOf(th);
          row.append(mk('b',null,h.title),
            mk('span',null,(h.name?h.name+' · ':'')+th.fs.length+'개 · '+(last(th)?kst(last(th)):'')+' · '+(waiting?'답변 대기':'답변함')));
          if(waiting) row.classList.add('wait');
          row.addEventListener('click',()=>{ cur=th.t; msg.textContent=''; draw().then(()=>{ log.scrollTop=log.scrollHeight; }); });
          return row; }));
        listV.textContent=''; listV.append(newB, ...rows);
        if(!rows.length) listV.append(mk('p','rve','아직 스레드가 없습니다.'));
        return;
      }
      if(isNew){ ttl.textContent='새 스레드'; return; }
      const th=threads().find(x=>x.t===cur)||{t:cur,fs:[]};
      ttl.textContent=(await headOf(th)).title;
      const atBottom=log.scrollHeight-log.scrollTop-log.clientHeight<40;
      const els=await Promise.all(th.fs.map(async f=>{ const m=await blob(f.sha); return m?bubble(f.who,Date.parse(m.at)||fnTime(f.name),m.text,false,m.name,m.dev):null; }));
      log.textContent=''; els.forEach(x=>{ if(x) log.append(x); });
      pend.filter(p=>p.t===cur).forEach(p=>log.append(bubble('r',p.ms,p.text,true,p.name,DEV)));
      if(atBottom) log.scrollTop=log.scrollHeight;
    }
    const refresh=()=>loadTree().then(draw).then(()=>{ if(!pend.length&&/^올렸습니다/.test(msg.textContent)) msg.textContent=''; }).catch(e=>{ msg.textContent='불러오지 못했습니다 — '+e.message; });
    back.addEventListener('click',()=>{ cur=null; msg.textContent=''; draw(); });
    newB.addEventListener('click',()=>{ cur='new'; msg.textContent=''; draw(); tIn.focus(); });
    rf.addEventListener('click',refresh);
    del.addEventListener('click',()=>{ cf.hidden=false; });
    cfN.addEventListener('click',()=>{ cf.hidden=true; });
    cfY.addEventListener('click',async()=>{
      const t=cur; if(typeof t!=='number') return; cfY.disabled=true;
      try{
        const r=await fetch(API+'/issues/'+t,{method:'PATCH',headers:Object.assign(hd('application/vnd.github+json'),{'Content-Type':'application/json'}),
          body:JSON.stringify({state:'closed',state_reason:'not_planned'})});
        if(!r.ok) throw new Error('HTTP '+r.status);
        gone.add(t); pend=pend.filter(p=>p.t!==t); cur=null; cf.hidden=true;
        msg.textContent='삭제했습니다 — 1분쯤 뒤 완전히 지워집니다'; await draw();
      }catch(e){ msg.textContent='삭제하지 못했습니다 — '+e.message; }
      cfY.disabled=false;
    });
    nm.addEventListener('change',()=>{ if(cur!==null&&cur!=='new') draw(); });
    async function seal(obj){
      const z=new Uint8Array(await pipe(new TextEncoder().encode(JSON.stringify(obj)),new CompressionStream('deflate-raw')));
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,tagLength:128},await keyP,z));
      const body=['sapporo-review v2',b64(iv),b64(ct)].join(String.fromCharCode(10));
      if(body.length>65000) throw new Error('too-long');
      return body;
    }
    const post=(path,o)=>fetch(API+path,{method:'POST',headers:Object.assign(hd('application/vnd.github+json'),{'Content-Type':'application/json'}),body:JSON.stringify(o)})
      .then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); });
    bt.addEventListener('click',async()=>{
      const text=ta.value.trim(), title=tIn.value.trim(), name=nm.value.trim();
      if(!name){ msg.textContent='작성자 이름을 적어 주세요'; nm.focus(); return; }
      if(!text){ msg.textContent='내용이 비어 있습니다'; return; }
      try{ localStorage.setItem(NK,name); }catch(_){}
      if(cur==='new'&&!title){ msg.textContent='제목을 적어 주세요'; return; }
      bt.disabled=true; msg.textContent='암호화해서 올리는 중…';
      try{
        const now=new Date().toISOString();
        if(cur==='new'){
          const j=await post('/issues',{title:'review '+now.slice(0,16).replace('T',' '),body:await seal({v:2,at:now,name,dev:DEV,title,text})});
          pend.push({t:j.number,id:j.number,text,title,name,ms:Date.now()}); cur=j.number; tIn.value='';
        }else{
          const j=await post('/issues/'+cur+'/comments',{body:await seal({v:2,at:now,name,dev:DEV,text})});
          pend.push({t:cur,id:j.id,text,name,ms:Date.now()});
        }
        ta.value=''; msg.textContent='올렸습니다 — 1분쯤 뒤 기록되면 고정됩니다';
        await draw(); log.scrollTop=log.scrollHeight;
        let k=0; const iv2=setInterval(()=>{ if(!pend.length||++k>16){ clearInterval(iv2); if(pend.length) msg.textContent='기록이 늦어지고 있습니다 — 잠시 뒤 새로고침'; else msg.textContent=''; return; } refresh(); },15000);
      }catch(e){ msg.textContent=e.message==='too-long'?'너무 깁니다 — 나눠서 올려 주세요':'올리지 못했습니다 — '+e.message; }
      bt.disabled=false;
    });
    refresh(); setInterval(()=>{ if(!document.hidden&&!pend.length) refresh(); },60000);
  }
  // 지금 모드 — 일본 시각(JST) 기준
  const jst=()=>{ const t=new Date(Date.now()+9*36e5).toISOString(); return [t.slice(0,10),t.slice(11,16)]; };
  const days=(a,b)=>Math.round((Date.parse(b)-Date.parse(a))/864e5);
  let first=true;
  function tick(){
    const [ymd,hm]=jst(), dd=$('#dday');
    if(dd){
      if(S&&ymd<S) dd.textContent='D-'+days(ymd,S);
      else if(S&&E&&ymd<=E) dd.textContent='여행 중 · DAY '+(days(S,ymd)+1);
      else dd.textContent='';
    }
    $$('.it.now,.it.next').forEach(n=>n.classList.remove('now','next'));
    $$('.day.today,.toc a.today').forEach(n=>n.classList.remove('today'));
    const day=$('.day[data-date="'+ymd+'"]'); let bar=$('.nowbar');
    if(!day){ if(bar) bar.remove(); return; }
    day.classList.add('today');
    const na=$('.toc a[href="#'+day.id+'"]'); if(na) na.classList.add('today');
    let cur=null,nxt=null;
    for(const it of $$('.it[data-t]',day)){ if(it.dataset.t<=hm) cur=it; else { nxt=it; break; } }
    if(cur) cur.classList.add('now'); if(nxt) nxt.classList.add('next');
    if(!bar){
      bar=document.createElement('div'); bar.className='nowbar'; bar.setAttribute('role','button');
      bar.addEventListener('click',()=>{ const t=$('.it.now')||$('.it.next'); if(t) t.scrollIntoView({behavior:'smooth',block:'center'});
        history.replaceState(null,'',location.pathname+location.search); });   // 다음 새로 고침은 다시 「지금」으로
      B.append(bar);
    }
    const nm=n=>{ const t=n&&$('.tt',n); return t?t.textContent:''; };
    bar.textContent='';
    const lab=document.createElement('b');
    if(nxt){ lab.textContent='다음 '+nxt.dataset.t; bar.append(lab,' '+nm(nxt)); }
    else { lab.textContent='오늘 일정 끝'; bar.append(lab); }
    if(first&&!location.hash){ first=false; const t=cur||nxt; if(t) setTimeout(()=>t.scrollIntoView({block:'center'}),60); }
    first=false;
  }
  // 목차 — 지금 보고 있는 섹션을 강조. 넓은 화면은 늘 보이고, 좁은 화면은 스크롤할 때만 버튼이 떴다가 2초 뒤 숨는다
  const T=$('.toc');
  if(T){
    const links=$$('.toc-p a[data-s]',T), secs=links.map(a=>document.getElementById(a.getAttribute('href').slice(1)));
    const btn=document.createElement('button'), curL=document.createElement('span'), wide=matchMedia('(min-width:1280px)');
    btn.type='button'; btn.className='toc-b'; btn.setAttribute('aria-expanded','false'); btn.setAttribute('aria-controls','toc-p');
    curL.className='toc-cur'; curL.textContent='목차'; btn.append(curL,' ☰'); T.append(btn);
    let hideT=0, raf=0;
    const show=ms=>{ T.classList.remove('hide'); clearTimeout(hideT);
      if(!wide.matches&&!T.classList.contains('open')) hideT=setTimeout(()=>T.classList.add('hide'),ms); };
    const setOpen=o=>{ T.classList.toggle('open',o); btn.setAttribute('aria-expanded',String(o)); show(2000); };
    btn.addEventListener('click',()=>setOpen(!T.classList.contains('open')));
    document.addEventListener('click',ev=>{ if(T.classList.contains('open')&&!T.contains(ev.target)) setOpen(false); });
    $$('.toc-p a',T).forEach(a=>a.addEventListener('click',ev=>{
      const id=a.getAttribute('href').slice(1), t=id==='top'?null:document.getElementById(id);
      ev.preventDefault();
      const dd=t&&t.querySelector('details'); if(dd) dd.open=true;   // 접힌 섹션은 목차로 가면 펼친다
      if(t) t.scrollIntoView({behavior:'smooth',block:'start'}); else scrollTo({top:0,behavior:'smooth'});
      history.replaceState(null,'',t?'#'+id:location.pathname+location.search);   // 주소에 남겨 새로 고침해도 그 자리 (기록은 쌓지 않음)
      if(T.classList.contains('open')) setOpen(false);
    }));
    const spy=()=>{ raf=0;
      let k=-1; secs.forEach((x,i)=>{ if(x&&x.getBoundingClientRect().top<=48) k=i; });
      if(innerHeight+scrollY>=document.documentElement.scrollHeight-4) k=secs.length-1;
      links.forEach((a,i)=>a.classList.toggle('on',i===k));
      curL.textContent=k>=0?links[k].dataset.s:'목차';
      if(k>=0&&wide.matches){ const a=links[k], r=a.getBoundingClientRect(), R=T.getBoundingClientRect();
        if(r.top<R.top||r.bottom>R.bottom) T.scrollTop+=r.top-R.top-R.height/2; }
    };
    addEventListener('scroll',()=>{ if(!raf) raf=requestAnimationFrame(spy); show(2000); },{passive:true});
    wide.addEventListener('change',()=>{ setOpen(false); show(3000); });
    spy(); show(3000);
  }
  tick(); setInterval(tick,30000);
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden) tick(); });
  if(location.hash){
    const t=document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if(t){ const own=t.querySelector(':scope>details'), up=t.closest('details');   // 접힌 섹션이면 펼친 뒤 이동
      if(own) own.open=true; if(up) up.open=true; t.scrollIntoView(); }
  }
  else scrollTo(0,0);
}
const F=document.getElementById('f'),Bt=document.getElementById('b'),Er=document.getElementById('e');
F.addEventListener('submit',async ev=>{
  ev.preventDefault(); Bt.disabled=true; Bt.textContent='여는 중…'; Er.textContent='';
  try{
    const pw=document.getElementById('p').value.trim();
    const html=await unlock(pw);
    if(document.getElementById('r').checked) localStorage.setItem(LK,pw);
    render(html);
  }catch(_){ Er.textContent='비밀번호가 맞지 않습니다'; Bt.disabled=false; Bt.textContent='열기';
    document.getElementById('p').select(); }
});
(async()=>{
  let v=localStorage.getItem(LK); if(!v) return;
  try{render(await unlock(v));}catch(_){localStorage.removeItem(LK);}
})();`;

  const hash = crypto.createHash('sha256').update(SCRIPT, 'utf8').digest('base64');
  const CSP = `default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; ` +
              `script-src 'sha256-${hash}'; connect-src https://api.github.com; object-src 'none'; base-uri 'none'; form-action 'none'`;

  const out = `<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<title>SAPPORO</title>
<meta name="robots" content="noindex,nofollow">
<meta property="og:type" content="website">
<meta property="og:title" content="SAPPORO">
<meta property="og:description" content="비밀번호가 필요한 페이지입니다.">
<meta property="og:url" content="https://jiyolla.github.io/sapporo-2026/">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta name="theme-color" content="#0b1530">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px;
 font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard",sans-serif;
 background:radial-gradient(120% 60% at 50% 115%,rgba(245,176,66,.32) 0%,rgba(245,176,66,0) 60%),
 linear-gradient(180deg,#070d22 0%,#13204a 55%,#283a78 100%);color:#fff}
.box{width:100%;max-width:340px;text-align:center}
svg{width:58px;height:58px;margin:0 auto 22px;display:block;opacity:.95}
h1{font-size:26px;font-weight:900;letter-spacing:.08em;margin-bottom:7px}
p{font-size:13.5px;opacity:.6;margin-bottom:24px}
input[type=password]{width:100%;padding:14px 16px;font-size:16px;border-radius:12px;
 border:1px solid rgba(255,255,255,.22);background:rgba(255,255,255,.1);color:#fff;text-align:center;outline:none}
input[type=password]::placeholder{color:rgba(255,255,255,.4)}
input[type=password]:focus{border-color:#ffd58a;background:rgba(255,255,255,.15)}
button{width:100%;margin-top:10px;padding:14px;font-size:15px;font-weight:800;border:0;
 border-radius:12px;background:#ffd58a;color:#0b1530;cursor:pointer}
button:disabled{opacity:.55}
.e{margin-top:14px;font-size:13px;color:#fca5a5;min-height:19px}
label{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:16px;font-size:12.5px;opacity:.6}
</style></head><body>
<div class="box">
  <svg viewBox="0 0 32 32" fill="none" stroke="#ffd58a" stroke-linecap="round" stroke-linejoin="round"><path d="M16.00 5.40L16.00 26.60M6.82 10.70L25.18 21.30M6.82 21.30L25.18 10.70" stroke-width="2"/><path d="M18.68 7.19L16.00 9.60L13.32 7.19M9.71 9.28L10.46 12.80L7.03 13.91M7.03 18.09L10.46 19.20L9.71 22.72M13.32 24.81L16.00 22.40L18.68 24.81M22.29 22.72L21.54 19.20L24.97 18.09M24.97 13.91L21.54 12.80L22.29 9.28" stroke-width="1.6"/></svg>
  <h1>SAPPORO</h1><p>비밀번호를 입력하세요</p>
  <form id="f"><input id="p" type="password" placeholder="비밀번호" autocomplete="off"
   autocapitalize="off" autocorrect="off" spellcheck="false" autofocus>
  <button id="b" type="submit">열기</button>
  <label><input type="checkbox" id="r"> 이 기기에서 기억</label></form>
  <div class="e" id="e"></div>
</div>
<script>${SCRIPT}</script></body></html>
`;
  // 평문에서 뽑을 수 있는 모든 특징 토큰을, 커밋 대상 전체 파일에 대해 전수 검사한다.
  const txt = plain.toString('utf8');
  const tokens = new Set();
  for (const m of txt.matchAll(/[가-힣][가-힣\s·]{7,}/g)) tokens.add(m[0].trim());   // 한글 본문
  for (const m of txt.matchAll(/[぀-ヿ一-鿿]{4,}/g)) tokens.add(m[0]); // 일본어 고유명
  for (const m of txt.matchAll(/\b[A-Z0-9]{2}\d{3,4}\b/g)) tokens.add(m[0]);         // 편명
  for (const m of txt.matchAll(/\d{2,4}-\d{3,4}-\d{4}/g)) tokens.add(m[0]);           // 전화번호
  for (const m of txt.matchAll(/[A-Za-z]{4,}(?:\s+[A-Za-z]{2,}){2,}/g)) tokens.add(m[0]); // 영문 주소류
  for (const m of txt.matchAll(/github_pat_[A-Za-z0-9_]{20,}/g)) tokens.add(m[0]);   // 리뷰 토큰
  for (const m of txt.matchAll(/data-rk="([A-Za-z0-9+/=]{40,})"/g)) tokens.add(m[1]); // 리뷰 키
  tokens.add(pw);                                                                     // 비밀번호 자체
  // 로더 템플릿(=이 스크립트)과 공유하는 문자열은 보일러플레이트이므로 표본에서 뺀다
  const boiler = fs.readFileSync(__filename, 'utf8');
  if (boiler.includes(pw)) { console.error('비밀번호가 build.js 안에 있습니다'); process.exit(1); }
  const probes = [...tokens].filter(t => t === pw || ((t.length >= 8 || /[぀-鿿]/.test(t)) && !boiler.includes(t)));
  if (probes.length < 50) { console.error('검사 표본 부족'); process.exit(1); }

  // 커밋될 수 있는 파일 전부(추적 + 무시되지 않은 미추적) + 지금 만든 산출물
  const tracked = require('child_process').execSync('git ls-files --cached --others --exclude-standard', { encoding: 'utf8' })
    .split('\n').filter(Boolean).filter(f => f !== 'index.html');
  const targets = ['index.html', ...new Set(tracked)].filter(f => f === 'index.html' || (fs.existsSync(f) && !/\.(webp|png)$/.test(f)));
  let scanned = 0;
  for (const f of targets) {
    const body = f === 'index.html' ? out : fs.readFileSync(f).toString('utf8');
    for (const probe of probes) {
      if (body.includes(probe)) {
        console.error(`평문 누출: ${f} 안에 "${probe === pw ? '(비밀번호)' : probe.slice(0, 14) + '…'}"`); process.exit(1);
      }
    }
    scanned++;
  }
  fs.writeFileSync('index.html.tmp', out);
  fs.renameSync('index.html.tmp', 'index.html');
  console.log(`index.html · 평문 ${(plain.length/1024)|0}KB → 암호문 ${(ct.length/1024)|0}KB · PBKDF2 ${ITER.toLocaleString()}회`);
  console.log(`왕복 검증 통과 · 토큰 ${probes.length}개 × 파일 ${scanned}개 전수 검사 통과 · CSP ${hash.slice(0,12)}…`);
})();
