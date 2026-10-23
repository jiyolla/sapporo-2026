// 평문 원본을 AES-256-GCM 으로 암호화해 index.html(로더) 를 만든다.
// 평문·비밀번호는 저장소 밖에 둔다.  사용: node build.js
// 비밀번호는 PRIV/password(600) → PW 환경변수 → 숨김 입력 순으로 찾는다.
const fs = require('fs'), crypto = require('crypto'), path = require('path');

const PRIV = process.env.PRIV || `${process.env.HOME}/home/.sapporo-private`;
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
  const pw = (await password()).normalize('NFC');
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
function render(html){
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
    $$('.day.today,.dn a.today').forEach(n=>n.classList.remove('today'));
    const day=$('.day[data-date="'+ymd+'"]'); let bar=$('.nowbar');
    if(!day){ if(bar) bar.remove(); return; }
    day.classList.add('today');
    const na=$('.dn a[href="#'+day.id+'"]'); if(na) na.classList.add('today');
    let cur=null,nxt=null;
    for(const it of $$('.it[data-t]',day)){ if(it.dataset.t<=hm) cur=it; else { nxt=it; break; } }
    if(cur) cur.classList.add('now'); if(nxt) nxt.classList.add('next');
    if(!bar){
      bar=document.createElement('div'); bar.className='nowbar'; bar.setAttribute('role','button');
      bar.addEventListener('click',()=>{ const t=$('.it.now')||$('.it.next'); if(t) t.scrollIntoView({behavior:'smooth',block:'center'}); });
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
  tick(); setInterval(tick,30000);
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden) tick(); });
  if(location.hash){ const t=document.getElementById(location.hash.slice(1)); if(t) t.scrollIntoView(); }
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
              `script-src 'sha256-${hash}'; object-src 'none'; base-uri 'none'; form-action 'none'`;

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
  tokens.add(pw);                                                                     // 비밀번호 자체
  // 로더 템플릿(=이 스크립트)과 공유하는 문자열은 보일러플레이트이므로 표본에서 뺀다
  const boiler = fs.readFileSync(__filename, 'utf8');
  const probes = [...tokens].filter(t => (t.length >= 8 || /[぀-鿿]/.test(t) || t === pw) && !boiler.includes(t));
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
