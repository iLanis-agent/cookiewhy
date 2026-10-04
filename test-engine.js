const C=require('./engine.js'),cp=require('child_process');
let seed=4242;const rnd=n=>{seed=(seed*1103515245+12345)&0x7fffffff;return (seed>>8)%n};const pick=a=>a[rnd(a.length)];
const lab=()=>pick(['a','b','www','example','com','x1']);
const host=()=>{const n=1+rnd(3);const a=[];for(let i=0;i<n;i++)a.push(lab());return a.join('.')};
const ipOrHost=()=>rnd(6)?host():pick(['1.2.3.4','10.0.0.1']);
const seg=()=>pick(['a','b','dir','x']);
const pth=()=>{const n=rnd(4);let s='';for(let i=0;i<n;i++)s+='/'+seg();if(rnd(3)===0)s+='/';return s||'/'};
const dm=[],pm=[],dp=[];
for(let i=0;i<4000;i++){const h=ipOrHost();let d=rnd(2)?h:host();if(rnd(2)&&h.indexOf('.')>0)d=h.slice(h.indexOf('.')+1);if(rnd(8)===0)d=pick(['1.2.3.4','3.4']);dm.push([h,d]);}
for(let i=0;i<4000;i++){pm.push([pth(),pth()]);dp.push(rnd(9)===0?pick(['','x','a/b']):pth());}
const o=JSON.parse(cp.execFileSync('python3',['oracle.py'],{input:JSON.stringify({dm,pm,dp}),maxBuffer:1e8}));
let bad=0;const rep=(k,i,a,b)=>{bad++;if(bad<15)console.log(k,JSON.stringify(i),a,b)};
dm.forEach((x,i)=>{const r=C.domainMatch(x[0],x[1]);if(r!==o.dm[i])rep('domainMatch',x,r,o.dm[i])});
pm.forEach((x,i)=>{const r=C.pathMatch(x[0],x[1]);if(r!==o.pm[i])rep('pathMatch',x,r,o.pm[i])});
dp.forEach((x,i)=>{const r=C.defaultPath(x);if(r!==o.dp[i])rep('defaultPath',x,r,o.dp[i])});
// worked behaviours from RFC 6265 text and common traps
const T=1e12,eqs=[];const chk=(n,c)=>{if(!c){bad++;console.log('FAIL',n)}eqs.push(n)};
let p=C.parse('sid=1; Path=/; Domain=example.com','https://www.example.com/a/b',T);chk('domain ok',p.ok&&!p.cookie.hostOnly&&p.cookie.domain==='example.com');
p=C.parse('sid=1; Domain=evil.com','https://www.example.com/',T);chk('foreign domain rejected',!p.ok);
p=C.parse('sid=1; Domain=.Example.COM','https://www.example.com/',T);chk('leading dot and case',p.ok&&p.cookie.domain==='example.com');
p=C.parse('sid=1','https://example.com/a/b/c',T);chk('default path',p.cookie.path==='/a/b');
p=C.parse('sid=1; Max-Age=60; Expires=Wed, 21 Oct 2015 07:28:00 GMT','https://example.com/',T);chk('max-age wins',p.cookie.expiry===T+60000);
p=C.parse('sid=1; Max-Age=0','https://example.com/',T);chk('max-age 0 expired',p.cookie.expiry<=T);
p=C.parse('sid=1; Max-Age=1.5','https://example.com/',T);chk('bad max-age ignored',p.cookie.persistent===false);
p=C.parse('=x','https://example.com/',T);chk('empty name',!p.ok);
p=C.parse('novalue','https://example.com/',T);chk('no equals',!p.ok);
p=C.parse(' a = b c ; Secure ; HttpOnly','https://example.com/',T);chk('trim',p.ok&&p.cookie.name==='a'&&p.cookie.value==='b c'&&p.cookie.secure&&p.cookie.httpOnly);
p=C.parse('a=b; Path=x','https://example.com/q/r',T);chk('relative path attr',p.cookie.path==='/q');
p=C.parse('a=b; Domain=example.com','https://example.com/',T);chk('host-only vs domain',C.willSend(p.cookie,'https://sub.example.com/',T).send===true);
p=C.parse('a=b','https://example.com/',T);chk('host-only no subdomain',C.willSend(p.cookie,'https://sub.example.com/',T).send===false);
p=C.parse('a=b; Secure','https://example.com/',T);chk('secure not over http',C.willSend(p.cookie,'http://example.com/',T).send===false);
p=C.parse('__Host-a=b; Secure; Path=/; Domain=example.com','https://example.com/',T);chk('host prefix note',p.issues.some(x=>x.includes('__Host-')));
p=C.parse('a=b; SameSite=None','https://example.com/',T);chk('samesite none note',p.issues.some(x=>x.includes('SameSite=None')));
p=C.parse('a=b; Path=/app','https://example.com/',T);chk('path /app vs /apple',C.willSend(p.cookie,'https://example.com/apple',T).send===false&&C.willSend(p.cookie,'https://example.com/app/x',T).send===true);
console.log('checks',dm.length+pm.length+dp.length+eqs.length,'mismatches/fails',bad);process.exit(bad?1:0);
