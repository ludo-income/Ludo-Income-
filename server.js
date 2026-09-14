const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),url=require('url');
const db=require('./database');
let webPush=null; try{webPush=require('web-push')}catch{webPush=null}
/* Native WebSocket (no external ws package required) */
const ROOT=__dirname,PORT=process.env.PORT||3000;
// Backward-compatible environment names: existing Render deployments may use
// ADMIN_MOBILE + JWT_SECRET. Prefer the newer ADMIN_USERNAME/ADMIN_SECRET/USER_SECRET
// names when they are present, without forcing the user to recreate their Render config.
const LEGACY_JWT_SECRET=String(process.env.JWT_SECRET||'');
const SECRET=String(process.env.ADMIN_SECRET||LEGACY_JWT_SECRET||'');
const ADMIN_USERNAME=String(process.env.ADMIN_USERNAME||process.env.ADMIN_MOBILE||'');
const ADMIN_PASSWORD=String(process.env.ADMIN_PASSWORD||'');
const ADMIN_ROLE=String(process.env.ADMIN_ROLE||'super_admin');
const USER_SECRET=String(process.env.USER_SECRET||((LEGACY_JWT_SECRET&&LEGACY_JWT_SECRET.length>=32)?crypto.createHash('sha256').update(LEGACY_JWT_SECRET+'|ludo-baji-user-secret').digest('hex'):''));
const CORS_ORIGIN=String(process.env.CORS_ORIGIN||'').trim();
let VAPID_PUBLIC_KEY=String(process.env.VAPID_PUBLIC_KEY||'').trim();
let VAPID_PRIVATE_KEY=String(process.env.VAPID_PRIVATE_KEY||'').trim();
const VAPID_SUBJECT=String(process.env.VAPID_SUBJECT||'mailto:admin@example.com').trim();
async function ensureVapidConfig(){if(!webPush)return false;try{const d=await read();const cfg=d.pushConfig||{};if(!VAPID_PUBLIC_KEY||!VAPID_PRIVATE_KEY){VAPID_PUBLIC_KEY=String(cfg.public_key||'').trim();VAPID_PRIVATE_KEY=String(cfg.private_key||'').trim();}if(!VAPID_PUBLIC_KEY||!VAPID_PRIVATE_KEY){const ecdh=crypto.createECDH('prime256v1');ecdh.generateKeys();VAPID_PRIVATE_KEY=ecdh.getPrivateKey().toString('base64url');VAPID_PUBLIC_KEY=ecdh.getPublicKey().toString('base64url');d.pushConfig={public_key:VAPID_PUBLIC_KEY,private_key:VAPID_PRIVATE_KEY,created_at:new Date().toISOString()};await write(d);}webPush.setVapidDetails(VAPID_SUBJECT,VAPID_PUBLIC_KEY,VAPID_PRIVATE_KEY);return true}catch(e){console.error('VAPID configuration error:',e.message);return false}}
const TRUST_PROXY=String(process.env.TRUST_PROXY||'').toLowerCase()==='true';
const MAX_BODY_BYTES=Math.max(1024*1024,Number(process.env.MAX_BODY_MB||10)*1024*1024);
const ADMIN_TOKEN_TTL_MS=Math.max(15,Number(process.env.ADMIN_TOKEN_TTL_MINUTES||480))*60*1000;
const ADMIN_LOGIN_WINDOW_MS=15*60*1000,ADMIN_LOGIN_MAX_ATTEMPTS=Math.max(3,Number(process.env.ADMIN_LOGIN_MAX_ATTEMPTS||5));
const adminSessions=new Map(),adminLoginAttempts=new Map(),otpRequestAttempts=new Map();
function requireSecurityEnv(){const missing=[];if(!ADMIN_USERNAME||ADMIN_USERNAME.length<3||ADMIN_USERNAME.length>100)missing.push('ADMIN_USERNAME (3-100 characters)');if(!ADMIN_PASSWORD||ADMIN_PASSWORD.length<12||ADMIN_PASSWORD.length>200)missing.push('ADMIN_PASSWORD (12-200 characters)');if(!SECRET||SECRET.length<32)missing.push('ADMIN_SECRET (minimum 32 characters)');if(!USER_SECRET||USER_SECRET.length<32)missing.push('USER_SECRET (minimum 32 characters)');if(SECRET&&USER_SECRET&&SECRET===USER_SECRET)missing.push('USER_SECRET must be different from ADMIN_SECRET');if(missing.length)throw new Error('Required security environment variables are missing/unsafe: '+missing.join(', '));}
requireSecurityEnv();
const OTP_TTL_MS=Math.max(60,Number(process.env.OTP_TTL_SECONDS||300))*1000;
const OTP_COOLDOWN_MS=Math.max(30,Number(process.env.OTP_COOLDOWN_SECONDS||60))*1000;
const OTP_MAX_ATTEMPTS=Math.max(3,Number(process.env.OTP_MAX_ATTEMPTS||5));
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp','.svg':'image/svg+xml','.webmanifest':'application/manifest+json'};
async function read(){return db.getData()}
async function write(d){return db.saveData(d)}
function send(res,status,body,type='application/json; charset=utf-8'){const h={'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()'};if(CORS_ORIGIN){h['Access-Control-Allow-Origin']=CORS_ORIGIN;h['Access-Control-Allow-Headers']='Content-Type, Authorization';h['Access-Control-Allow-Methods']='GET,POST,PUT,DELETE,OPTIONS';h['Vary']='Origin'}res.writeHead(status,h);res.end(typeof body==='string'?body:JSON.stringify(body))}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>MAX_BODY_BYTES){req.destroy();reject(new Error('Payload too large'))}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}});req.on('error',reject)})}
function signToken(payload,secret){const p=Buffer.from(JSON.stringify(payload)).toString('base64url');const s=crypto.createHmac('sha256',secret).update(p).digest('base64url');return p+'.'+s}
function verifyToken(raw,secret){try{const [p,s]=String(raw||'').split('.');if(!p||!s)return null;const es=crypto.createHmac('sha256',secret).update(p).digest('base64url');if(s.length!==es.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(es)))return null;const x=JSON.parse(Buffer.from(p,'base64url').toString());if(!x.e||Date.now()>x.e)return null;return x}catch{return null}}
function passwordMatches(input,expected){const a=Buffer.from(String(input||''));const b=Buffer.from(String(expected||''));return a.length===b.length&&crypto.timingSafeEqual(a,b)}
function clientKey(req){if(TRUST_PROXY){const xf=String(req.headers['x-forwarded-for']||'').split(',')[0].trim();if(xf)return xf}return req.socket.remoteAddress||'unknown'}
function loginBlocked(key){const now=Date.now(),x=adminLoginAttempts.get(key);if(!x)return false;if(now-x.first>ADMIN_LOGIN_WINDOW_MS){adminLoginAttempts.delete(key);return false}return x.count>=ADMIN_LOGIN_MAX_ATTEMPTS}
function recordLoginFailure(key){const now=Date.now(),x=adminLoginAttempts.get(key);if(!x||now-x.first>ADMIN_LOGIN_WINDOW_MS){adminLoginAttempts.set(key,{first:now,count:1});return}x.count++;adminLoginAttempts.set(key,x)}
function clearLoginFailures(key){adminLoginAttempts.delete(key)}
function otpBlocked(key){const now=Date.now(),x=otpRequestAttempts.get(key);if(!x)return false;if(now-x.first>60*1000){otpRequestAttempts.delete(key);return false}return x.count>=2}
function recordOtpRequest(key){const now=Date.now(),x=otpRequestAttempts.get(key);if(!x||now-x.first>60*1000){otpRequestAttempts.set(key,{first:now,count:1});return}x.count++;otpRequestAttempts.set(key,x)}
const otpSendLocks=new Map();
function acquireOtpLock(email){const k=String(email||'').toLowerCase();if(otpSendLocks.get(k))return false;otpSendLocks.set(k,Date.now());setTimeout(()=>otpSendLocks.delete(k),90*1000);return true}
function releaseOtpLock(email){otpSendLocks.delete(String(email||'').toLowerCase())}
function clearOtpRequests(key){otpRequestAttempts.delete(key)}
function issueAdminToken(){const jti=crypto.randomBytes(24).toString('hex'),e=Date.now()+ADMIN_TOKEN_TTL_MS;adminSessions.set(jti,{expiresAt:e,role:ADMIN_ROLE});return signToken({u:'admin',e,jti,role:ADMIN_ROLE},SECRET)}
function permissionForPath(method,p){if(p==='/api/admin/data'||p.startsWith('/api/admin/main-options'))return 'website';if(p.startsWith('/api/admin/payment-methods'))return 'deposits';if(p.startsWith('/api/admin/deposits'))return 'deposits';if(p.startsWith('/api/admin/withdrawals')||p.startsWith('/api/admin/withdraw-config'))return 'withdrawals';if(p.startsWith('/api/admin/users'))return 'users';if(p.startsWith('/api/admin/matches')||p==='/api/admin/match-players')return 'matches';if(p.startsWith('/api/admin/transactions'))return 'transactions';if(p.startsWith('/api/admin/support'))return 'support';if(p.startsWith('/api/admin/reports'))return 'reports';if(p.startsWith('/api/admin/audit-log'))return 'audit';if(p.startsWith('/api/admin/roles'))return 'roles';if(p.startsWith('/api/admin/banners')||p.startsWith('/api/admin/faqs')||p.startsWith('/api/admin/pages')||p.startsWith('/api/admin/referral')||p.startsWith('/api/admin/tournaments'))return 'website';if(p.startsWith('/api/admin/system')||p.startsWith('/api/admin/notice'))return 'settings';return null}
async function auth(req,res){const raw=String(req.headers.authorization||'').replace(/^Bearer\s+/i,''),x=verifyToken(raw,SECRET);if(!x||x.u!=='admin'||!x.jti){send(res,401,{error:'Unauthorized'});return null}const session=adminSessions.get(x.jti);if(!session||session.expiresAt<=Date.now()){adminSessions.delete(x.jti);send(res,401,{error:'Session expired'});return null}if(session.role!==ADMIN_ROLE||x.role!==ADMIN_ROLE){adminSessions.delete(x.jti);send(res,403,{error:'Admin role is not permitted'});return null}const d=await read(),roles=Array.isArray(d.adminRoles)?d.adminRoles:[],role=roles.find(r=>String(r.id)===ADMIN_ROLE);if(!role){send(res,403,{error:'Configured admin role does not exist'});return null}const perm=permissionForPath(req.method,req.url.split('?')[0]);const permissions=Array.isArray(role.permissions)?role.permissions:[];if(perm&&!(permissions.includes('*')||permissions.includes(perm))){send(res,403,{error:'Permission denied'});return null}return x}
function revokeAdminToken(req){const raw=String(req.headers.authorization||'').replace(/^Bearer\s+/i,''),x=verifyToken(raw,SECRET);if(x?.jti)adminSessions.delete(x.jti);}
async function userAuth(req,res){const x=verifyToken((req.headers.authorization||'').replace(/^Bearer\s+/i,''),USER_SECRET);if(!x||x.typ!=='user'){send(res,401,{ok:false,error:'Login required'});return null}const u=await db.getUserById(x.id);if(!u){send(res,401,{ok:false,error:'Account not found'});return null}if(u.status!=='active'){send(res,403,{ok:false,error:'এই অ্যাকাউন্টটি বন্ধ আছে'});return null}return x}
function safeHttpUrl(input){const s=String(input||'').trim();if(!s)return '';try{const u=new URL(s);return ['http:','https:'].includes(u.protocol)?s:''}catch{return ''}}
function publicMatchStatus(m){const raw=String(m.status||'open').toLowerCase();if(['started','completed','cancelled'].includes(raw))return raw;return Array.isArray(m.players)&&m.players.length>=2?'full':'open'}
function normalizeBDPhone(input){let s=String(input||'').trim().replace(/[\s()-]/g,'');if(/^01\d{9}$/.test(s))return '+880'+s.slice(1);if(/^8801\d{9}$/.test(s))return '+'+s;if(/^\+8801\d{9}$/.test(s))return s;return null}
function pushConfigured(){return !!(webPush&&VAPID_PUBLIC_KEY&&VAPID_PRIVATE_KEY)}
async function pushSubscribe(userId,subscription){
  const d=await read(); d.pushSubscriptions=Array.isArray(d.pushSubscriptions)?d.pushSubscriptions:[];
  const sub=subscription||{}; if(!sub.endpoint||typeof sub.endpoint!=='string')throw new Error('Invalid push subscription');
  const item={user_id:String(userId),endpoint:sub.endpoint,keys:sub.keys||{},updated_at:new Date().toISOString()};
  const i=d.pushSubscriptions.findIndex(x=>String(x.user_id)===String(userId)&&x.endpoint===sub.endpoint);
  if(i>=0)d.pushSubscriptions[i]=item;else d.pushSubscriptions.push(item); await write(d); return item;
}
async function pushUnsubscribe(userId,endpoint){const d=await read();d.pushSubscriptions=Array.isArray(d.pushSubscriptions)?d.pushSubscriptions:[];d.pushSubscriptions=d.pushSubscriptions.filter(x=>!(String(x.user_id)===String(userId)&&(!endpoint||x.endpoint===endpoint)));await write(d)}
async function sendPushToUsers(userIds,title,message,data={}){
  if(!pushConfigured()) return {sent:0,configured:false};
  const d=await read();d.pushSubscriptions=Array.isArray(d.pushSubscriptions)?d.pushSubscriptions:[];const wanted=new Set((userIds||[]).map(String));
  const targets=d.pushSubscriptions.filter(x=>wanted.has(String(x.user_id)));
  let sent=0;const dead=[];
  for(const sub of targets){try{await webPush.sendNotification({endpoint:sub.endpoint,keys:sub.keys},JSON.stringify({title,message,data}));sent++}catch(e){if([404,410].includes(Number(e.statusCode)))dead.push(sub.endpoint);else console.error('Push send failed:',e.message)}}
  if(dead.length){d.pushSubscriptions=d.pushSubscriptions.filter(x=>!dead.includes(x.endpoint));await write(d)}
  return {sent,configured:true};
}

function otpHash(email,otp){return crypto.createHash('sha256').update(email+'|'+otp+'|'+USER_SECRET).digest('hex')}
function makeOtp(){return String(crypto.randomInt(0,1000000)).padStart(6,'0')}
function normalizeEmail(input){const e=String(input||'').trim().toLowerCase();return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)&&e.length<=254?e:null}
function maskEmail(email){const [local,domain]=String(email).split('@');if(!domain)return '****';return (local.length<=2?(local[0]||'*'):local.slice(0,2))+'***@'+domain}
async function addAudit(action,target,detail){try{const d=await read();d.auditLogs=Array.isArray(d.auditLogs)?d.auditLogs:[];d.auditLogs.unshift({id:'A-'+Date.now()+Math.random().toString(36).slice(2,5),action,target:String(target||''),detail,created_at:new Date().toISOString()});d.auditLogs=d.auditLogs.slice(0,2000);await write(d)}catch{}}

function supabaseConfigured(){
  const url=String(process.env.SUPABASE_URL||'').trim().replace(/\/$/,'');
  const key=String(process.env.SUPABASE_ANON_KEY||process.env.SUPABASE_PUBLISHABLE_KEY||'').trim();
  return !!(url&&key);
}
function supabaseAuthHeaders(){
  const key=String(process.env.SUPABASE_ANON_KEY||process.env.SUPABASE_PUBLISHABLE_KEY||'').trim();
  return {'apikey':key,'Authorization':'Bearer '+key,'Content-Type':'application/json'};
}
async function supabaseSendOtp(email){
  const url=String(process.env.SUPABASE_URL||'').trim().replace(/\/$/,'');
  if(!url)throw new Error('SUPABASE_URL missing');
  const r=await fetch(url+'/auth/v1/otp',{
    method:'POST',
    headers:supabaseAuthHeaders(),
    body:JSON.stringify({email,create_user:true})
  });
  const t=await r.text().catch(()=> '');
  let j={};try{j=JSON.parse(t||'{}')}catch{j={raw:t}}
  if(!r.ok){
    const msg=j.msg||j.error_description||j.error||t||('Supabase OTP failed '+r.status);
    throw new Error(String(msg));
  }
  return {sent:true,provider:'supabase'};
}
async function supabaseVerifyOtp(email,otp){
  const url=String(process.env.SUPABASE_URL||'').trim().replace(/\/$/,'');
  if(!url)throw new Error('SUPABASE_URL missing');
  const r=await fetch(url+'/auth/v1/verify',{
    method:'POST',
    headers:supabaseAuthHeaders(),
    body:JSON.stringify({email,token:String(otp),type:'email'})
  });
  const t=await r.text().catch(()=> '');
  let j={};try{j=JSON.parse(t||'{}')}catch{j={raw:t}}
  if(!r.ok){
    const msg=j.msg||j.error_description||j.error||t||('Invalid OTP');
    throw new Error(String(msg));
  }
  return j;
}
async function sendOtpEmail(email,otp){
  const fromAddr=String(process.env.SMTP_FROM||process.env.SMTP_USER||process.env.BREVO_SENDER||'').trim();
  const subject='Ludo Baji OTP: '+otp;
  const textBody='Your Ludo Baji OTP is '+otp+'. It expires in 5 minutes. Do not share this OTP with anyone.';
  const htmlBody='<div style="font-family:Arial,sans-serif;max-width:420px;margin:0 auto;padding:20px;background:#0b1f17;color:#fff;border-radius:12px"><h2 style="margin:0 0 12px;color:#10c878">Ludo Baji</h2><p style="margin:0 0 8px;color:#cde">Your login OTP:</p><div style="font-size:32px;font-weight:800;letter-spacing:6px;background:#123;padding:14px 18px;border-radius:10px;text-align:center;color:#fff">'+otp+'</div><p style="margin:14px 0 0;font-size:13px;color:#9ab">Expires in 5 minutes. Do not share with anyone.</p></div>';
  const devMode=String(process.env.OTP_DEV_MODE||'').toLowerCase()==='true';
  let lastErr=null;

  // 0) Dev mode first when no HTTP mail provider — instant, no hang
  const hasBrevo=!!String(process.env.BREVO_API_KEY||'').trim();
  const hasResend=!!String(process.env.RESEND_API_KEY||'').trim();
  const hasSmtp=!!(process.env.SMTP_USER&&process.env.SMTP_PASS);
  if(devMode && !hasBrevo && !hasResend){
    console.log('[OTP DEV] '+email+': '+otp);
    return {sent:false,dev:true,otp,provider:'dev'};
  }

  // 1) Brevo
  if(hasBrevo){
    try{
      const sender=String(process.env.BREVO_SENDER||fromAddr||'').trim();
      if(!sender) throw new Error('BREVO_SENDER সেট করুন');
      const r=await fetch('https://api.brevo.com/v3/smtp/emails',{
        method:'POST',
        headers:{'api-key':String(process.env.BREVO_API_KEY).trim(),'Content-Type':'application/json','Accept':'application/json'},
        body:JSON.stringify({sender:{name:'Ludo Baji',email:sender},to:[{email}],subject,htmlContent:htmlBody,textContent:textBody})
      });
      if(!r.ok){const t=await r.text().catch(()=> '');throw new Error('Brevo failed: '+(t||r.status));}
      return {sent:true,provider:'brevo'};
    }catch(e){lastErr=e;console.error('Brevo failed:',e.message);if(!devMode)throw e;}
  }

  // 2) Resend
  if(hasResend){
    try{
      const sender=String(process.env.RESEND_FROM||'beth.t@example.com').trim();
      const from=sender.includes('<')?sender:('Ludo Baji <'+sender+'>');
      const r=await fetch('https://api.resend.com/emails',{
        method:'POST',
        headers:{Authorization:'Bearer '+String(process.env.RESEND_API_KEY).trim(),'Content-Type':'application/json'},
        body:JSON.stringify({from,to:[email],subject,html:htmlBody,text:textBody})
      });
      if(!r.ok){const t=await r.text().catch(()=> '');throw new Error('Resend failed: '+(t||r.status));}
      return {sent:true,provider:'resend'};
    }catch(e){lastErr=e;console.error('Resend failed:',e.message);if(!devMode)throw e;}
  }

  // 3) SMTP — ONE quick attempt only (Render usually blocks; max ~4s)
  if(hasSmtp){
    try{
      let nodemailer;try{nodemailer=require('nodemailer')}catch{throw new Error('nodemailer missing');}
      const from=fromAddr.includes('<')?fromAddr:('"Ludo Baji" <'+(fromAddr||process.env.SMTP_USER)+'>');
      const mail={from,to:email,subject,text:textBody,html:htmlBody};
      const host=String(process.env.SMTP_HOST||'smtp.gmail.com').trim();
      const port=Number(process.env.SMTP_PORT||465);
      const secure=port===465||String(process.env.SMTP_SECURE||'').toLowerCase()==='true';
      const transporter=nodemailer.createTransport({
        host,port,secure,
        auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS},
        connectionTimeout:3000,greetingTimeout:3000,socketTimeout:4000,
        tls:{rejectUnauthorized:false}
      });
      await Promise.race([
        transporter.sendMail(mail),
        new Promise((_,rej)=>setTimeout(()=>rej(new Error('SMTP timeout')),4000))
      ]);
      return {sent:true,provider:'smtp'};
    }catch(e){
      lastErr=e;
      console.error('SMTP failed:',e.message);
      if(!devMode){
        throw new Error('Gmail SMTP কাজ করেনি (Render ব্লক করে)। RESEND_API_KEY + ডোমেইন অথবা BREVO_API_KEY দিন, অথবা টেস্টের জন্য OTP_DEV_MODE=true সেট করুন।');
      }
    }
  }

  // 4) Dev fallback
  if(devMode){
    console.log('[OTP DEV] '+email+': '+otp);
    return {sent:false,dev:true,otp,provider:'dev'};
  }

  throw new Error((lastErr&&lastErr.message)||'ইমেইল সেট নেই। OTP_DEV_MODE=true (টেস্ট) অথবা RESEND/BREVO API Key দিন।');
}
async function userLoginOtpEnabled(){const d=await read();return d.system?.user_login_otp!==false}
const MAIN_PAGE_DEFAULTS=[
  {id:'match',name:'Match',icon:'🎮',content:'Match system-এর content এখানে Auto Show হবে।'},
  {id:'deposit',name:'Deposit',icon:'💳',content:'Deposit system-এর content এখানে Auto Show হবে।'},
  {id:'statement',name:'My Statement',icon:'🏷️',content:'My Statement system-এর content এখানে Auto Show হবে।'},
  {id:'withdraw',name:'Withdraw',icon:'💰',content:'Withdraw system-এর content এখানে Auto Show হবে।'},
  {id:'support',name:'Support',icon:'✅',content:'Support system-এর content এখানে Auto Show হবে।'},
  {id:'mymatch',name:'My Match',icon:'🎮',content:'My Match system-এর content এখানে Auto Show হবে।'},
  {id:'notifications',name:'Notifications',icon:'🔔',content:'Notifications system-এর content এখানে Auto Show হবে।'},
  {id:'referral',name:'Referral',icon:'🔗',content:'Referral system-এর content এখানে Auto Show হবে।'},
  {id:'leaderboard',name:'Leaderboard',icon:'🏆',content:'Leaderboard system-এর content এখানে Auto Show হবে。'}
];
function normalizeMainOptions(d){
  const list=Array.isArray(d.mainOptions)?d.mainOptions.slice():[]; const byId=new Map(list.map(x=>[String(x.id),x])); let changed=false;
  MAIN_PAGE_DEFAULTS.forEach((def,i)=>{let x=byId.get(def.id); if(!x){x={...def,logo:'',visible:true};list.push(x);byId.set(def.id,x);changed=true} const before=JSON.stringify(x); x.visible=x.visible!==false; x.order=Number(x.order||i+1); x.short_name=x.short_name||''; x.button_text=x.button_text||''; x.action=x.action||'auto'; x.url=safeHttpUrl(x.url||''); x.background=x.background||'#092d21'; x.text_color=x.text_color||'#ffffff'; x.border_radius=Number.isFinite(Number(x.border_radius))?Number(x.border_radius):12; if(JSON.stringify(x)!==before)changed=true});
  d.mainOptions=list.sort((a,b)=>Number(a.order||999)-Number(b.order||999)); return {data:d,changed};
}

// ===== Real-time WebSocket for Ludo Matches =====
const matchWsClients=new Set();
function broadcastMatchesChanged(extra){
  const payload=JSON.stringify(Object.assign({type:'matches_changed',ts:Date.now()},extra||{}));
  for(const c of matchWsClients){
    try{if(c.readyState===1)c.send(payload)}catch{}
  }
}
function attachMatchWebSocket(server){
  // Minimal RFC6455 WebSocket server for /ws/matches (no external dependency)
  function wsAcceptKey(key){
    return crypto.createHash('sha1').update(String(key)+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  }
  function wsSend(socket, data){
    try{
      const payload=Buffer.from(String(data),'utf8');
      const len=payload.length;
      let header;
      if(len<126){header=Buffer.alloc(2);header[0]=0x81;header[1]=len}
      else if(len<65536){header=Buffer.alloc(4);header[0]=0x81;header[1]=126;header.writeUInt16BE(len,2)}
      else{header=Buffer.alloc(10);header[0]=0x81;header[1]=127;header.writeUInt32BE(0,2);header.writeUInt32BE(len,6)}
      socket.write(Buffer.concat([header,payload]));
    }catch{}
  }
  function wsClose(socket){
    try{socket.write(Buffer.from([0x88,0x00]));}catch{}
    try{socket.destroy()}catch{}
  }
  server.on('upgrade',(req,socket,head)=>{
    try{
      const u=url.parse(req.url||'',true);
      if(u.pathname!=='/ws/matches'){socket.destroy();return}
      const key=req.headers['sec-websocket-key'];
      if(!key){socket.destroy();return}
      const headers=[
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Accept: '+wsAcceptKey(key),
        '',''
      ].join('\r\n');
      socket.write(headers);
      const client={socket,readyState:1,send(data){wsSend(socket,data)},close(){wsClose(socket)}};
      matchWsClients.add(client);
      wsSend(socket,JSON.stringify({type:'connected',ts:Date.now()}));
      let buf=Buffer.alloc(0);
      socket.on('data',(chunk)=>{
        try{
          buf=Buffer.concat([buf,chunk]);
          while(buf.length>=2){
            const b0=buf[0],b1=buf[1];
            const opcode=b0&0x0f;
            const masked=(b1&0x80)!==0;
            let payloadLen=b1&0x7f, offset=2;
            if(payloadLen===126){if(buf.length<4)return;payloadLen=buf.readUInt16BE(2);offset=4}
            else if(payloadLen===127){if(buf.length<10)return;payloadLen=Number(buf.readBigUInt64BE(2));offset=10}
            const maskLen=masked?4:0;
            if(buf.length<offset+maskLen+payloadLen)return;
            let payload=buf.slice(offset+maskLen,offset+maskLen+payloadLen);
            if(masked){
              const mask=buf.slice(offset,offset+4);
              payload=Buffer.from(payload.map((b,i)=>b^mask[i%4]));
            }
            buf=buf.slice(offset+maskLen+payloadLen);
            if(opcode===0x8){matchWsClients.delete(client);client.readyState=3;wsClose(socket);return}
            if(opcode===0x9){ // ping -> pong
              const pong=Buffer.alloc(2+payload.length);pong[0]=0x8a;pong[1]=payload.length;payload.copy(pong,2);socket.write(pong);continue}
            if(opcode===0x1){
              try{
                const msg=JSON.parse(payload.toString('utf8')||'{}');
                if(msg&&msg.type==='ping')wsSend(socket,JSON.stringify({type:'pong',ts:Date.now()}));
              }catch{}
            }
          }
        }catch{matchWsClients.delete(client)}
      });
      socket.on('close',()=>{matchWsClients.delete(client);client.readyState=3});
      socket.on('error',()=>{matchWsClients.delete(client);client.readyState=3});
    }catch(e){try{socket.destroy()}catch{}}
  });
  console.log('Native WebSocket /ws/matches ready for real-time match updates');
}

const server=http.createServer(async(req,res)=>{try{
 const u=url.parse(req.url,true),p=u.pathname;
 if(req.method==='OPTIONS'){const h={};if(CORS_ORIGIN){h['Access-Control-Allow-Origin']=CORS_ORIGIN;h['Access-Control-Allow-Headers']='Content-Type, Authorization';h['Access-Control-Allow-Methods']='GET,POST,PUT,DELETE,OPTIONS';h['Vary']='Origin'}res.writeHead(204,h);return res.end()}
 if(p.startsWith('/api/')&&p!=='/api/site'&&!p.startsWith('/api/admin')){const md=await read();if(md.system?.maintenance?.enabled===true)return send(res,503,{ok:false,error:'Ludo Baji Website & App Update চলছে। এখন প্রবেশ করা যাবে না।'});}
 if(req.method==='POST'&&p==='/api/login'){const key=clientKey(req);if(loginBlocked(key))return send(res,429,{ok:false,error:'অনেকবার ভুল Login চেষ্টা হয়েছে। 15 মিনিট পরে আবার চেষ্টা করুন'});const x=await body(req);const username=String(x.username||''),password=String(x.password||'');if(username.length>100||password.length>200)return send(res,400,{ok:false,error:'Invalid login data'});if(passwordMatches(username,ADMIN_USERNAME)&&passwordMatches(password,ADMIN_PASSWORD)){clearLoginFailures(key);return send(res,200,{ok:true,token:issueAdminToken(),expires_in:Math.floor(ADMIN_TOKEN_TTL_MS/1000),role:ADMIN_ROLE})}recordLoginFailure(key);return send(res,401,{ok:false,error:'Username অথবা Password ভুল'})}
 if(req.method==='POST'&&p==='/api/admin/logout'){const x=await auth(req,res);if(!x)return;revokeAdminToken(req);return send(res,200,{ok:true})}
 if(req.method==='POST'&&p==='/api/auth/request-otp'){
   if(!(await userLoginOtpEnabled()))return send(res,403,{ok:false,error:'User Login / OTP System is currently OFF. Admin Panel থেকে ON করুন।'});
   const x=await body(req),email=normalizeEmail(x.email);if(!email)return send(res,400,{ok:false,error:'সঠিক Email/Gmail address দিন'});const otpKey=clientKey(req)+'|'+email;if(otpBlocked(otpKey))return send(res,429,{ok:false,error:'এই Email-এর জন্য অনেকবার OTP চাওয়া হয়েছে। ১ মিনিট পরে আবার চেষ্টা করুন'});
   let user=await db.findUserByEmail(email);if(user&&user.status!=='active')return send(res,403,{ok:false,error:'এই অ্যাকাউন্টটি বন্ধ আছে'});
   const now=Date.now();if(user?.otp_sent_at&&now-new Date(user.otp_sent_at).getTime()<OTP_COOLDOWN_MS)return send(res,429,{ok:false,error:'আবার OTP চাইতে একটু অপেক্ষা করুন ('+Math.ceil((OTP_COOLDOWN_MS-(now-new Date(user.otp_sent_at).getTime()))/1000)+' সেকেন্ড)',retry_after:Math.ceil((OTP_COOLDOWN_MS-(now-new Date(user.otp_sent_at).getTime()))/1000)});
   if(!acquireOtpLock(email))return send(res,429,{ok:false,error:'OTP ইতিমধ্যে পাঠানো হচ্ছে। একটু অপেক্ষা করুন'});
   recordOtpRequest(otpKey);
   if(!user)user=await db.createUserByEmail(email);
   try{
     // 1) Supabase Email OTP (সবচেয়ে নির্ভরযোগ্য)
     if(supabaseConfigured()){
       await supabaseSendOtp(email);
       const sent=new Date().toISOString();
       // local placeholder so verify can also try local fallback; real code comes from Supabase email
       await db.setUserOtpByEmail(email,otpHash(email,'supabase'),new Date(Date.now()+OTP_TTL_MS).toISOString(),sent);
       releaseOtpLock(email);return send(res,200,{ok:true,message:'OTP sent successfully',email:maskEmail(email),expires_in:Math.floor(OTP_TTL_MS/1000),provider:'supabase'});
     }
     const otp=makeOtp(),expires=new Date(now+OTP_TTL_MS).toISOString(),sent=new Date(now).toISOString();
     await db.setUserOtpByEmail(email,otpHash(email,otp),expires,sent);
     // Always await email send so SMTP/Gmail failures are returned to the user (no silent false success)
     const result=await sendOtpEmail(email,otp);
     releaseOtpLock(email);return send(res,200,{ok:true,message:result.dev?'Test OTP generated':'OTP sent successfully',email:maskEmail(email),expires_in:Math.floor(OTP_TTL_MS/1000),provider:result.provider||(result.dev?'dev':'smtp'),...(result.dev?{dev_otp:otp}:{})});
   }catch(e){releaseOtpLock(email);return send(res,503,{ok:false,error:e.message||'OTP পাঠানো যায়নি'})}finally{/* lock auto-expires */} 
 }
 if(req.method==='POST'&&p==='/api/auth/verify-otp'){
   if(!(await userLoginOtpEnabled()))return send(res,403,{ok:false,error:'User Login / OTP System is currently OFF. Admin Panel থেকে ON করুন।'});
   const x=await body(req),email=normalizeEmail(x.email),otp=String(x.otp||'').trim();if(!email||!/^[0-9]{6}$/.test(otp))return send(res,400,{ok:false,error:'Email এবং ৬ সংখ্যার OTP দিন'});
   let user=await db.findUserByEmail(email);if(!user)return send(res,404,{ok:false,error:'অ্যাকাউন্ট পাওয়া যায়নি'});if(user.status!=='active')return send(res,403,{ok:false,error:'এই অ্যাকাউন্টটি বন্ধ আছে'});
   // Supabase verify first when configured
   if(supabaseConfigured()){
     try{
       await supabaseVerifyOtp(email,otp);
       await db.clearUserOtpByEmail(email);
       const fresh=await db.getUserById(user.id);await db.ensureUserWallet(fresh.id);
       const userToken=signToken({typ:'user',id:String(fresh.id),e:Date.now()+30*86400000},USER_SECRET);
       return send(res,200,{ok:true,token:userToken,user:{id:fresh.id,user_code:fresh.user_code,email:fresh.email||email,phone:fresh.phone||null,name:fresh.name||'',status:fresh.status}});
     }catch(e){
       // fall through to local OTP if was sent via SMTP/dev
       if(!user.otp_hash||user.otp_hash===otpHash(email,'supabase')){
         return send(res,401,{ok:false,error:e.message||'OTP সঠিক নয়'});
       }
     }
   }
   if(!user.otp_hash||!user.otp_expires_at)return send(res,400,{ok:false,error:'OTP-এর মেয়াদ শেষ। নতুন OTP নিন'});
   if(Date.now()>new Date(user.otp_expires_at).getTime()){await db.clearUserOtpByEmail(email);return send(res,400,{ok:false,error:'OTP-এর মেয়াদ শেষ। নতুন OTP নিন'});}
   if(Number(user.otp_attempts||0)>=OTP_MAX_ATTEMPTS){await db.clearUserOtpByEmail(email);return send(res,429,{ok:false,error:'অনেকবার ভুল OTP দেওয়া হয়েছে। নতুন OTP নিন'});}
   if(otpHash(email,otp)!==user.otp_hash){await db.updateOtpAttemptsByEmail(email,Number(user.otp_attempts||0)+1);return send(res,401,{ok:false,error:'OTP সঠিক নয়'});}
   await db.clearUserOtpByEmail(email);const fresh=await db.getUserById(user.id);await db.ensureUserWallet(fresh.id);const userToken=signToken({typ:'user',id:String(fresh.id),e:Date.now()+30*86400000},USER_SECRET);return send(res,200,{ok:true,token:userToken,user:{id:fresh.id,user_code:fresh.user_code,email:fresh.email||email,phone:fresh.phone||null,name:fresh.name||'',status:fresh.status}});
 }
 if(req.method==='GET'&&p==='/api/auth/me'){const x=await userAuth(req,res);if(!x)return;const user=await db.getUserById(x.id);if(!user)return send(res,404,{ok:false,error:'User not found'});return send(res,200,{ok:true,user:{id:user.id,user_code:user.user_code,email:user.email||'',phone:user.phone||null,name:user.name||'',status:user.status}})}
 if(req.method==='GET'&&p==='/api/user/push/public-key'){return send(res,200,{ok:true,configured:pushConfigured(),public_key:pushConfigured()?VAPID_PUBLIC_KEY:''});}
 if(req.method==='POST'&&p==='/api/user/push/subscribe'){const x=await userAuth(req,res);if(!x)return;try{const b=await body(req);if(!pushConfigured())return send(res,503,{ok:false,error:'Phone notification service is not configured yet'});await pushSubscribe(x.id,b.subscription);return send(res,200,{ok:true})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='POST'&&p==='/api/user/push/unsubscribe'){const x=await userAuth(req,res);if(!x)return;try{const b=await body(req);await pushUnsubscribe(x.id,String(b.endpoint||''));return send(res,200,{ok:true})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/user/dashboard'){const x=await userAuth(req,res);if(!x)return;const user=await db.getUserById(x.id);if(!user)return send(res,404,{ok:false,error:'User not found'});const dashboard=await db.getUserDashboard(x.id);return send(res,200,{ok:true,user:{id:user.id,user_code:user.user_code,email:user.email||'',phone:user.phone||null,name:user.name||'',status:user.status},dashboard})}
 if(req.method==='PUT'&&p==='/api/auth/profile'){const x=await userAuth(req,res);if(!x)return;const b=await body(req),name=String(b.name||'').trim();if(name.length>60)return send(res,400,{ok:false,error:'Name too long'});const user=await db.updateUserName(x.id,name);return send(res,200,{ok:true,user:{id:user.id,user_code:user.user_code,email:user.email||'',phone:user.phone||null,name:user.name||'',status:user.status}})}
 if(req.method==='GET'&&p==='/api/deposit/info'){
   const d=await read(); const methods=(d.paymentMethods||[]).filter(m=>m.enabled!==false).sort((a,b)=>Number(a.order||999)-Number(b.order||999)); return send(res,200,{ok:true,methods});
 }
 if(req.method==='GET'&&p==='/api/user/deposits'){
   const x=await userAuth(req,res);if(!x)return;
   return send(res,200,{ok:true,deposits:await db.listUserDeposits(x.id)});
 }
 if(req.method==='POST'&&p==='/api/user/deposits'){
   const x=await userAuth(req,res);if(!x)return;
   const b=await body(req),method=String(b.method||'').toLowerCase(),amount=Number(b.amount),transactionId=String(b.transaction_id||'').trim(),screenshot=String(b.screenshot||'');
   const pd=(await read()).paymentMethods||[], pm=pd.find(m=>m.id===method&&m.enabled!==false);
   if(!pm)return send(res,400,{ok:false,error:'এই Payment Method বর্তমানে বন্ধ'}); if(!Number.isFinite(amount)||amount<Number(pm.min_deposit||0)||amount>Number(pm.max_deposit||1000000))return send(res,400,{ok:false,error:`Deposit amount ৳${pm.min_deposit||0} থেকে ৳${pm.max_deposit||1000000} এর মধ্যে দিন`});
   if(!/^[A-Za-z0-9._-]{3,100}$/.test(transactionId))return send(res,400,{ok:false,error:'সঠিক Transaction ID দিন'});
   if(!/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(screenshot))return send(res,400,{ok:false,error:'Payment screenshot upload করুন'});
   const comma=screenshot.indexOf(','),bytes=comma>0?Buffer.byteLength(screenshot.slice(comma+1),'base64'):0;if(bytes>8*1024*1024)return send(res,413,{ok:false,error:'Screenshot সর্বোচ্চ 8MB হতে পারবে'});
   try{const d=await db.createDeposit(x.id,method,amount,transactionId,screenshot);return send(res,201,{ok:true,message:'Deposit request জমা হয়েছে। Admin approval-এর অপেক্ষায় আছে।',deposit:{id:d.id,method:d.method,amount:Number(d.amount),transaction_id:d.transaction_id,status:d.status,created_at:d.created_at}})}catch(e){return send(res,400,{ok:false,error:e.message||'Deposit failed'})}
 }
 if(req.method==='GET'&&p==='/api/user/transactions'){
   const x=await userAuth(req,res);if(!x)return;
   return send(res,200,{ok:true,transactions:await db.listUserTransactions(x.id)});
 }
 if(req.method==='GET'&&p==='/api/user/withdrawals'){
   const x=await userAuth(req,res);if(!x)return;
   return send(res,200,{ok:true,withdrawals:await db.listUserWithdrawals(x.id)});
 }
 function defaultWithdrawConfig(){
   return {
     notice:'প্রিয় User, আপনি সর্বনিম্ন ৳100 থেকে সর্বোচ্চ ৳10,000 টাকা Withdraw করতে পারবেন। ধন্যবাদ।',
     min_amount:100,
     max_amount:10000,
     methods:[
       {id:'bkash',name:'bKash',logo:'💗',enabled:true,order:1},
       {id:'nagad',name:'Nagad',logo:'🟠',enabled:true,order:2},
       {id:'rocket',name:'Rocket',logo:'🚀',enabled:true,order:3},
       {id:'upay',name:'Upay',logo:'🟣',enabled:true,order:4}
     ]
   };
 }
 function getWithdrawConfig(d){
   const base=defaultWithdrawConfig();
   const cfg=(d&&d.withdrawConfig&&typeof d.withdrawConfig==='object')?d.withdrawConfig:{};
   const methods=Array.isArray(cfg.methods)&&cfg.methods.length?cfg.methods:base.methods;
   return {
     notice:String(cfg.notice!=null?cfg.notice:base.notice),
     min_amount:Math.max(1,Number(cfg.min_amount!=null?cfg.min_amount:base.min_amount)||100),
     max_amount:Math.max(1,Number(cfg.max_amount!=null?cfg.max_amount:base.max_amount)||10000),
     methods:methods.map((m,i)=>({
       id:String(m.id||'').toLowerCase(),
       name:String(m.name||m.id||'Method'),
       logo:String(m.logo||''),
       enabled:m.enabled!==false,
       order:Number(m.order||i+1)
     })).filter(m=>['bkash','nagad','rocket','upay'].includes(m.id))
   };
 }
 if(req.method==='GET'&&p==='/api/withdraw/config'){
   const d=await read();return send(res,200,{ok:true,config:getWithdrawConfig(d)});
 }
 if(req.method==='GET'&&p==='/api/admin/withdraw-config'){
   const a=await auth(req,res);if(!a)return;const d=await read();return send(res,200,{ok:true,config:getWithdrawConfig(d)});
 }
 if(req.method==='PUT'&&p==='/api/admin/withdraw-config'){
   const a=await auth(req,res);if(!a)return;const b=await body(req),d=await read();
   const cur=getWithdrawConfig(d);
   const next={
     notice:String(b.notice!=null?b.notice:cur.notice).slice(0,500),
     min_amount:Math.max(1,Number(b.min_amount!=null?b.min_amount:cur.min_amount)||100),
     max_amount:Math.max(1,Number(b.max_amount!=null?b.max_amount:cur.max_amount)||10000),
     methods:Array.isArray(b.methods)?b.methods:cur.methods
   };
   if(next.max_amount<next.min_amount)next.max_amount=next.min_amount;
   d.withdrawConfig=getWithdrawConfig({withdrawConfig:next});
   await write(d);await addAudit('withdraw_config_update','withdrawConfig',d.withdrawConfig);
   return send(res,200,{ok:true,config:d.withdrawConfig,message:'Withdraw settings saved'});
 }
 if(req.method==='POST'&&p==='/api/user/withdrawals'){
   const x=await userAuth(req,res);if(!x)return;
   const b=await body(req),method=String(b.method||'').toLowerCase(),accountNumber=String(b.account_number||'').trim(),accountName=String(b.account_name||'').trim(),amount=Number(b.amount),balanceType=String(b.balance_type||'winning').toLowerCase();
   const dcfg=await read();const cfg=getWithdrawConfig(dcfg);
   const minWithdrawal=cfg.min_amount,maxWithdrawal=cfg.max_amount;
   const enabledIds=cfg.methods.filter(m=>m.enabled).map(m=>m.id);
   if(!enabledIds.includes(method))return send(res,400,{ok:false,error:'এই Withdraw method এখন বন্ধ আছে'});
   if(!['gaming','winning'].includes(balanceType))return send(res,400,{ok:false,error:'সঠিক Balance নির্বাচন করুন'});
   if(!accountName||accountName.length<2)return send(res,400,{ok:false,error:'Account Holder Name দিন'});
   if(!/^01\d{9}$/.test(accountNumber)&&!/^(?:\+880|880)1\d{9}$/.test(accountNumber))return send(res,400,{ok:false,error:'সঠিক Mobile Number দিন (01XXXXXXXXX)'});
   if(!Number.isFinite(amount)||amount<minWithdrawal||amount>maxWithdrawal)return send(res,400,{ok:false,error:`Withdrawal amount ৳${minWithdrawal} থেকে ৳${maxWithdrawal} এর মধ্যে হতে হবে`});
   try{const d=await db.createWithdrawal(x.id,method,accountNumber,amount,balanceType,accountName);return send(res,201,{ok:true,message:'Withdrawal request জমা হয়েছে। Admin approval-এর অপেক্ষায় আছে।',withdrawal:{id:d.id,method:d.method,account_number:d.account_number,account_name:d.account_name||accountName,amount:Number(d.amount),balance_type:d.balance_type,status:d.status,created_at:d.created_at}})}catch(e){return send(res,400,{ok:false,error:e.message||'Withdrawal failed'})}
 }
 
 // ===== Steps 3-35 APIs =====
 if(req.method==='GET'&&p==='/api/payment-methods'){const d=await read();return send(res,200,{ok:true,methods:(d.paymentMethods||[]).filter(x=>x.enabled)});}
 if(req.method==='GET'&&p==='/api/matches'){let all=await db.listFeatureMatches('all');all=all.filter(m=>!['cancelled'].includes(String(m.status||'').toLowerCase()));all=all.slice().sort((a,b)=>String(b.created_at||'').localeCompare(String(a.created_at||'')));const matches=all.map(m=>({id:m.id,match_code:m.match_code,title:m.title,entry_fee:m.entry_fee,winning_amount:m.winning_amount,max_players:2,status:m.status,scheduled_at:m.scheduled_at,rules:m.rules,players:(m.players||[]).map(p=>({slot:p.slot,status:p.status})),created_at:m.created_at,updated_at:m.updated_at,room_id:'',room_password:''}));return send(res,200,{ok:true,matches});}
 if(req.method==='GET'&&p==='/api/user/matches'){const x=await userAuth(req,res);if(!x)return;let all=await db.listFeatureMatches(String(u.query.status||'all'));all=all.filter(m=>String(m.status||'').toLowerCase()!=='cancelled');all=all.slice().sort((a,b)=>String(b.created_at||'').localeCompare(String(a.created_at||'')));const matches=all.map(m=>{const joined=Array.isArray(m.players)&&m.players.some(a=>String(a.user_id)===String(x.id));const ready=Array.isArray(m.players)&&m.players.length>=2;return (joined&&ready)?m:{...m,room_id:'',room_password:''}});return send(res,200,{ok:true,matches});}
 if(req.method==='GET'&&p==='/api/user/matches/mine'){const x=await userAuth(req,res);if(!x)return;const matches=await db.listUserFeatureMatches(x.id);const safe=matches.map(m=>{const ready=Array.isArray(m.players)&&m.players.length>=2;return ready?m:{...m,room_id:'',room_password:''}});return send(res,200,{ok:true,matches:safe});}
 if(req.method==='GET'&&p.startsWith('/api/user/matches/')&&p.split('/').length===5){const x=await userAuth(req,res);if(!x)return;const m=await db.getFeatureMatch(decodeURIComponent(p.split('/')[4]));if(!m)return send(res,404,{ok:false,error:'Match not found'});const joined=Array.isArray(m.players)&&m.players.some(a=>String(a.user_id)===String(x.id));if(!joined)return send(res,403,{ok:false,error:'You have not joined this match'});if(m.players.length<2)return send(res,200,{ok:true,match:{...m,room_id:'',room_password:''}});return send(res,200,{ok:true,match:m});}
 if(req.method==='POST'&&p.startsWith('/api/user/matches/')&&p.endsWith('/join')){const x=await userAuth(req,res);if(!x)return;const id=decodeURIComponent(p.split('/')[4]);try{const r=await db.joinFeatureMatch(id,x.id);const m=r.match||{};if(Array.isArray(m.players)&&m.players.length>=2&&m.room_id){const ids=m.players.map(a=>String(a.user_id));for(const uid of ids){await db.notifyUser(uid,'Ludo Match Room Code',''+m.title+' match-এর ২ জন player পূর্ণ হয়েছে। Room Code: '+m.room_id+' — Ludo King-এ join করুন।')}await sendPushToUsers(ids,'Ludo Match Room Code',m.title+' match-এর ২ জন player পূর্ণ হয়েছে। Room Code: '+m.room_id+' — Ludo King-এ join করুন।',{match_id:m.id,room_code:m.room_id});}broadcastMatchesChanged({action:'join',match_id:id,players:Array.isArray(m.players)?m.players.length:0});return send(res,200,{ok:true,message:'Match joined successfully',...r});}catch(e){return send(res,400,{ok:false,error:e.message})}}

 if(req.method==='POST'&&p.startsWith('/api/user/matches/')&&p.endsWith('/result')){
   const x=await userAuth(req,res);if(!x)return;
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req);
   try{
     const screenshot=String(b.screenshot||'');
     const comma=screenshot.indexOf(',');
     const bytes=comma>0?Buffer.byteLength(screenshot.slice(comma+1),'base64'):0;
     if(bytes>8*1024*1024)return send(res,413,{ok:false,error:'Screenshot সর্বোচ্চ 8MB হতে পারবে'});
     const r=await db.submitFeatureResult(id,x.id,screenshot);
     broadcastMatchesChanged({action:'result_submit',match_id:id});
     return send(res,201,{ok:true,message:'Winner screenshot জমা হয়েছে। Admin verification-এর অপেক্ষায় আছে।',submission:{id:r.id,status:r.status,submitted_at:r.submitted_at}});
   }catch(e){return send(res,400,{ok:false,error:e.message})}
 }

 if(req.method==='GET'&&p==='/api/user/notifications'){const x=await userAuth(req,res);if(!x)return;return send(res,200,{ok:true,notifications:await db.listNotifications(x.id)});}
 if(req.method==='POST'&&p==='/api/user/notifications/read'){const x=await userAuth(req,res);if(!x)return;const b=await body(req);await db.markNotificationsRead(x.id,String(b.id||'all'));return send(res,200,{ok:true});}
 if(req.method==='GET'&&p==='/api/user/support'){const x=await userAuth(req,res);if(!x)return;return send(res,200,{ok:true,messages:await db.supportList(x.id)});}
 if(req.method==='POST'&&p==='/api/user/support'){const x=await userAuth(req,res);if(!x)return;const b=await body(req);try{return send(res,200,{ok:true,message:await db.supportSend(x.id,'user',b.message)})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/user/referral'){const x=await userAuth(req,res);if(!x)return;const user=await db.getUserById(x.id),d=await read(),cfg=d.referral||{};return send(res,200,{ok:true,code:(cfg.code_prefix||'LB')+String(user.user_code||user.id).replace(/\W/g,''),bonus:Number(cfg.bonus||0),enabled:cfg.enabled!==false});}
 if(p.startsWith('/api/admin')){const x=await auth(req,res);if(!x)return;}
 if(req.method==='GET'&&p==='/api/admin/users'){const q=String(u.query.q||'');return send(res,200,{ok:true,users:await db.listUsers(500,q)});}
 if(req.method==='POST'&&p.startsWith('/api/admin/users/')&&p.endsWith('/status')){const id=decodeURIComponent(p.split('/')[4]),b=await body(req);try{const user=await db.setUserStatus(id,b.status);await addAudit('user_status',id,b.status);return send(res,200,{ok:true,user});}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='POST'&&p.startsWith('/api/admin/users/')&&p.endsWith('/balance')){const id=decodeURIComponent(p.split('/')[4]),b=await body(req);try{const r=await db.adjustBalance(id,b.balance_type,b.amount,b.note);await addAudit('balance_adjustment',id,b);return send(res,200,{ok:true,result:r});}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/admin/payment-methods'){const d=await read();return send(res,200,{ok:true,methods:d.paymentMethods||[]});}
 if(req.method==='POST'&&p==='/api/admin/payment-methods'){const b=await body(req),d=await read();d.paymentMethods=Array.isArray(d.paymentMethods)?d.paymentMethods:[];const id=String(b.id||('PAY-'+Date.now().toString(36)));if(d.paymentMethods.some(x=>String(x.id)===id))return send(res,409,{ok:false,error:'Payment Method ID already exists'});const m={id,provider:String(b.provider||'Payment'),account_type:String(b.account_type||'Personal'),name:String(b.name||'Deposit Method'),number:String(b.number||''),account_name:String(b.account_name||''),logo:String(b.logo||''),enabled:b.enabled!==false,order:Number(b.order||d.paymentMethods.length+1),min_deposit:Number(b.min_deposit||0),max_deposit:Number(b.max_deposit||1000000),instructions:String(b.instructions||'')};if(!m.name||!m.number)return send(res,400,{ok:false,error:'Method Name ও Number required'});d.paymentMethods.push(m);await write(d);await addAudit('payment_method_create',id,m);return send(res,201,{ok:true,method:m});}
 if(req.method==='PUT'&&p.startsWith('/api/admin/payment-methods/')){const id=decodeURIComponent(p.split('/').pop()),b=await body(req),d=await read();d.paymentMethods=Array.isArray(d.paymentMethods)?d.paymentMethods:[];let m=d.paymentMethods.find(x=>x.id===id);if(!m){m={id,name:id};d.paymentMethods.push(m)}Object.assign(m,{provider:String(b.provider??m.provider??(String(id).toLowerCase().includes('nagad')?'Nagad':'Payment')),account_type:String(b.account_type??m.account_type??(String(m.name||'').match(/merchant/i)?'Merchant':String(m.name||'').match(/agent/i)?'Agent':String(m.name||'').match(/debit/i)?'Debit':'Personal')),name:String(b.name??m.name),number:String(b.number??m.number),account_name:String((b.account_name??m.account_name)??''),logo:String((b.logo??m.logo)??''),enabled:b.enabled!==undefined?!!b.enabled:m.enabled!==false,min_deposit:Number((b.min_deposit??m.min_deposit)??0),max_deposit:Number((b.max_deposit??m.max_deposit)??1000000),instructions:String((b.instructions??m.instructions)??'')});await write(d);await addAudit('payment_method_update',id,m);return send(res,200,{ok:true,method:m});}
 if(req.method==='DELETE'&&p.startsWith('/api/admin/payment-methods/')){const id=decodeURIComponent(p.split('/').pop()),d=await read();d.paymentMethods=Array.isArray(d.paymentMethods)?d.paymentMethods:[];const before=d.paymentMethods.length;d.paymentMethods=d.paymentMethods.filter(x=>String(x.id)!==id);if(d.paymentMethods.length===before)return send(res,404,{ok:false,error:'Payment Method not found'});await write(d);await addAudit('payment_method_delete',id,{});return send(res,200,{ok:true});}
 if(req.method==='POST'&&p==='/api/admin/matches'){const b=await body(req);try{const m=await db.createFeatureMatch(b);await addAudit('match_create',m.id,m.title);broadcastMatchesChanged({action:'create',match_id:m.id});return send(res,201,{ok:true,match:m});}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/admin/matches'){const matches=await db.listFeatureMatches(String(u.query.status||'all'));matches.forEach(m=>m.status=publicMatchStatus(m));return send(res,200,{ok:true,matches});}
 if(req.method==='PUT'&&p.startsWith('/api/admin/matches/')){const id=decodeURIComponent(p.split('/').pop()),b=await body(req);try{const m=await db.updateFeatureMatch(id,b);broadcastMatchesChanged({action:'update',match_id:id,status:m&&m.status});return send(res,200,{ok:true,match:m})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='DELETE'&&p.startsWith('/api/admin/matches/')){const id=decodeURIComponent(p.split('/').pop()),d=await read();d.matches=(d.matches||[]).filter(m=>String(m.id)!==String(id));await write(d);broadcastMatchesChanged({action:'delete',match_id:id});return send(res,200,{ok:true});}
 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/cancel')){const id=decodeURIComponent(p.split('/')[4]);const m=await db.getFeatureMatch(id);if(!m)return send(res,404,{ok:false,error:'Match not found'});if(m.status==='cancelled')return send(res,400,{ok:false,error:'Already cancelled'});for(const pl of (m.players||[])){try{await db.adjustBalance(pl.user_id,'gaming',Number(m.entry_fee),'Match cancelled refund '+m.match_code)}catch{}}const d=await read();const mm=(d.matches||[]).find(a=>String(a.id)===String(id));if(mm){mm.status='cancelled';mm.updated_at=new Date().toISOString(); try{db.debitAdminEntriesOnCancel(d,mm)}catch(e){console.error('debitAdminEntriesOnCancel',e.message)} }await write(d);await addAudit('match_cancel',id,m.match_code);broadcastMatchesChanged({action:'cancel',match_id:id});return send(res,200,{ok:true,match:mm});}
 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/room')){const id=decodeURIComponent(p.split('/')[4]),b=await body(req);try{const m=await db.setFeatureRoom(id,b.room_id,b.room_password);broadcastMatchesChanged({action:'room',match_id:id});return send(res,200,{ok:true,match:m})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/winner')){const id=decodeURIComponent(p.split('/')[4]),b=await body(req);try{return send(res,200,{ok:true,match:await db.setFeatureWinner(id,b.user_id)})}catch(e){return send(res,400,{ok:false,error:e.message})}}

 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/result/approve')){
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req);
   try{const m=await db.approveFeatureResult(id,String(b.user_id||''));await addAudit('match_result_approve',id,b.user_id);broadcastMatchesChanged({action:'result_approve',match_id:id});return send(res,200,{ok:true,match:m})}
   catch(e){return send(res,400,{ok:false,error:e.message})}
 }
 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/result/reject')){
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req);
   try{const m=await db.rejectFeatureResult(id,String(b.user_id||''),String(b.note||''));await addAudit('match_result_reject',id,b.user_id);broadcastMatchesChanged({action:'result_reject',match_id:id});return send(res,200,{ok:true,match:m})}
   catch(e){return send(res,400,{ok:false,error:e.message})}
 }

 if(req.method==='POST'&&p.startsWith('/api/admin/matches/')&&p.endsWith('/prize')){const id=decodeURIComponent(p.split('/')[4]);try{return send(res,200,{ok:true,match:await db.approveFeaturePrize(id)})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/admin/match-players'){const id=String(u.query.match_id||'');const m=await db.getFeatureMatch(id);if(!m)return send(res,404,{ok:false,error:'Match not found'});const users=await db.listUsers(500);const map=new Map(users.map(a=>[String(a.id),a]));return send(res,200,{ok:true,players:(m.players||[]).map(p=>({...p,user:map.get(String(p.user_id))||null}))});}
 if(req.method==='GET'&&p==='/api/admin/users'){
   const q=String(u.query.q||'').trim(),status=String(u.query.status||'all');
   let users=await db.listUsers(1000,q); if(['active','blocked'].includes(status))users=users.filter(x=>x.status===status);
   return send(res,200,{ok:true,users});
  }
  if(req.method==='GET'&&/^\/api\/admin\/users\/[^/]+$/.test(p)){
   const id=decodeURIComponent(p.split('/').pop());const detail=await db.getUserAdminDetail(id,300);if(!detail)return send(res,404,{ok:false,error:'User not found'});return send(res,200,{ok:true,...detail});
  }
  if(req.method==='POST'&&/^\/api\/admin\/users\/[^/]+\/status$/.test(p)){
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req),status=String(b.status||'').toLowerCase();if(!['active','blocked'].includes(status))return send(res,400,{ok:false,error:'Invalid user status'});
   try{const user=await db.setUserStatus(id,status);await addAudit(status==='blocked'?'user_block':'user_unblock',id,{user_code:user.user_code,admin:ADMIN_USERNAME});return send(res,200,{ok:true,user})}catch(e){return send(res,400,{ok:false,error:e.message})}
  }
  if(req.method==='POST'&&/^\/api\/admin\/users\/[^/]+\/balance$/.test(p)){
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req),balanceType=String(b.balance_type||''),amount=Number(b.amount),note=String(b.note||'Admin balance adjustment').trim().slice(0,300);
   if(!['gaming','winning'].includes(balanceType)||!Number.isFinite(amount)||amount===0)return send(res,400,{ok:false,error:'Valid balance type and non-zero amount required'});
   try{const result=await db.adjustBalance(id,balanceType,amount,note);await addAudit('user_balance_adjust',id,{balance_type:balanceType,change:Number(amount.toFixed(2)),before:result.before,after:result.after,note,admin:ADMIN_USERNAME});return send(res,200,{ok:true,result})}catch(e){return send(res,400,{ok:false,error:e.message})}
  }
  if(req.method==='POST'&&/^\/api\/admin\/users\/[^/]+\/notify$/.test(p)){
   const id=decodeURIComponent(p.split('/')[4]),b=await body(req),title=String(b.title||'Admin Notification').trim(),message=String(b.message||'').trim();if(!title||!message||title.length>120||message.length>2000)return send(res,400,{ok:false,error:'Title and message required'});
   try{const user=await db.getUserById(id);if(!user)return send(res,404,{ok:false,error:'User not found'});const notification=await db.notifyUser(id,title,message);await addAudit('user_notification',id,{user_code:user.user_code,title,admin:ADMIN_USERNAME});return send(res,201,{ok:true,notification})}catch(e){return send(res,400,{ok:false,error:e.message})}
  }
 if(req.method==='GET'&&p==='/api/admin/support'){return send(res,200,{ok:true,messages:await db.adminSupport()});}
 if(req.method==='POST'&&p==='/api/admin/support'){const b=await body(req);try{return send(res,200,{ok:true,message:await db.supportSend(b.user_id,'admin',b.message)})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/admin/finance'){try{const fin=await db.getAdminFinance();return send(res,200,{ok:true,finance:fin})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='POST'&&p==='/api/admin/finance/withdraw'){const b=await body(req);try{const row=await db.adminWithdraw(b.method,b.account_number,b.amount,b.note);await addAudit('admin_withdraw',row.id,{method:row.method,amount:row.amount,account:row.account_number});return send(res,201,{ok:true,withdrawal:row,message:'Admin Withdraw সম্পন্ন হয়েছে। Admin Account থেকে কেটে নেওয়া হয়েছে।'})}catch(e){return send(res,400,{ok:false,error:e.message})}}
 if(req.method==='GET'&&p==='/api/admin/reports'){const d=await read(),tx=await db.listAdminTransactions(10000),users=await db.listUsers(10000);const fin=await db.getAdminFinance();return send(res,200,{ok:true,summary:{users:users.length,active_users:users.filter(x=>x.status==='active').length,blocked_users:users.filter(x=>x.status==='blocked').length,deposit:Number(tx.filter(x=>x.type==='deposit'&&x.status==='completed').reduce((a,x)=>a+Number(x.amount||0),0)),withdrawal:Number(tx.filter(x=>x.type==='withdrawal'&&x.status==='completed').reduce((a,x)=>a+Number(x.amount||0),0)),matches:(d.matches||[]).length,admin_commission:Number(fin.commission_balance||0),total_commission_earned:Number(fin.total_commission_earned||0)},finance:fin,transactions:tx});}
 if(req.method==='GET'&&p==='/api/admin/audit-log'){const d=await read();return send(res,200,{ok:true,logs:d.auditLogs||[]});}
 if(req.method==='GET'&&p==='/api/admin/roles'){const d=await read();return send(res,200,{ok:true,roles:d.adminRoles||[]});}
 if(req.method==='PUT'&&p==='/api/admin/roles'){const b=await body(req),d=await read();d.adminRoles=Array.isArray(b.roles)?b.roles:[];await write(d);return send(res,200,{ok:true,roles:d.adminRoles});}
 if(req.method==='GET'&&p==='/api/admin/banners'){const d=await read();return send(res,200,{ok:true,banners:d.banners||[]});}
 if(req.method==='POST'&&p==='/api/admin/banners'){const b=await body(req),d=await read();d.banners=Array.isArray(d.banners)?d.banners:[];const x={id:'B-'+Date.now(),title:String(b.title||''),image:String(b.image||''),link:String(b.link||''),enabled:b.enabled!==false,order:Number(b.order||0)};d.banners.push(x);await write(d);return send(res,201,{ok:true,banner:x});}
 if(req.method==='PUT'&&p.startsWith('/api/admin/banners/')){const id=decodeURIComponent(p.split('/').pop()),b=await body(req),d=await read();const x=(d.banners||[]).find(a=>String(a.id)===id);if(!x)return send(res,404,{ok:false,error:'Banner not found'});Object.assign(x,b);await write(d);return send(res,200,{ok:true,banner:x});}
 if(req.method==='DELETE'&&p.startsWith('/api/admin/banners/')){const id=decodeURIComponent(p.split('/').pop()),d=await read();d.banners=(d.banners||[]).filter(x=>String(x.id)!==id);await write(d);return send(res,200,{ok:true});}
 if(req.method==='GET'&&p==='/api/admin/faqs'){const d=await read();return send(res,200,{ok:true,faqs:d.faqs||[]});}
 if(req.method==='POST'&&p==='/api/admin/faqs'){const b=await body(req),d=await read();d.faqs=Array.isArray(d.faqs)?d.faqs:[];const x={id:'F-'+Date.now(),question:String(b.question||''),answer:String(b.answer||''),enabled:b.enabled!==false,order:Number(b.order||0)};if(!x.question||!x.answer)return send(res,400,{ok:false,error:'Question and answer required'});d.faqs.push(x);await write(d);return send(res,201,{ok:true,faq:x});}
 if(req.method==='PUT'&&p==='/api/admin/pages'){const b=await body(req),d=await read();d.pages={...(d.pages||{}),...b};await write(d);return send(res,200,{ok:true,pages:d.pages});}
 if(req.method==='GET'&&p==='/api/admin/system'){const d=await read();return send(res,200,{ok:true,system:d.system||{}});}
 if(req.method==='PUT'&&p==='/api/admin/system'){const b=await body(req),d=await read();d.system={...(d.system||{}),...b,maintenance:{...(d.system?.maintenance||{}),...(b.maintenance||{})}};await write(d);return send(res,200,{ok:true,system:d.system});}
 if(req.method==='POST'&&p==='/api/admin/notice'){const b=await body(req),d=await read();d.notifications_global=Array.isArray(d.notifications_global)?d.notifications_global:[];const n={id:'N-'+Date.now(),title:String(b.title||'Notice'),message:String(b.message||''),created_at:new Date().toISOString()};d.notifications_global.unshift(n);const users=await db.listUsers(10000);if(!db.hasDatabase()){const fs=require('fs'),fp=path.join(ROOT,'notifications.json');let a=[];try{a=JSON.parse(fs.readFileSync(fp,'utf8'))}catch{};users.forEach(x=>a.unshift({id:Date.now()+Math.random(),user_id:x.id,title:n.title,message:n.message,read_at:null,created_at:n.created_at}));fs.writeFileSync(fp,JSON.stringify(a,null,2));}await write(d);return send(res,201,{ok:true,notice:n});}

 if(req.method==='PUT'&&/^\/api\/admin\/faqs\/[^/]+$/.test(p)){const id=decodeURIComponent(p.split('/').pop()),b=await body(req),d=await read(),x=(d.faqs||[]).find(a=>String(a.id)===id);if(!x)return send(res,404,{ok:false,error:'FAQ not found'});if(b.question!==undefined)x.question=String(b.question||'').trim();if(b.answer!==undefined)x.answer=String(b.answer||'').trim();if(b.enabled!==undefined)x.enabled=b.enabled!==false;if(b.order!==undefined)x.order=Number(b.order)||1;if(!x.question||!x.answer)return send(res,400,{ok:false,error:'Question and answer required'});await write(d);return send(res,200,{ok:true,faq:x})}
 if(req.method==='DELETE'&&/^\/api\/admin\/faqs\/[^/]+$/.test(p)){const id=decodeURIComponent(p.split('/').pop()),d=await read();d.faqs=(d.faqs||[]).filter(x=>String(x.id)!==id);await write(d);return send(res,200,{ok:true})}
 if(req.method==='GET'&&p==='/api/admin/tournaments'){const d=await read();return send(res,200,{ok:true,tournaments:Array.isArray(d.tournaments)?d.tournaments:[]})}
 if(req.method==='POST'&&p==='/api/admin/tournaments'){const b=await body(req),d=await read();d.tournaments=Array.isArray(d.tournaments)?d.tournaments:[];const x={id:'T-'+Date.now()+Math.random().toString(36).slice(2,6),name:String(b.name||'').trim(),entry_fee:Math.max(0,Number(b.entry_fee)||0),prize:Math.max(0,Number(b.prize)||0),max_players:Math.max(2,Math.min(1000,Number(b.max_players)||8)),status:'open',created_at:new Date().toISOString()};if(!x.name)return send(res,400,{ok:false,error:'Tournament name required'});d.tournaments.unshift(x);await write(d);await addAudit('tournament_create',x.id,x.name);return send(res,201,{ok:true,tournament:x})}
 if(req.method==='DELETE'&&/^\/api\/admin\/tournaments\/[^/]+$/.test(p)){const id=decodeURIComponent(p.split('/').pop()),d=await read();d.tournaments=(d.tournaments||[]).filter(x=>String(x.id)!==id);await write(d);await addAudit('tournament_delete',id,'');return send(res,200,{ok:true})}
 if(req.method==='GET'&&p==='/api/admin/referral'){const d=await read();return send(res,200,{ok:true,referral:d.referral||{enabled:true,code_prefix:'LB',bonus:0}})}
 if(req.method==='PUT'&&p==='/api/admin/referral'){const b=await body(req),d=await read();d.referral={...(d.referral||{}),enabled:b.enabled!==false,code_prefix:String(b.code_prefix||'LB').slice(0,20),bonus:Math.max(0,Number(b.bonus)||0)};await write(d);await addAudit('referral_update','referral',d.referral);return send(res,200,{ok:true,referral:d.referral})}
 if(req.method==='GET'&&p==='/api/leaderboard'){const d=await read(),matches=Array.isArray(d.matches)?d.matches:[],users=await db.listUsers(10000),map=new Map(users.map(x=>[String(x.id),x])),stats=new Map();for(const m of matches){if(!m.winner_user_id)continue;const id=String(m.winner_user_id),u=map.get(id);if(!u)continue;const x=stats.get(id)||{user_code:u.user_code||'Player',wins:0,prize:0};x.wins++;if(m.prize_status==='approved')x.prize+=Number(m.winning_amount||0);stats.set(id,x)}const rows=[...stats.values()].sort((a,b)=>b.wins-a.wins||b.prize-a.prize).slice(0,50).map((x,i)=>({...x,rank:i+1}));return send(res,200,{ok:true,leaderboard:rows});}
   if(req.method==='GET'&&p==='/api/admin/support-widget'){const d=await read();return send(res,200,{ok:true,supportWidget:d.supportWidget||{enabled:true,image:'support-bot.png',whatsapp:'',message:'Hello Ludo Baji Support'}})}
 if(req.method==='PUT'&&p==='/api/admin/support-widget'){const b=await body(req);const d=await read();d.supportWidget={enabled:b.enabled!==false,title:String(b.title||'Live Support 🔴').trim(),image:String(b.image||d.supportWidget?.image||'support-bot.png').trim(),whatsapp:String(b.whatsapp||'').replace(/[^0-9]/g,''),message:String(b.message||'Hello').trim()};await write(d);return send(res,200,{ok:true,supportWidget:d.supportWidget})}
if(req.method==='GET'&&p==='/api/admin/help-links'){const d=await read();const links=Array.isArray(d.helpLinks)?d.helpLinks:[{id:'faq',name:'FAQ',visible:true,order:1},{id:'rules',name:'Rules',visible:true,order:2},{id:'terms',name:'Terms',visible:true,order:3},{id:'privacy',name:'Privacy',visible:true,order:4},{id:'deposit_rules',name:'Deposit',visible:true,order:5},{id:'withdrawal_rules',name:'Withdraw',visible:true,order:6},{id:'refund_rules',name:'Refund',visible:true,order:7}];return send(res,200,{ok:true,helpLinks:links})}
 if(req.method==='PUT'&&p==='/api/admin/help-links'){const b=await body(req);const d=await read();if(!Array.isArray(b.helpLinks))return send(res,400,{ok:false,error:'helpLinks array required'});d.helpLinks=b.helpLinks.map((x,i)=>({id:String(x.id||'').trim(),name:String(x.name||x.id||'Link').trim(),visible:x.visible!==false,order:Number(x.order)||(i+1)})).filter(x=>x.id);await write(d);return send(res,200,{ok:true,helpLinks:d.helpLinks})}
if(req.method==='GET'&&p==='/api/site'){const d=await read(),nd=normalizeMainOptions(d).data;nd.banners=Array.isArray(d.banners)?d.banners:[];nd.faqs=Array.isArray(d.faqs)?d.faqs:[];nd.pages=d.pages||{};nd.referral=d.referral||{};nd.withdrawConfig=getWithdrawConfig(d);nd.supportWidget=d.supportWidget||{enabled:true,image:'support-bot.png',whatsapp:'',message:'Hello'};nd.helpLinks=Array.isArray(d.helpLinks)?d.helpLinks:[{id:'faq',name:'FAQ',visible:true,order:1},{id:'rules',name:'Rules',visible:true,order:2},{id:'terms',name:'Terms',visible:true,order:3},{id:'privacy',name:'Privacy',visible:true,order:4},{id:'deposit_rules',name:'Deposit',visible:true,order:5},{id:'withdrawal_rules',name:'Withdraw',visible:true,order:6},{id:'refund_rules',name:'Refund',visible:true,order:7}];nd.matches=Array.isArray(d.matches)?d.matches.filter(m=>String(m.status||'').toLowerCase()!=='cancelled').map(m=>({id:m.id,match_code:m.match_code,title:m.title,entry_fee:m.entry_fee,winning_amount:m.winning_amount,max_players:2,status:m.status,scheduled_at:m.scheduled_at,rules:m.rules,players:Array.isArray(m.players)?m.players.map(p=>({slot:p.slot,status:p.status})): [],created_at:m.created_at,room_id:'',room_password:''})):[];delete nd.pushConfig;delete nd.pushSubscriptions;return send(res,200,nd)}
 if(p.startsWith('/api/admin')){const d=await read();
  if(req.method==='GET'&&p==='/api/admin/data'){normalizeMainOptions(d);d.paymentMethods=Array.isArray(d.paymentMethods)?d.paymentMethods:[];d.paymentMethods.forEach(m=>{m.provider=m.provider||(/nagad/i.test(String(m.id)+' '+String(m.name))?'Nagad':'bKash');m.account_type=m.account_type||(/merchant/i.test(String(m.name))?'Merchant':/agent/i.test(String(m.name))?'Agent':/debit/i.test(String(m.name))?'Debit':'Personal');m.enabled=m.enabled!==false;m.order=Number(m.order||0)});return send(res,200,{ok:true,data:d});}
  if(req.method==='GET'&&p==='/api/admin/transactions'){
    return send(res,200,{ok:true,transactions:await db.listAdminTransactions()});
  }
  if(req.method==='GET'&&p==='/api/admin/withdrawals'){
    const status=['all','pending','approved','rejected'].includes(String(u.query.status||'all'))?String(u.query.status||'all'):'all';
    return send(res,200,{ok:true,withdrawals:await db.listAdminWithdrawals(status)});
  }
  if(req.method==='POST'&&/^\/api\/admin\/withdrawals\/[^/]+\/review$/.test(p)){
    const id=decodeURIComponent(p.split('/')[4]),b=await body(req),status=String(b.status||'').toLowerCase(),note=String(b.note||'').trim();
    if(!['approved','rejected'].includes(status))return send(res,400,{ok:false,error:'Approve অথবা Reject নির্বাচন করুন'});
    try{const adminId=await db.getAdminId(ADMIN_USERNAME);const d=await db.reviewWithdrawal(id,status,adminId,note);await addAudit('withdrawal_review',id,{status,note,amount:d.amount,user_id:d.user_id});return send(res,200,{ok:true,message:status==='approved'?'Withdrawal approved':'Withdrawal rejected',withdrawal:d})}catch(e){return send(res,400,{ok:false,error:e.message||'Review failed'})}
  }
  if(req.method==='GET'&&p==='/api/admin/deposits'){
    const status=['all','pending','approved','rejected'].includes(String(u.query.status||'all'))?String(u.query.status||'all'):'all';
    return send(res,200,{ok:true,deposits:await db.listAdminDeposits(status)});
  }
  if(req.method==='POST'&&/^\/api\/admin\/deposits\/[^/]+\/review$/.test(p)){
    const id=decodeURIComponent(p.split('/')[4]),b=await body(req),status=String(b.status||'').toLowerCase(),note=String(b.note||'').trim();
    if(!['approved','rejected'].includes(status))return send(res,400,{ok:false,error:'Approve অথবা Reject নির্বাচন করুন'});
    try{const adminId=await db.getAdminId(ADMIN_USERNAME);const d=await db.reviewDeposit(id,status,adminId,note);await addAudit(status==='approved'?'deposit_approve':'deposit_reject',id,{note,user_id:d.user_id,amount:d.amount,method:d.method});return send(res,200,{ok:true,message:status==='approved'?'Deposit approved':'Deposit rejected',deposit:d})}catch(e){return send(res,400,{ok:false,error:e.message||'Review failed'})}
  }
  if(req.method==='PUT'&&p==='/api/admin/data'){const x=await body(req);const nd={...d,site:{...d.site,...(x.site||{})},adminMenus:Array.isArray(x.adminMenus)?x.adminMenus:d.adminMenus,mainOptions:Array.isArray(x.mainOptions)?x.mainOptions:d.mainOptions,paymentMethods:Array.isArray(x.paymentMethods)?x.paymentMethods:d.paymentMethods,system:{...d.system,...(x.system||{})}};normalizeMainOptions(nd);await write(nd);return send(res,200,{ok:true,data:nd})}
  if(req.method==='POST'&&p==='/api/admin/main-options'){const x=await body(req);if(!String(x.name||'').trim())return send(res,400,{error:'Option Name দিন'});d.mainOptions.push({id:'main-'+Date.now()+Math.random().toString(36).slice(2,6),name:String(x.name).trim(),icon:String(x.icon||'📌'),logo:String(x.logo||''),content:String(x.content||''),visible:true,order:Number(x.order||d.mainOptions.length+1),button_text:String(x.button_text||''),action:['auto','content','url'].includes(String(x.action||'auto'))?String(x.action||'auto'):'auto',url:safeHttpUrl(x.url||''),background:String(x.background||'#092d21'),text_color:String(x.text_color||'#ffffff'),border_radius:Math.max(0,Math.min(60,Number(x.border_radius)||12))});await write(d);return send(res,200,{ok:true,data:d})}
  if(req.method==='DELETE'&&p.startsWith('/api/admin/main-options/')){const id=decodeURIComponent(p.split('/').pop());d.mainOptions=d.mainOptions.filter(x=>x.id!==id);await write(d);return send(res,200,{ok:true,data:d})}
 }
 if(req.method==='GET'){let file=p==='/'?'index.html':p==='/admin'||p==='/admin/'?'admin.html':p.slice(1);if(file.includes('..'))return send(res,403,'Forbidden','text/plain');const fp=path.join(ROOT,file);if(fs.existsSync(fp)&&fs.statSync(fp).isFile()){res.writeHead(200,{'Content-Type':mime[path.extname(fp)]||'application/octet-stream','Cache-Control':path.extname(fp)==='.html'?'no-store':'public,max-age=3600'});return fs.createReadStream(fp).pipe(res)}}
 send(res,404,'Not found','text/plain; charset=utf-8');
}catch(e){console.error(e);send(res,500,{error:'Server error'})}});
(async()=>{try{await db.init();await ensureVapidConfig();attachMatchWebSocket(server);server.listen(PORT,()=>console.log('Ludo Baji V9 listening on '+PORT+(db.hasDatabase()?' with PostgreSQL':' with local fallback')+' | WS /ws/matches'))}catch(e){console.error('Database initialization failed:',e.message);process.exit(1)}})();
