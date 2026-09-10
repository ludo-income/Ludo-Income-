const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDb(){
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e){ return {settings:{siteName:'Ludo Income',tagline:'Play. Compete. Enjoy.',notice:'Welcome',support:'',maintenance:false,showNotice:true,primaryColor:'#6d28d9'},matches:[]}; }
}
function saveDb(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function tokenFor(email){ return jwt.sign({email, role:'superadmin'}, JWT_SECRET, {expiresIn:'12h'}); }
function auth(req,res,next){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):null;
  if(!token) return res.status(401).json({error:'Authentication required'});
  try { req.admin=jwt.verify(token, JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({error:'Session expired'}); }
}
app.use(express.json({limit:'100kb'}));
app.use(express.urlencoded({extended:false}));

app.post('/api/admin/login', async (req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase();
  const password=String(req.body.password||'');
  const adminEmail=String(process.env.ADMIN_EMAIL||'admin@example.com').trim().toLowerCase();
  const adminHash=process.env.ADMIN_PASSWORD_HASH;
  const adminPassword=process.env.ADMIN_PASSWORD||'ChangeThisPassword123!';
  if(email!==adminEmail) return res.status(401).json({error:'Invalid email or password'});
  const ok=adminHash ? await bcrypt.compare(password,adminHash) : password===adminPassword;
  if(!ok) return res.status(401).json({error:'Invalid email or password'});
  res.json({token:tokenFor(email),admin:{email,role:'Super Admin'}});
});

app.get('/api/site', (req,res)=>{
  const db=loadDb();
  res.json({settings:db.settings,matches:db.matches});
});

app.get('/api/admin/settings', auth, (req,res)=>res.json(loadDb().settings));
app.put('/api/admin/settings', auth, (req,res)=>{
  const db=loadDb();
  const allowed=['siteName','tagline','notice','support','maintenance','showNotice','primaryColor'];
  for(const k of allowed) if(req.body[k]!==undefined) db.settings[k]=req.body[k];
  saveDb(db); res.json({ok:true,settings:db.settings});
});

app.post('/api/admin/password', auth, async (req,res)=>{
  const current=String(req.body.currentPassword||'');
  const next=String(req.body.newPassword||'');
  if(next.length<8) return res.status(400).json({error:'New password must be at least 8 characters'});
  const adminPassword=process.env.ADMIN_PASSWORD||'';
  const hash=process.env.ADMIN_PASSWORD_HASH;
  const valid=hash ? await bcrypt.compare(current,hash) : current===adminPassword;
  if(!valid) return res.status(400).json({error:'Current password is incorrect'});
  // Runtime password change. For durable production use, store admin credentials in a database.
  process.env.ADMIN_PASSWORD=next;
  process.env.ADMIN_PASSWORD_HASH=await bcrypt.hash(next,12);
  res.json({ok:true,message:'Password changed. Please log in again.'});
});

app.get('/api/admin/matches', auth, (req,res)=>res.json(loadDb().matches));
app.post('/api/admin/matches', auth, (req,res)=>{
  const db=loadDb();
  const m={id:String(req.body.id||('LD'+Date.now())).trim(),name:String(req.body.name||'New Match').trim(),time:String(req.body.time||''),players:String(req.body.players||'2 Players'),status:String(req.body.status||'Open')};
  if(!m.name) return res.status(400).json({error:'Match name required'});
  db.matches.unshift(m); saveDb(db); res.json({ok:true,match:m});
});
app.delete('/api/admin/matches/:id', auth, (req,res)=>{
  const db=loadDb(); const before=db.matches.length;
  db.matches=db.matches.filter(m=>m.id!==req.params.id); saveDb(db);
  if(db.matches.length===before) return res.status(404).json({error:'Match not found'});
  res.json({ok:true});
});

app.use('/admin', express.static(path.join(__dirname,'admin')));
app.get('/admin', (req,res)=>res.sendFile(path.join(__dirname,'admin','index.html')));
app.get('/admin/', (req,res)=>res.sendFile(path.join(__dirname,'admin','index.html')));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT, ()=>console.log('Ludo Income server running on port '+PORT));
