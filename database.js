const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
function cryptoRandom(n){return crypto.randomBytes(Math.max(1,Number(n)||8)).toString('hex').slice(0,Math.max(1,Number(n)||8))}

const DATA = path.join(__dirname, 'data.json');
const USERS_DATA = path.join(__dirname, 'users.json');
const DEPOSITS_DATA = path.join(__dirname, 'deposits.json');
const WITHDRAWALS_DATA = path.join(__dirname, 'withdrawals.json');
const NOTIFICATIONS_DATA = path.join(__dirname, 'notifications.json');
const TRANSACTIONS_DATA = path.join(__dirname, 'transactions.json');
const SUPPORT_DATA = path.join(__dirname, 'support_messages.json');
let featureMatchLock=Promise.resolve();
async function withFeatureMatchLock(fn){const prev=featureMatchLock;let release;featureMatchLock=new Promise(r=>release=r);await prev;try{return await fn()}finally{release()}}
let pool = null;
let ready = null;
let fallbackFinancialQueue = Promise.resolve();

function assertMoneyAmount(value, field='amount') {
  const n=Number(value);
  if(!Number.isFinite(n) || n<=0 || n>999999999999.99) throw new Error(`Invalid ${field}`);
  if(Math.round(n*100)!==Math.round(n)*100 && !Number.isInteger(Math.round(n*100))) throw new Error(`Invalid ${field}`);
  return Number(n.toFixed(2));
}
function withFallbackFinancialLock(task){
  const run=fallbackFinancialQueue.then(task,task);
  fallbackFinancialQueue=run.catch(()=>{});
  return run;
}
function snapshotFallbackFinancialFiles(){
  const files=[DATA,USERS_DATA,DEPOSITS_DATA,WITHDRAWALS_DATA,TRANSACTIONS_DATA,NOTIFICATIONS_DATA];
  const out={}; for(const f of files) out[f]=fs.existsSync(f)?fs.readFileSync(f,'utf8'):null; return out;
}
function restoreFallbackFinancialFiles(snapshot){
  for(const [f,data] of Object.entries(snapshot)){ if(data===null){try{fs.unlinkSync(f)}catch{}} else {const tmp=f+'.restore.tmp';fs.writeFileSync(tmp,data,'utf8');fs.renameSync(tmp,f)} }
}

function fallbackRead() {
  // Never overwrite existing production data.json — only seed if missing
  if (!fs.existsSync(DATA)) {
    const def = path.join(__dirname, 'data.default.json');
    if (fs.existsSync(def)) {
      try { fs.copyFileSync(def, DATA); } catch (e) {}
    }
  }
  if (!fs.existsSync(DATA)) {
    return { site: { name: 'Ludo Baji', logo: 'logo-ludo-baji.jpg' }, mainOptions: [], paymentMethods: [], system: {} };
  }
  return JSON.parse(fs.readFileSync(DATA, 'utf8'));
}
function fallbackWrite(data) {
  const tmp = DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, DATA);
}
function fallbackUsersRead() {
  if (!fs.existsSync(USERS_DATA)) return [];
  try { return JSON.parse(fs.readFileSync(USERS_DATA, 'utf8')); } catch { return []; }
}
function fallbackUsersWrite(users) {
  const tmp = USERS_DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2), 'utf8');
  fs.renameSync(tmp, USERS_DATA);
}
function fallbackDepositsRead() {
  if (!fs.existsSync(DEPOSITS_DATA)) return [];
  try { return JSON.parse(fs.readFileSync(DEPOSITS_DATA, 'utf8')); } catch { return []; }
}
function fallbackDepositsWrite(items) {
  const tmp = DEPOSITS_DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(items, null, 2), 'utf8');
  fs.renameSync(tmp, DEPOSITS_DATA);
}
function fallbackWithdrawalsRead() {
  if (!fs.existsSync(WITHDRAWALS_DATA)) return [];
  try { return JSON.parse(fs.readFileSync(WITHDRAWALS_DATA, 'utf8')); } catch { return []; }
}
function fallbackWithdrawalsWrite(items) {
  const tmp = WITHDRAWALS_DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(items, null, 2), 'utf8');
  fs.renameSync(tmp, WITHDRAWALS_DATA);
}
function fallbackNotificationsRead() {
  if (!fs.existsSync(NOTIFICATIONS_DATA)) return [];
  try { return JSON.parse(fs.readFileSync(NOTIFICATIONS_DATA, 'utf8')); } catch { return []; }
}
function fallbackNotificationsWrite(items) {
  const tmp = NOTIFICATIONS_DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(items, null, 2), 'utf8');
  fs.renameSync(tmp, NOTIFICATIONS_DATA);
}
function fallbackTransactionsRead() {
  if (!fs.existsSync(TRANSACTIONS_DATA)) return [];
  try { return JSON.parse(fs.readFileSync(TRANSACTIONS_DATA, 'utf8')); } catch { return []; }
}
function fallbackTransactionsWrite(items) {
  const tmp = TRANSACTIONS_DATA + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(items, null, 2), 'utf8');
  fs.renameSync(tmp, TRANSACTIONS_DATA);
}
function hasDatabase() { return Boolean(process.env.DATABASE_URL); }

async function init() {
  if (!hasDatabase()) return;
  if (ready) return ready;
  ready = (async () => {
    let pg;
    try { pg = require('pg'); } catch (err) { throw new Error('DATABASE_URL is set but the pg package is unavailable. Run npm install before deployment.'); }
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
      max: 5
    });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS admins (id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'super_admin', active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY, user_code TEXT UNIQUE, email TEXT UNIQUE, phone TEXT UNIQUE, name TEXT, status TEXT NOT NULL DEFAULT 'active',
        otp_hash TEXT, otp_expires_at TIMESTAMPTZ, otp_sent_at TIMESTAMPTZ, otp_attempts INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT UNIQUE;
      ALTER TABLE users ALTER COLUMN phone DROP NOT NULL;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_sent_at TIMESTAMPTZ;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_attempts INTEGER NOT NULL DEFAULT 0;
      CREATE TABLE IF NOT EXISTS wallets (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, gaming_balance NUMERIC(14,2) NOT NULL DEFAULT 0, winning_balance NUMERIC(14,2) NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS transactions (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, balance_type TEXT, reference TEXT, status TEXT NOT NULL DEFAULT 'pending', note TEXT, balance_before NUMERIC(14,2), balance_after NUMERIC(14,2), balance_change NUMERIC(14,2), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_before NUMERIC(14,2);
      ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_after NUMERIC(14,2);
      ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_change NUMERIC(14,2);
      CREATE TABLE IF NOT EXISTS deposits (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, method TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, transaction_id TEXT, screenshot TEXT, status TEXT NOT NULL DEFAULT 'pending', reviewed_by BIGINT REFERENCES admins(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_deposits_transaction_id ON deposits(transaction_id) WHERE transaction_id IS NOT NULL AND transaction_id <> '';
      CREATE TABLE IF NOT EXISTS withdrawals (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, method TEXT NOT NULL, account_number TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, balance_type TEXT NOT NULL DEFAULT 'winning', status TEXT NOT NULL DEFAULT 'pending', note TEXT, reviewed_by BIGINT REFERENCES admins(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ);
      ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS balance_type TEXT NOT NULL DEFAULT 'winning';
      ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS note TEXT;
      CREATE TABLE IF NOT EXISTS matches (id BIGSERIAL PRIMARY KEY, match_code TEXT UNIQUE, title TEXT NOT NULL, entry_fee NUMERIC(14,2) NOT NULL DEFAULT 0, winning_amount NUMERIC(14,2) NOT NULL DEFAULT 0, room_id TEXT, status TEXT NOT NULL DEFAULT 'open', scheduled_at TIMESTAMPTZ, winner_user_id BIGINT REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS match_players (match_id BIGINT NOT NULL REFERENCES matches(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, slot SMALLINT NOT NULL, status TEXT NOT NULL DEFAULT 'joined', joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (match_id, user_id), UNIQUE (match_id, slot));
      CREATE TABLE IF NOT EXISTS notifications (id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, message TEXT NOT NULL, read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS support_messages (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender TEXT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE INDEX IF NOT EXISTS idx_transactions_user_created ON transactions(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);
      CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);
      CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_support_user_created ON support_messages(user_id, created_at DESC);
      DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT wallets_gaming_nonnegative CHECK (gaming_balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT wallets_winning_nonnegative CHECK (winning_balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
      DO $$ BEGIN ALTER TABLE transactions ADD CONSTRAINT transactions_amount_nonnegative CHECK (amount >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    `);
    const existing = await pool.query('SELECT COUNT(*)::int AS count FROM app_config');
    if (existing.rows[0].count === 0) {
      const seed = fallbackRead();
      for (const [key, value] of Object.entries(seed)) await pool.query('INSERT INTO app_config(key, value) VALUES($1, $2::jsonb) ON CONFLICT (key) DO NOTHING', [key, JSON.stringify(value)]);
    }
    await pool.query('INSERT INTO admins(username) VALUES($1) ON CONFLICT (username) DO NOTHING', [process.env.ADMIN_USERNAME || 'admin']);
  })();
  return ready;
}

async function getData() {
  if (!hasDatabase()) return fallbackRead();
  await init();
  const result = await pool.query('SELECT key, value FROM app_config');
  const data = {};
  for (const row of result.rows) data[row.key] = row.value;
  return data;
}
async function saveData(data) {
  if (!hasDatabase()) return fallbackWrite(data);
  await init();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const [key, value] of Object.entries(data)) await client.query(`INSERT INTO app_config(key, value, updated_at) VALUES($1, $2::jsonb, NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`, [key, JSON.stringify(value)]);
    await client.query('COMMIT');
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}

async function findUser(phone) {
  if (!hasDatabase()) return fallbackUsersRead().find(u => u.phone === phone) || null;
  await init(); const r = await pool.query('SELECT id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at FROM users WHERE phone=$1',[phone]); return r.rows[0]||null;
}
async function findUserByEmail(email) {
  email=String(email||'').trim().toLowerCase();
  if (!hasDatabase()) return fallbackUsersRead().find(u=>String(u.email||'').toLowerCase()===email)||null;
  await init(); const r=await pool.query('SELECT id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at FROM users WHERE LOWER(email)=LOWER($1)',[email]); return r.rows[0]||null;
}
async function createUser(phone) {
  if (!hasDatabase()) { const users=fallbackUsersRead(); const existing=users.find(u=>u.phone===phone); if(existing)return existing; const id=Date.now(); const user={id,user_code:'U'+String(id).slice(-8),phone,email:null,name:'',status:'active',otp_hash:null,otp_expires_at:null,otp_sent_at:null,otp_attempts:0,created_at:new Date().toISOString()}; users.push(user); fallbackUsersWrite(users); return user; }
  await init(); const r=await pool.query('INSERT INTO users(user_code,phone) VALUES($1,$2) ON CONFLICT(phone) DO UPDATE SET phone=EXCLUDED.phone,updated_at=NOW() RETURNING id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at',['U'+cryptoRandom(8),phone]); return r.rows[0];
}
async function createUserByEmail(email) {
  email=String(email||'').trim().toLowerCase();
  if(!hasDatabase()){const users=fallbackUsersRead();const existing=users.find(u=>String(u.email||'').toLowerCase()===email);if(existing)return existing;const id=Date.now();const user={id,user_code:'U'+String(id).slice(-8),email,phone:null,name:'',status:'active',otp_hash:null,otp_expires_at:null,otp_sent_at:null,otp_attempts:0,created_at:new Date().toISOString()};users.push(user);fallbackUsersWrite(users);return user;}
  await init(); const r=await pool.query('INSERT INTO users(user_code,email) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET email=EXCLUDED.email,updated_at=NOW() RETURNING id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at',['U'+cryptoRandom(8),email]); return r.rows[0];
}
async function setUserOtp(phone, otpHash, expiresAt, sentAt) {
  if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>x.phone===phone);if(!u)throw new Error('User not found');u.otp_hash=otpHash;u.otp_expires_at=expiresAt;u.otp_sent_at=sentAt;u.otp_attempts=0;fallbackUsersWrite(users);return u;}
  await init(); const r=await pool.query('UPDATE users SET otp_hash=$1,otp_expires_at=$2,otp_sent_at=$3,otp_attempts=0,updated_at=NOW() WHERE phone=$4 RETURNING id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at',[otpHash,expiresAt,sentAt,phone]); return r.rows[0];
}
async function setUserOtpByEmail(email, otpHash, expiresAt, sentAt) {
  email=String(email||'').trim().toLowerCase();
  if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>String(x.email||'').toLowerCase()===email);if(!u)throw new Error('User not found');u.otp_hash=otpHash;u.otp_expires_at=expiresAt;u.otp_sent_at=sentAt;u.otp_attempts=0;fallbackUsersWrite(users);return u;}
  await init(); const r=await pool.query('UPDATE users SET otp_hash=$1,otp_expires_at=$2,otp_sent_at=$3,otp_attempts=0,updated_at=NOW() WHERE LOWER(email)=LOWER($4) RETURNING id,user_code,email,phone,name,status,otp_hash,otp_expires_at,otp_sent_at,otp_attempts,created_at',[otpHash,expiresAt,sentAt,email]); return r.rows[0];
}
async function updateOtpAttempts(phone, attempts) { if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>x.phone===phone);if(u){u.otp_attempts=attempts;fallbackUsersWrite(users);}return;} await init();await pool.query('UPDATE users SET otp_attempts=$1,updated_at=NOW() WHERE phone=$2',[attempts,phone]); }
async function updateOtpAttemptsByEmail(email, attempts) { email=String(email||'').trim().toLowerCase();if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>String(x.email||'').toLowerCase()===email);if(u){u.otp_attempts=attempts;fallbackUsersWrite(users);}return;}await init();await pool.query('UPDATE users SET otp_attempts=$1,updated_at=NOW() WHERE LOWER(email)=LOWER($2)',[attempts,email]); }
async function clearUserOtp(phone) { if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>x.phone===phone);if(u){u.otp_hash=null;u.otp_expires_at=null;u.otp_sent_at=null;u.otp_attempts=0;fallbackUsersWrite(users);}return;}await init();await pool.query('UPDATE users SET otp_hash=NULL,otp_expires_at=NULL,otp_sent_at=NULL,otp_attempts=0,updated_at=NOW() WHERE phone=$1',[phone]); }
async function clearUserOtpByEmail(email) { email=String(email||'').trim().toLowerCase();if(!hasDatabase()){const users=fallbackUsersRead();const u=users.find(x=>String(x.email||'').toLowerCase()===email);if(u){u.otp_hash=null;u.otp_expires_at=null;u.otp_sent_at=null;u.otp_attempts=0;fallbackUsersWrite(users);}return;}await init();await pool.query('UPDATE users SET otp_hash=NULL,otp_expires_at=NULL,otp_sent_at=NULL,otp_attempts=0,updated_at=NOW() WHERE LOWER(email)=LOWER($1)',[email]); }
async function updateUserName(id, name) {
  if (!hasDatabase()) { const users=fallbackUsersRead(); const u=users.find(x=>String(x.id)===String(id)); if(!u) return null; u.name=name; fallbackUsersWrite(users); return u; }
  await init(); const r=await pool.query('UPDATE users SET name=$1, updated_at=NOW() WHERE id=$2 RETURNING id,user_code,email,phone,name,status,created_at', [name,id]); return r.rows[0]||null;
}
async function getUserById(id) {
  if (!hasDatabase()) return fallbackUsersRead().find(u=>String(u.id)===String(id))||null;
  await init(); const r=await pool.query('SELECT id,user_code,email,phone,name,status,created_at FROM users WHERE id=$1',[id]); return r.rows[0]||null;
}

async function getUserDashboard(id) {
  if (!hasDatabase()) {
    const users = fallbackUsersRead();
    const u = users.find(x => String(x.id) === String(id));
    if (!u) return null;
    return {
      gaming_balance: Number(u.gaming_balance || 0),
      winning_balance: Number(u.winning_balance || 0),
      joined_matches: Number(u.joined_matches || 0),
      notifications: Number(u.notifications || 0)
    };
  }
  await init();
  await pool.query('INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING', [id]);
  const r = await pool.query(`
    SELECT w.gaming_balance, w.winning_balance,
      (SELECT COUNT(*) FROM match_players mp WHERE mp.user_id=$1)::int AS joined_matches,
      (SELECT COUNT(*) FROM notifications n WHERE n.user_id=$1 AND n.read_at IS NULL)::int AS notifications
    FROM wallets w WHERE w.user_id=$1`, [id]);
  return r.rows[0] || {gaming_balance:0, winning_balance:0, joined_matches:0, notifications:0};
}

async function ensureUserWallet(id) {
  if (!hasDatabase()) {
    const users = fallbackUsersRead();
    const u = users.find(x => String(x.id) === String(id));
    if (!u) return null;
    if (u.gaming_balance == null) u.gaming_balance = 0;
    if (u.winning_balance == null) u.winning_balance = 0;
    fallbackUsersWrite(users);
    return u;
  }
  await init();
  await pool.query('INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING', [id]);
  return true;
}


async function createDeposit(userId, method, amount, transactionId, screenshot) {
  amount=assertMoneyAmount(amount);
  if (!hasDatabase()) return withFallbackFinancialLock(async()=>{
    const snapshot=snapshotFallbackFinancialFiles();
    try {
      const users = fallbackUsersRead();
      const user = users.find(u => String(u.id) === String(userId));
      if (!user) throw new Error('User not found');
      if (user.status !== 'active') throw new Error('এই অ্যাকাউন্টটি বন্ধ আছে');
      const deposits = fallbackDepositsRead();
      if (transactionId && deposits.some(d => String(d.transaction_id||'').toLowerCase() === String(transactionId).toLowerCase())) throw new Error('এই Transaction ID আগে ব্যবহার করা হয়েছে');
      const id = Date.now()+'-'+Math.random().toString(36).slice(2,8);
      const now=new Date().toISOString();
      const item = {id, user_id:user.id, user_code:user.user_code, phone:user.phone, method, amount, transaction_id:transactionId, screenshot, status:'pending', reviewed_by:null, created_at:now, reviewed_at:null};
      deposits.unshift(item); fallbackDepositsWrite(deposits);
      const txs=fallbackTransactionsRead();
      const ref=transactionId||('DEP-'+id);
      if(txs.some(t=>String(t.user_id)===String(user.id)&&t.type==='deposit'&&String(t.reference)===String(ref))) throw new Error('Duplicate deposit transaction');
      txs.unshift({id:'DEP-'+id,user_id:user.id,user_code:user.user_code,type:'deposit',amount,balance_type:'gaming',reference:ref,status:'pending',note:'Deposit request via '+method,balance_before:Number(user.gaming_balance||0),balance_after:Number(user.gaming_balance||0),balance_change:0,created_at:now});
      fallbackTransactionsWrite(txs);
      return item;
    } catch(e){ restoreFallbackFinancialFiles(snapshot); throw e; }
  });
  await init();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const u = await client.query('SELECT id,user_code,phone,status FROM users WHERE id=$1 FOR UPDATE',[userId]);
    if (!u.rows[0]) throw new Error('User not found');
    if (u.rows[0].status !== 'active') throw new Error('এই অ্যাকাউন্টটি বন্ধ আছে');
    const d = await client.query('INSERT INTO deposits(user_id,method,amount,transaction_id,screenshot,status) VALUES($1,$2,$3,$4,$5,\'pending\') RETURNING *',[userId,method,amount,transactionId||null,screenshot||null]);
    await client.query('INSERT INTO transactions(user_id,type,amount,balance_type,reference,status,note) VALUES($1,\'deposit\',$2,\'gaming\',$3,\'pending\',$4)',[userId,amount,transactionId||('DEP-'+d.rows[0].id),'Deposit request via '+method]);
    await client.query('COMMIT');
    return {...d.rows[0],user_code:u.rows[0].user_code,phone:u.rows[0].phone};
  } catch(e) { await client.query('ROLLBACK'); if(e && e.code==='23505') throw new Error('এই Transaction ID আগে ব্যবহার করা হয়েছে'); throw e; } finally { client.release(); }
}

async function listUserDeposits(userId, limit=50) {
  if (!hasDatabase()) return fallbackDepositsRead().filter(d=>String(d.user_id)===String(userId)).slice(0,limit);
  await init();
  const r=await pool.query(`SELECT id,method,amount,transaction_id,screenshot,status,created_at,reviewed_at FROM deposits WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,[userId,limit]);
  return r.rows;
}

async function listAdminDeposits(status='all', limit=100) {
  if (!hasDatabase()) {
    const users=fallbackUsersRead(); const map=new Map(users.map(u=>[String(u.id),u]));
    let rows=fallbackDepositsRead().map(d=>({...d,user_code:d.user_code||map.get(String(d.user_id))?.user_code||'',phone:d.phone||map.get(String(d.user_id))?.phone||''}));
    if(status!=='all') rows=rows.filter(d=>d.status===status);
    return rows.slice(0,limit);
  }
  await init();
  const where=status==='all'?'':' WHERE d.status=$1';
  const params=status==='all'?[limit]:[status,limit];
  const r=await pool.query(`SELECT d.id,d.user_id,u.user_code,u.phone,u.name,d.method,d.amount,d.transaction_id,d.screenshot,d.status,d.created_at,d.reviewed_at FROM deposits d JOIN users u ON u.id=d.user_id${where} ORDER BY d.created_at DESC LIMIT $${params.length}` ,params);
  return r.rows;
}

async function reviewDeposit(depositId, status, adminId=null, note='') {
  if (!['approved','rejected'].includes(status)) throw new Error('Invalid deposit status');
  if (!hasDatabase()) return withFallbackFinancialLock(async()=>{
    const snapshot=snapshotFallbackFinancialFiles();
    try {
      const deposits=fallbackDepositsRead(); const d=deposits.find(x=>String(x.id)===String(depositId));
      if(!d) throw new Error('Deposit পাওয়া যায়নি');
      if(d.status!=='pending') throw new Error('এই Deposit ইতিমধ্যে review করা হয়েছে');
      const users=fallbackUsersRead(); const u=users.find(x=>String(x.id)===String(d.user_id)); if(!u) throw new Error('User not found');
      const before=Number(u.gaming_balance||0), after=status==='approved'?Number((before+Number(d.amount)).toFixed(2)):before;
      d.status=status; d.reviewed_by=adminId; d.reviewed_at=new Date().toISOString(); d.note=note||'';
      if(status==='approved') u.gaming_balance=after;
      fallbackDepositsWrite(deposits); fallbackUsersWrite(users);
      const txs=fallbackTransactionsRead(); const ref=d.transaction_id||('DEP-'+d.id); const tx=txs.find(x=>String(x.reference)===String(ref)&&x.type==='deposit'&&String(x.user_id)===String(d.user_id)&&x.status==='pending');
      if(!tx) throw new Error('Deposit transaction record not found');
      tx.status=status==='approved'?'completed':'rejected'; tx.note=note||(status==='approved'?'Deposit approved':'Deposit rejected'); tx.balance_before=before; tx.balance_after=after; tx.balance_change=status==='approved'?Number(d.amount):0;
      fallbackTransactionsWrite(txs);
      const notes=fallbackNotificationsRead(); notes.unshift({id:Date.now()+Math.random(),user_id:d.user_id,title:status==='approved'?'Deposit Approved':'Deposit Rejected',message:status==='approved'?('আপনার ৳'+Number(d.amount).toFixed(2)+' Deposit Gaming Balance-এ যোগ হয়েছে।'):('আপনার Deposit requestটি বাতিল করা হয়েছে।'+(note?' কারণ: '+note:'')),read_at:null,created_at:d.reviewed_at}); fallbackNotificationsWrite(notes);
      return d;
    } catch(e){ restoreFallbackFinancialFiles(snapshot); throw e; }
  });
  await init();
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const q=await client.query('SELECT d.*,u.user_code FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.id=$1 FOR UPDATE',[depositId]);
    if(!q.rows[0]) throw new Error('Deposit পাওয়া যায়নি');
    const d=q.rows[0]; if(d.status!=='pending') throw new Error('এই Deposit ইতিমধ্যে review করা হয়েছে');
    await client.query('UPDATE deposits SET status=$1, reviewed_by=$2, reviewed_at=NOW() WHERE id=$3',[status,adminId,depositId]);
    if(status==='approved'){
      await client.query('INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING',[d.user_id]);
      const wb=await client.query('SELECT gaming_balance FROM wallets WHERE user_id=$1 FOR UPDATE',[d.user_id]);
      const before=Number(wb.rows[0]?.gaming_balance||0), after=Number((before+Number(d.amount)).toFixed(2));
      await client.query('UPDATE wallets SET gaming_balance=$1,updated_at=NOW() WHERE user_id=$2',[after,d.user_id]);
      const txr=await client.query('UPDATE transactions SET status=\'completed\',note=$1,balance_before=$2,balance_after=$3,balance_change=$4 WHERE user_id=$5 AND reference=$6 AND type=\'deposit\' AND status=\'pending\'',[note||'Deposit approved',before,after,Number(d.amount),d.user_id,d.transaction_id||('DEP-'+d.id)]);
      if(txr.rowCount!==1) throw new Error('Deposit transaction record not found');
      await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[d.user_id,'Deposit Approved','আপনার ৳'+Number(d.amount).toFixed(2)+' Deposit Gaming Balance-এ যোগ হয়েছে।']);
    } else {
      const txr=await client.query('UPDATE transactions SET status=\'rejected\',note=$1 WHERE user_id=$2 AND reference=$3 AND type=\'deposit\' AND status=\'pending\'',[note||'Deposit rejected',d.user_id,d.transaction_id||('DEP-'+d.id)]);
      if(txr.rowCount!==1) throw new Error('Deposit transaction record not found');
      await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[d.user_id,'Deposit Rejected','আপনার Deposit requestটি বাতিল করা হয়েছে।']);
    }
    await client.query('COMMIT'); return {...d,status,reviewed_at:new Date().toISOString()};
  }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}



async function createWithdrawal(userId, method, accountNumber, amount, balanceType='winning', accountName='') {
  if (!['bkash','nagad','rocket','upay'].includes(method)) throw new Error('bKash, Nagad, Rocket অথবা Upay নির্বাচন করুন');
  if (!['gaming','winning'].includes(balanceType)) throw new Error('সঠিক Balance নির্বাচন করুন');
  amount=assertMoneyAmount(amount);
  accountNumber=String(accountNumber||'').trim();
  accountName=String(accountName||'').trim();
  if(!accountName || accountName.length<2) throw new Error('Account Holder Name দিন');
  if(!/^(?:\+?8801|01)\d{9}$/.test(accountNumber.replace(/[\s-]/g,''))) throw new Error('সঠিক Mobile Number দিন (01XXXXXXXXX)');
  if (!hasDatabase()) return withFallbackFinancialLock(async()=>{
    const snapshot=snapshotFallbackFinancialFiles();
    try {
      const users=fallbackUsersRead(); const u=users.find(x=>String(x.id)===String(userId));
      if(!u) throw new Error('User not found'); if(u.status!=='active') throw new Error('এই অ্যাকাউন্টটি বন্ধ আছে');
      const key=balanceType+'_balance',before=Number(u[key]||0); if(before<amount) throw new Error('পর্যাপ্ত Balance নেই');
      const id=Date.now()+'-'+Math.random().toString(36).slice(2,8),now=new Date().toISOString(),ref='WDR-'+id;
      const after=Number((before-amount).toFixed(2)); u[key]=after;
      const item={id,user_id:u.id,user_code:u.user_code,email:u.email||'',phone:u.phone||null,name:u.name||'',method,account_number:accountNumber,account_name:accountName,amount,balance_type:balanceType,status:'pending',note:'',reviewed_by:null,created_at:now,reviewed_at:null,balance_before:before,balance_after:after};
      const withdrawals=fallbackWithdrawalsRead(); withdrawals.unshift(item); fallbackWithdrawalsWrite(withdrawals); fallbackUsersWrite(users);
      const txs=fallbackTransactionsRead(); txs.unshift({id:ref,user_id:u.id,type:'withdrawal',amount,balance_type:balanceType,reference:ref,status:'pending',note:'Withdrawal request via '+method,balance_before:before,balance_after:after,balance_change:-amount,created_at:now}); fallbackTransactionsWrite(txs);
      const notes=fallbackNotificationsRead(); notes.unshift({id:Date.now()+Math.random(),user_id:u.id,title:'Withdrawal Submitted',message:'আপনার ৳'+amount.toFixed(2)+' Withdrawal request জমা হয়েছে।',read_at:null,created_at:now}); fallbackNotificationsWrite(notes);
      return item;
    }catch(e){restoreFallbackFinancialFiles(snapshot);throw e;}
  });
  await init(); const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const u=await client.query('SELECT id,user_code,phone,name,status FROM users WHERE id=$1 FOR UPDATE',[userId]);
    if(!u.rows[0]) throw new Error('User not found'); if(u.rows[0].status!=='active') throw new Error('এই অ্যাকাউন্টটি বন্ধ আছে');
    await client.query('INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING',[userId]);
    const col=balanceType==='gaming'?'gaming_balance':'winning_balance';
    const w=await client.query(`SELECT ${col} AS balance FROM wallets WHERE user_id=$1 FOR UPDATE`,[userId]);
    const before=Number(w.rows[0]?.balance||0); if(before<amount) throw new Error('পর্যাপ্ত Balance নেই'); const after=Number((before-amount).toFixed(2));
    try{await client.query('ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS account_name TEXT')}catch{}
    const r=await client.query('INSERT INTO withdrawals(user_id,method,account_number,account_name,amount,balance_type,status,note) VALUES($1,$2,$3,$4,$5,$6,\'pending\',\'\') RETURNING *',[userId,method,accountNumber,accountName,amount,balanceType]);
    await client.query(`UPDATE wallets SET ${col}=$1,updated_at=NOW() WHERE user_id=$2`,[after,userId]);
    await client.query('INSERT INTO transactions(user_id,type,amount,balance_type,reference,status,note,balance_before,balance_after,balance_change) VALUES($1,\'withdrawal\',$2,$3,$4,\'pending\',$5,$6,$7,$8)',[userId,amount,balanceType,'WDR-'+r.rows[0].id,'Withdrawal request via '+method,before,after,-amount]);
    await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[userId,'Withdrawal Submitted','আপনার ৳'+amount.toFixed(2)+' Withdrawal request জমা হয়েছে।']);
    await client.query('COMMIT'); return {...r.rows[0],user_code:u.rows[0].user_code,phone:u.rows[0].phone,name:u.rows[0].name||'',balance_before:before,balance_after:after};
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
async function listUserWithdrawals(userId, limit=50) {
  if (!hasDatabase()) return fallbackWithdrawalsRead().filter(d=>String(d.user_id)===String(userId)).slice(0,limit);
  await init();
  const r=await pool.query('SELECT id,method,account_number,account_name,amount,balance_type,status,note,created_at,reviewed_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',[userId,limit]);
  return r.rows;
}

async function listAdminWithdrawals(status='all', limit=100) {
  if (!hasDatabase()) {
    const users=fallbackUsersRead(); const map=new Map(users.map(u=>[String(u.id),u]));
    let rows=fallbackWithdrawalsRead().map(d=>({...d,user_code:d.user_code||map.get(String(d.user_id))?.user_code||'',phone:d.phone||map.get(String(d.user_id))?.phone||'',name:d.name||map.get(String(d.user_id))?.name||''}));
    if(status!=='all') rows=rows.filter(d=>d.status===status);
    return rows.slice(0,limit);
  }
  await init();
  const where=status==='all'?'':' WHERE w.status=$1';
  const params=status==='all'?[limit]:[status,limit];
  const r=await pool.query(`SELECT w.id,w.user_id,u.user_code,u.phone,u.name,w.method,w.account_number,w.account_name,w.amount,w.balance_type,w.status,w.note,w.created_at,w.reviewed_at FROM withdrawals w JOIN users u ON u.id=w.user_id${where} ORDER BY w.created_at DESC LIMIT $${params.length}`,params);
  return r.rows;
}

async function reviewWithdrawal(withdrawalId, status, adminId=null, note='') {
  if (!['approved','rejected'].includes(status)) throw new Error('Invalid withdrawal status');
  if (!hasDatabase()) return withFallbackFinancialLock(async()=>{
    const snapshot=snapshotFallbackFinancialFiles();
    try {
      const withdrawals=fallbackWithdrawalsRead(); const d=withdrawals.find(x=>String(x.id)===String(withdrawalId)); if(!d) throw new Error('Withdrawal পাওয়া যায়নি');
      if(d.status!=='pending') throw new Error('এই Withdrawal ইতিমধ্যে review করা হয়েছে');
      const users=fallbackUsersRead(); const u=users.find(x=>String(x.id)===String(d.user_id)); if(!u) throw new Error('User not found');
      const key=d.balance_type==='gaming'?'gaming_balance':'winning_balance'; const current=Number(u[key]||0);
      let before=current,after=current,change=0;
      if(status==='rejected'){before=current;after=Number((current+Number(d.amount)).toFixed(2));u[key]=after;change=Number(d.amount);}
      d.status=status; d.note=note; d.reviewed_by=adminId; d.reviewed_at=new Date().toISOString(); d.balance_after=after;
      fallbackUsersWrite(users); fallbackWithdrawalsWrite(withdrawals);
      const txs=fallbackTransactionsRead(); const tx=txs.find(x=>String(x.reference)==='WDR-'+d.id&&String(x.status)==='pending'); if(!tx) throw new Error('Withdrawal transaction record not found');
      tx.status=status==='approved'?'completed':'rejected'; tx.note=note||(status==='approved'?'Withdrawal approved':'Withdrawal rejected'); tx.balance_before=before; tx.balance_after=after; tx.balance_change=change; fallbackTransactionsWrite(txs);
      const notes=fallbackNotificationsRead(); notes.unshift({id:Date.now()+Math.random(),user_id:d.user_id,title:status==='approved'?'Withdrawal Approved':'Withdrawal Rejected',message:status==='approved'?('আপনার ৳'+Number(d.amount).toFixed(2)+' Withdrawal request approved হয়েছে।'):('আপনার Withdrawal requestটি বাতিল করা হয়েছে এবং ৳'+Number(d.amount).toFixed(2)+' Balance-এ ফেরত দেওয়া হয়েছে।'+(note?' কারণ: '+note:'')),read_at:null,created_at:d.reviewed_at}); fallbackNotificationsWrite(notes);
      return d;
    }catch(e){restoreFallbackFinancialFiles(snapshot);throw e;}
  });
  await init(); const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const q=await client.query('SELECT w.*,u.user_code FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.id=$1 FOR UPDATE',[withdrawalId]); if(!q.rows[0]) throw new Error('Withdrawal পাওয়া যায়নি');
    const d=q.rows[0]; if(d.status!=='pending') throw new Error('এই Withdrawal ইতিমধ্যে review করা হয়েছে');
    await client.query('UPDATE withdrawals SET status=$1,reviewed_by=$2,reviewed_at=NOW(),note=$3 WHERE id=$4',[status,adminId,note,withdrawalId]);
    const col=d.balance_type==='gaming'?'gaming_balance':'winning_balance';
    const wb=await client.query(`SELECT ${col} AS balance FROM wallets WHERE user_id=$1 FOR UPDATE`,[d.user_id]);
    const current=Number(wb.rows[0]?.balance||0);
    if(status==='rejected'){
      const after=Number((current+Number(d.amount)).toFixed(2));
      await client.query(`UPDATE wallets SET ${col}=$1,updated_at=NOW() WHERE user_id=$2`,[after,d.user_id]);
      const txr=await client.query('UPDATE transactions SET status=\'rejected\',note=$1,balance_before=$2,balance_after=$3,balance_change=$4 WHERE user_id=$5 AND reference=$6 AND type=\'withdrawal\' AND status=\'pending\'',[note||'Withdrawal rejected',current,after,Number(d.amount),d.user_id,'WDR-'+d.id]);
      if(txr.rowCount!==1) throw new Error('Withdrawal transaction record not found');
      await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[d.user_id,'Withdrawal Rejected','আপনার Withdrawal requestটি বাতিল করা হয়েছে এবং ৳'+Number(d.amount).toFixed(2)+' Balance-এ ফেরত দেওয়া হয়েছে।'+(note?' কারণ: '+note:'')]);
    } else {
      const txr=await client.query('UPDATE transactions SET status=\'completed\',note=$1 WHERE user_id=$2 AND reference=$3 AND type=\'withdrawal\' AND status=\'pending\'',[note||'Withdrawal approved',d.user_id,'WDR-'+d.id]);
      if(txr.rowCount!==1) throw new Error('Withdrawal transaction record not found');
      await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[d.user_id,'Withdrawal Approved','আপনার ৳'+Number(d.amount).toFixed(2)+' Withdrawal request approved হয়েছে।']);
    }
    await client.query('COMMIT'); return {...d,status,note,reviewed_at:new Date().toISOString()};
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
async function getAdminId(username) {
  if (!hasDatabase()) return null;
  await init(); const r=await pool.query('SELECT id FROM admins WHERE username=$1',[username]); return r.rows[0]?.id||null;
}

async function listUserTransactions(userId, limit=100) {
  if (!hasDatabase()) {
    const users=fallbackUsersRead(); const u=users.find(x=>String(x.id)===String(userId));
    return fallbackTransactionsRead().filter(t=>String(t.user_id)===String(userId)).slice(0,limit).map(t=>({...t,user_code:t.user_code||u?.user_code||''}));
  }
  await init();
  const r=await pool.query(`SELECT id,type,amount,balance_type,reference,status,note,balance_before,balance_after,balance_change,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`,[userId,limit]);
  return r.rows;
}
async function listAdminTransactions(limit=200) {
  if (!hasDatabase()) {
    const users=fallbackUsersRead(); const map=new Map(users.map(u=>[String(u.id),u]));
    return fallbackTransactionsRead().slice(0,limit).map(t=>({...t,user_code:t.user_code||map.get(String(t.user_id))?.user_code||'',phone:map.get(String(t.user_id))?.phone||'',name:map.get(String(t.user_id))?.name||''}));
  }
  await init();
  const r=await pool.query(`SELECT t.id,t.user_id,u.user_code,u.phone,u.name,t.type,t.amount,t.balance_type,t.reference,t.status,t.note,t.balance_before,t.balance_after,t.balance_change,t.created_at FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC,t.id DESC LIMIT $1`,[limit]);
  return r.rows;
}

module.exports = { init, getData, saveData, hasDatabase, findUser, findUserByEmail, createUser, createUserByEmail, setUserOtp, setUserOtpByEmail, updateOtpAttempts, updateOtpAttemptsByEmail, clearUserOtp, clearUserOtpByEmail, updateUserName, getUserById, getUserDashboard, ensureUserWallet, createDeposit, listUserDeposits, listAdminDeposits, reviewDeposit, createWithdrawal, listUserWithdrawals, listAdminWithdrawals, reviewWithdrawal, listUserTransactions, listAdminTransactions, getAdminId };

// ===== Ludo Baji feature-complete extensions (Steps 3-35) =====
async function listUsers(limit=500, q='') {
  if (!hasDatabase()) { let a=fallbackUsersRead(); q=String(q||'').toLowerCase(); if(q)a=a.filter(u=>[u.user_code,u.email,u.phone,u.name].some(v=>String(v||'').toLowerCase().includes(q))); return a.slice(-limit).reverse().map(u=>({id:u.id,user_code:u.user_code,email:u.email||'',phone:u.phone||null,name:u.name||'',status:u.status||'active',gaming_balance:Number(u.gaming_balance||0),winning_balance:Number(u.winning_balance||0),created_at:u.created_at})); }
  await init(); const r=await pool.query(`SELECT u.id,u.user_code,u.email,u.phone,u.name,u.status,u.created_at,COALESCE(w.gaming_balance,0) gaming_balance,COALESCE(w.winning_balance,0) winning_balance FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE ($1='' OR u.user_code ILIKE '%'||$1||'%' OR COALESCE(u.email,'') ILIKE '%'||$1||'%' OR COALESCE(u.phone,'') ILIKE '%'||$1||'%' OR COALESCE(u.name,'') ILIKE '%'||$1||'%') ORDER BY u.created_at DESC LIMIT $2`,[String(q||''),limit]); return r.rows;
}
async function setUserStatus(id,status){
  status=status==='blocked'?'blocked':'active'; if(!hasDatabase()){const a=fallbackUsersRead(),u=a.find(x=>String(x.id)===String(id));if(!u)throw new Error('User not found');u.status=status;fallbackUsersWrite(a);return u;} await init();const r=await pool.query('UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,user_code,email,phone,name,status,created_at',[status,id]);if(!r.rows[0])throw new Error('User not found');return r.rows[0];
}
async function adjustBalance(id,balanceType,amount,note='Admin balance adjustment'){
  balanceType=balanceType==='gaming'?'gaming':'winning'; amount=Number(amount); if(!Number.isFinite(amount)||amount===0||Math.abs(amount)>999999999999.99)throw new Error('Invalid amount'); amount=Number(amount.toFixed(2));
  if(!hasDatabase()) return withFallbackFinancialLock(async()=>{const snapshot=snapshotFallbackFinancialFiles();try{const a=fallbackUsersRead(),u=a.find(x=>String(x.id)===String(id));if(!u)throw new Error('User not found');const key=balanceType+'_balance',before=Number(u[key]||0),after=Number((before+amount).toFixed(2));if(after<0)throw new Error('Balance cannot be negative');u[key]=after;fallbackUsersWrite(a);const txs=fallbackTransactionsRead(),ref='ADJ-'+Date.now()+'-'+Math.random().toString(36).slice(2,8);txs.unshift({id:ref,user_id:u.id,type:'balance_adjustment',amount:Math.abs(amount),balance_type:balanceType,reference:ref,status:'completed',note,balance_before:before,balance_after:after,balance_change:amount,created_at:new Date().toISOString()});fallbackTransactionsWrite(txs);return {before,after,change:amount};}catch(e){restoreFallbackFinancialFiles(snapshot);throw e;}});
  await init();const c=await pool.connect();try{await c.query('BEGIN');const ur=await c.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[id]);if(!ur.rows[0])throw new Error('User not found');await c.query('INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT DO NOTHING',[id]);const col=balanceType+'_balance';const w=await c.query(`SELECT ${col} balance FROM wallets WHERE user_id=$1 FOR UPDATE`,[id]);const before=Number(w.rows[0]?.balance||0),after=Number((before+amount).toFixed(2));if(after<0)throw new Error('Balance cannot be negative');await c.query(`UPDATE wallets SET ${col}=$1,updated_at=NOW() WHERE user_id=$2`,[after,id]);const ref='ADJ-'+Date.now()+'-'+Math.random().toString(36).slice(2,8);await c.query(`INSERT INTO transactions(user_id,type,amount,balance_type,reference,status,note,balance_before,balance_after,balance_change) VALUES($1,'balance_adjustment',$2,$3,$4,'completed',$5,$6,$7,$8)`,[id,Math.abs(amount),balanceType,ref,note,before,after,amount]);await c.query('COMMIT');return {before,after,change:amount};}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}
async function notifyUser(userId,title,message){const item={id:Date.now()+Math.random(),user_id:userId,title,message,read_at:null,created_at:new Date().toISOString()};if(!hasDatabase()){const a=fallbackNotificationsRead();a.unshift(item);fallbackNotificationsWrite(a);return item;}await init();const r=await pool.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3) RETURNING *',[userId,title,message]);return r.rows[0];}
async function createFeatureMatch(x){
  const d=await getData();d.matches=Array.isArray(d.matches)?d.matches:[];
  const serial=d.matches.length+1;
  let title=String(x.title||'').trim();
  if(!title) title='Special Match~~~~'+serial;
  else if(/^\d+$/.test(title)) title='Special Match~~~~'+title;
  const item={id:'M-'+Date.now()+Math.random().toString(36).slice(2,5),match_code:String(x.match_code||('LB'+Date.now())).toUpperCase(),title,entry_fee:Number(x.entry_fee||0),winning_amount:Number(x.winning_amount||0),max_players:2,scheduled_at:x.scheduled_at||new Date().toISOString(),status:x.status||'open',room_id:String(x.room_id||'').trim(),room_password:String(x.room_password||''),rules:String(x.rules||'').trim()||'সিট ফুল হলে রুম আইডি দেওয়া হবে',players:[],winner_user_id:null,prize_status:'pending',result_submissions:[],created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
  if(!item.title||item.entry_fee<0||item.winning_amount<0||!Number.isFinite(item.entry_fee)||!Number.isFinite(item.winning_amount))throw new Error('Invalid match data');
  item.entry_fee=Number(item.entry_fee.toFixed(2)); item.winning_amount=Number(item.winning_amount.toFixed(2));
  d.matches.unshift(item);await saveData(d);return item;
}
async function listFeatureMatches(status='all'){const d=await getData();let a=Array.isArray(d.matches)?d.matches:[];a=a.map(x=>{const players=Array.isArray(x.players)?x.players:[];const raw=String(x.status||'open').toLowerCase();const derived=['started','completed','cancelled'].includes(raw)?raw:(players.length>=2?'full':'open');return {...x,status:derived,players}});if(status!=='all')a=a.filter(x=>x.status===status);return a;}
async function getFeatureMatch(id){const a=await listFeatureMatches('all');return a.find(x=>String(x.id)===String(id)||String(x.match_code)===String(id))||null;}
async function updateFeatureMatch(id,x){const d=await getData();d.matches=Array.isArray(d.matches)?d.matches:[];const m=d.matches.find(a=>String(a.id)===String(id));if(!m)throw new Error('Match not found');if(String(x.status||'')==='started' && (!Array.isArray(m.players)||m.players.length<2))throw new Error('2 জন player join না হলে Match START করা যাবে না');Object.assign(m,{title:String(x.title??m.title),entry_fee:Number(x.entry_fee??m.entry_fee),winning_amount:Number(x.winning_amount??m.winning_amount),max_players:2,scheduled_at:x.scheduled_at??m.scheduled_at,rules:String((x.rules??m.rules)??''),status:String(x.status??m.status),room_id:String((x.room_id??m.room_id)??''),room_password:String((x.room_password??m.room_password)??''),updated_at:new Date().toISOString()});await saveData(d);return m;}
async function joinFeatureMatch(matchId,userId){return withFeatureMatchLock(async()=>{const d=await getData();d.matches=Array.isArray(d.matches)?d.matches:[];const m=d.matches.find(a=>String(a.id)===String(matchId));if(!m)throw new Error('Match not found');m.players=Array.isArray(m.players)?m.players:[];if(m.status!=='open')throw new Error('Match is not open');if(m.players.some(p=>String(p.user_id)===String(userId)))throw new Error('Already joined');if(m.players.length>=Number(m.max_players))throw new Error('Match is full');if(m.players.length===1&&!String(m.room_id||'').trim())throw new Error('Admin আগে Ludo King Room Code সেট করুন');const bal=await getUserDashboard(userId);if(Number(bal.gaming_balance||0)<Number(m.entry_fee))throw new Error('Gaming Balance insufficient');if(Number(m.entry_fee)>0){ await adjustBalance(userId,'gaming',-Number(m.entry_fee),'Match entry fee '+m.match_code); creditAdminEntry(d,m,userId,Number(m.entry_fee)); }const slot=m.players.length+1;m.players.push({user_id:userId,slot,status:'joined',joined_at:new Date().toISOString()});if(m.players.length>=Number(m.max_players))m.status='full';await saveData(d);if(m.players.length<2)await notifyUser(userId,'Match Joined','আপনি '+m.title+' match-এ Slot '+slot+' এ join করেছেন।');const tx=fallbackTransactionsRead();tx.unshift({id:'ENTRY-'+Date.now(),user_id:userId,type:'match_entry',amount:Number(m.entry_fee),balance_type:'gaming',reference:'ENTRY-'+m.match_code,status:'completed',note:'Joined '+m.title,balance_before:null,balance_after:null,balance_change:-Number(m.entry_fee),created_at:new Date().toISOString()});if(!hasDatabase())fallbackTransactionsWrite(tx);return {match:m,slot};});}
async function setFeatureRoom(id,roomId,password){return updateFeatureMatch(id,{room_id:roomId,room_password:password});}
async function setFeatureWinner(id,userId){return withFeatureMatchLock(async()=>{const d=await getData();d.matches=Array.isArray(d.matches)?d.matches:[];const m=d.matches.find(a=>String(a.id)===String(id));if(!m)throw new Error('Match not found');if(!m.players.some(p=>String(p.user_id)===String(userId)))throw new Error('Winner must be a joined player');m.winner_user_id=String(userId);m.status='completed';m.prize_status='pending';m.updated_at=new Date().toISOString();await saveData(d);await notifyUser(userId,'Match Result','আপনার '+m.title+' match-এর result প্রকাশিত হয়েছে।');return m;});}


function ensureFinance(d){
  if(!d.finance || typeof d.finance!=='object') d.finance={};
  const f=d.finance;
  // Admin Account Wallet (holds match entry pool; profit stays after prize paid)
  f.balance=Number(f.balance!=null?f.balance:(f.commission_balance||0));
  f.total_profit=Number(f.total_profit!=null?f.total_profit:(f.total_commission_earned||0));
  f.total_collected=Number(f.total_collected||0);
  f.total_paid_prizes=Number(f.total_paid_prizes||0);
  f.commission_balance=f.balance; // alias for old UI
  f.total_commission_earned=f.total_profit;
  f.commission_log=Array.isArray(f.commission_log)?f.commission_log:[];
  f.log=Array.isArray(f.log)?f.log:f.commission_log;
  return f;
}
function pushFinanceLog(fin, row){
  fin.log=Array.isArray(fin.log)?fin.log:[];
  fin.commission_log=fin.log;
  fin.log.unshift(row);
  if(fin.log.length>500) fin.log=fin.log.slice(0,500);
}
/** Player join → Entry Fee Admin Account-এ জমা */
function creditAdminEntry(d, m, userId, amount){
  const fin=ensureFinance(d);
  const amt=Number(amount||0);
  if(!(amt>0)) return 0;
  fin.balance=Number((fin.balance+amt).toFixed(2));
  fin.total_collected=Number((fin.total_collected+amt).toFixed(2));
  fin.commission_balance=fin.balance;
  pushFinanceLog(fin,{
    id:'IN-'+Date.now()+Math.random().toString(36).slice(2,5),
    type:'match_entry',
    match_id:m.id,
    match_code:m.match_code||'',
    title:m.title||'',
    user_id:String(userId),
    amount:amt,
    balance_after:fin.balance,
    note:'Match entry received',
    created_at:new Date().toISOString()
  });
  return amt;
}
/**
 * Prize approve:
 * - Winner gets only winning amount
 * - Admin Account থেকে prize কাটে
 * - বাকিটাই লাভ (আগেই entry দিয়ে এসেছিল)
 */
function settleAdminPrize(d, m){
  const fin=ensureFinance(d);
  if(m.commission_credited || m.prize_settled){
    return {prize:Number(m.winning_amount||0), profit:Number(m.commission_amount||0)};
  }
  const players=Array.isArray(m.players)?m.players.length:0;
  const entry=Number(m.entry_fee||0);
  const prize=Number(m.winning_amount||0);
  const pool=Number((entry*Math.max(players,0)).toFixed(2));
  const profit=Number((pool-prize).toFixed(2));
  // Debit prize from Admin Account (entries were already credited on join)
  fin.balance=Number((fin.balance-prize).toFixed(2));
  fin.total_paid_prizes=Number((fin.total_paid_prizes+prize).toFixed(2));
  if(profit>0) fin.total_profit=Number((fin.total_profit+profit).toFixed(2));
  fin.commission_balance=fin.balance;
  fin.total_commission_earned=fin.total_profit;
  m.pool_collected=pool;
  m.commission_amount=profit;
  m.commission_credited=true;
  m.prize_settled=true;
  pushFinanceLog(fin,{
    id:'OUT-'+Date.now()+Math.random().toString(36).slice(2,5),
    type:'prize_paid',
    match_id:m.id,
    match_code:m.match_code||'',
    title:m.title||'',
    amount:-prize,
    prize:prize,
    pool:pool,
    profit:profit,
    balance_after:fin.balance,
    note:'Prize paid to winner; profit kept in Admin Account',
    created_at:new Date().toISOString()
  });
  if(profit!==0){
    pushFinanceLog(fin,{
      id:'PF-'+Date.now()+Math.random().toString(36).slice(2,5),
      type:'profit',
      match_id:m.id,
      match_code:m.match_code||'',
      title:m.title||'',
      amount:profit,
      pool:pool,
      prize:prize,
      commission:profit,
      balance_after:fin.balance,
      note:'Match profit retained',
      created_at:new Date().toISOString()
    });
  }
  return {prize, profit, pool};
}
/** old name kept for compatibility */
function creditMatchCommission(d,m){
  const r=settleAdminPrize(d,m);
  return r.profit;
}
async function getAdminFinance(){
  const d=await getData();
  const fin=ensureFinance(d);
  return {
    balance:Number(fin.balance||0),
    total_profit:Number(fin.total_profit||0),
    total_collected:Number(fin.total_collected||0),
    total_paid_prizes:Number(fin.total_paid_prizes||0),
    commission_balance:Number(fin.balance||0),
    total_commission_earned:Number(fin.total_profit||0),
    commission_log:(fin.log||fin.commission_log||[]).slice(0,100),
    log:(fin.log||[]).slice(0,100),
    admin_withdrawals:Array.isArray(fin.admin_withdrawals)?fin.admin_withdrawals.slice(0,100):[]
  };
}

/** Match cancel → Admin Account থেকে Entry Fee ফেরত (users-কে refund হয়েছে) */
function debitAdminEntriesOnCancel(d, m){
  const fin=ensureFinance(d);
  const entry=Number(m.entry_fee||0);
  const players=Array.isArray(m.players)?m.players:[];
  if(!(entry>0) || !players.length) return 0;
  let total=0;
  for(const pl of players){
    const amt=entry;
    total+=amt;
    fin.balance=Number((fin.balance-amt).toFixed(2));
    fin.total_collected=Number((Math.max(0,fin.total_collected-amt)).toFixed(2));
    fin.commission_balance=fin.balance;
    pushFinanceLog(fin,{
      id:"RF-"+Date.now()+Math.random().toString(36).slice(2,5),
      type:"match_cancel_refund",
      match_id:m.id,
      match_code:m.match_code||"",
      title:m.title||"",
      user_id:String(pl.user_id||""),
      amount:-amt,
      balance_after:fin.balance,
      note:"Match cancelled — entry returned from Admin Account",
      created_at:new Date().toISOString()
    });
  }
  return total;
}

/**
 * Admin নিজের লাভের টাকা তুলতে পারবে (bKash / Nagad / Rocket)
 * সরাসরি Admin Account Balance থেকে কেটে নেয় এবং লগ রাখে।
 */
async function adminWithdraw(method, accountNumber, amount, note){
  const d=await getData();
  const fin=ensureFinance(d);
  const amt=Number(amount||0);
  const meth=String(method||"").trim().toLowerCase();
  const acc=String(accountNumber||"").trim();
  if(!["bkash","nagad","rocket"].includes(meth)) throw new Error("Method হতে হবে bKash, Nagad বা Rocket");
  if(!acc || acc.length<8) throw new Error("সঠিক Account Number দিন");
  if(!Number.isFinite(amt) || amt<=0) throw new Error("সঠিক Amount দিন");
  if(amt > Number(fin.balance||0)) throw new Error("Admin Account Balance অপর্যাপ্ত (৳"+Number(fin.balance||0).toFixed(2)+")");
  fin.balance=Number((fin.balance-amt).toFixed(2));
  fin.commission_balance=fin.balance;
  const row={
    id:"AW-"+Date.now()+Math.random().toString(36).slice(2,6),
    type:"admin_withdraw",
    method:meth,
    account_number:acc,
    amount:amt,
    note:String(note||"").trim()||"Admin profit withdrawal",
    balance_after:fin.balance,
    status:"completed",
    created_at:new Date().toISOString()
  };
  fin.admin_withdrawals=Array.isArray(fin.admin_withdrawals)?fin.admin_withdrawals:[];
  fin.admin_withdrawals.unshift(row);
  if(fin.admin_withdrawals.length>200) fin.admin_withdrawals=fin.admin_withdrawals.slice(0,200);
  pushFinanceLog(fin,{
    id:row.id,
    type:"admin_withdraw",
    method:meth,
    account_number:acc,
    amount:-amt,
    balance_after:fin.balance,
    note:row.note,
    created_at:row.created_at
  });
  await saveData(d);
  return row;
}

async function approveFeaturePrize(id){return withFeatureMatchLock(async()=>{const d=await getData();d.matches=Array.isArray(d.matches)?d.matches:[];const m=d.matches.find(a=>String(a.id)===String(id));if(!m||!m.winner_user_id)throw new Error('Winner not selected');if(m.prize_status==='approved')throw new Error('Prize already approved');if(!Number.isFinite(Number(m.winning_amount))||Number(m.winning_amount)<0)throw new Error('Invalid prize amount');await adjustBalance(m.winner_user_id,'winning',Number(m.winning_amount),'Prize for '+m.match_code);m.prize_status='approved';const commission=creditMatchCommission(d,m);m.updated_at=new Date().toISOString();await saveData(d);await notifyUser(m.winner_user_id,'Prize Credited','আপনার ৳'+Number(m.winning_amount).toFixed(2)+' prize Winning Balance-এ যোগ হয়েছে।');return {...m,commission_amount:commission};});}

async function submitFeatureResult(id,userId,screenshot){
  return withFeatureMatchLock(async()=>{
    const d=await getData(); d.matches=Array.isArray(d.matches)?d.matches:[];
    const m=d.matches.find(a=>String(a.id)===String(id));
    if(!m) throw new Error('Match not found');
    if(!Array.isArray(m.players)||!m.players.some(p=>String(p.user_id)===String(userId))) throw new Error('You have not joined this match');
    if(m.players.length<2) throw new Error('Match is not full yet');
    if(m.status!=='started' && m.status!=='full') throw new Error('Match result submission is not available yet');
    if(m.winner_user_id) throw new Error('Winner already selected');
    const s=String(screenshot||'');
    if(!/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(s)) throw new Error('Valid screenshot upload করুন');
    const comma=s.indexOf(',');
    const bytes=comma>0?Buffer.byteLength(s.slice(comma+1),'base64'):0;
    if(bytes>8*1024*1024) throw new Error('Screenshot সর্বোচ্চ 8MB হতে পারবে');
    m.result_submissions=Array.isArray(m.result_submissions)?m.result_submissions:[];
    const existing=m.result_submissions.find(x=>String(x.user_id)===String(userId));
    const item={id:existing?.id||('RS-'+Date.now()+Math.random().toString(36).slice(2,6)),user_id:String(userId),screenshot:s,status:'pending',submitted_at:new Date().toISOString(),review_note:''};
    if(existing) Object.assign(existing,item); else m.result_submissions.push(item);
    m.updated_at=new Date().toISOString();
    await saveData(d);
    await notifyUser(userId,'Result Screenshot Submitted','আপনার match result screenshot Admin-এর verification-এর জন্য জমা হয়েছে।');
    return item;
  });
}
async function approveFeatureResult(id,userId){
  return withFeatureMatchLock(async()=>{
    const d=await getData(); d.matches=Array.isArray(d.matches)?d.matches:[];
    const m=d.matches.find(a=>String(a.id)===String(id));
    if(!m) throw new Error('Match not found');
    const sub=(m.result_submissions||[]).find(x=>String(x.user_id)===String(userId));
    if(!sub) throw new Error('Result screenshot not found');
    if(sub.status==='approved' || m.winner_user_id) throw new Error('Winner already approved');
    if(!m.players.some(p=>String(p.user_id)===String(userId))) throw new Error('Winner must be a joined player');
    m.winner_user_id=String(userId); m.status='completed'; m.prize_status='approved';
    sub.status='approved'; sub.reviewed_at=new Date().toISOString(); sub.review_note='';
    await adjustBalance(m.winner_user_id,'winning',Number(m.winning_amount),'Prize for '+m.match_code);
    creditMatchCommission(d,m);
    m.updated_at=new Date().toISOString();
    await saveData(d);
    await notifyUser(m.winner_user_id,'Prize Credited','আপনার ৳'+Number(m.winning_amount).toFixed(2)+' prize Winning Balance-এ যোগ হয়েছে।');
    return m;
  });
}
async function rejectFeatureResult(id,userId,note){
  return withFeatureMatchLock(async()=>{
    const d=await getData(); d.matches=Array.isArray(d.matches)?d.matches:[];
    const m=d.matches.find(a=>String(a.id)===String(id));
    if(!m) throw new Error('Match not found');
    const sub=(m.result_submissions||[]).find(x=>String(x.user_id)===String(userId));
    if(!sub) throw new Error('Result screenshot not found');
    if(m.winner_user_id) throw new Error('Winner already approved');
    sub.status='rejected'; sub.reviewed_at=new Date().toISOString(); sub.review_note=String(note||'Screenshot rejected');
    m.updated_at=new Date().toISOString();
    await saveData(d);
    await notifyUser(userId,'Result Screenshot Rejected',sub.review_note+' — আবার screenshot জমা দিন।');
    return m;
  });
}

async function listUserFeatureMatches(userId){const a=await listFeatureMatches('all');return a.filter(m=>m.players.some(p=>String(p.user_id)===String(userId))).map(m=>({...m,my_slot:m.players.find(p=>String(p.user_id)===String(userId))?.slot}));}
async function listNotifications(userId,limit=100){if(!hasDatabase()){return fallbackNotificationsRead().filter(n=>String(n.user_id)===String(userId)).slice(0,limit)}await init();const r=await pool.query('SELECT id,title,message,read_at,created_at FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',[userId,limit]);return r.rows;}
async function markNotificationsRead(userId,id){if(!hasDatabase()){const a=fallbackNotificationsRead();a.forEach(n=>{if(String(n.user_id)===String(userId)&&(id==='all'||String(n.id)===String(id)))n.read_at=new Date().toISOString()});fallbackNotificationsWrite(a);return true;}await init();if(id==='all')await pool.query('UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL',[userId]);else await pool.query('UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND id=$2',[userId,id]);return true;}
async function supportList(userId){if(!hasDatabase())return fallbackSupportRead().filter(x=>String(x.user_id)===String(userId));await init();const r=await pool.query('SELECT id,user_id,sender,message,created_at FROM support_messages WHERE user_id=$1 ORDER BY created_at ASC',[userId]);return r.rows;}
async function supportSend(userId,sender,message){message=String(message||'').trim();if(!message||message.length>2000)throw new Error('Message required');if(!hasDatabase()){const a=fallbackSupportRead();a.push({id:Date.now(),user_id:userId,sender,message,created_at:new Date().toISOString()});fallbackSupportWrite(a);return a[a.length-1];}await init();const r=await pool.query('INSERT INTO support_messages(user_id,sender,message) VALUES($1,$2,$3) RETURNING *',[userId,sender,message]);return r.rows[0];}
async function adminSupport(limit=300){if(!hasDatabase())return fallbackSupportRead().slice(-limit).reverse();await init();const r=await pool.query('SELECT s.*,u.user_code,u.email,u.phone,u.name FROM support_messages s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT $1',[limit]);return r.rows;}
function fallbackSupportRead(){try{return JSON.parse(fs.readFileSync(SUPPORT_DATA,'utf8'))}catch{return []}}
function fallbackSupportWrite(items){const tmp=SUPPORT_DATA+'.tmp';fs.writeFileSync(tmp,JSON.stringify(items,null,2),'utf8');fs.renameSync(tmp,SUPPORT_DATA)}
async function getUserAdminDetail(userId, limit=200){
  const user=await getUserById(userId); if(!user) return null;
  const dashboard=await getUserDashboard(userId) || {gaming_balance:0,winning_balance:0,joined_matches:0,notifications:0};
  const [transactions,deposits,withdrawals,matches,notifications,support]=await Promise.all([
    listUserTransactions(userId,limit),
    hasDatabase()? (async()=>{await init();const r=await pool.query('SELECT id,method,amount,transaction_id,screenshot,status,created_at,reviewed_at FROM deposits WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',[userId,limit]);return r.rows})():Promise.resolve(fallbackDepositsRead().filter(x=>String(x.user_id)===String(userId)).slice(0,limit)),
    hasDatabase()? (async()=>{await init();const r=await pool.query('SELECT id,method,account_number,account_name,amount,balance_type,status,note,created_at,reviewed_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2',[userId,limit]);return r.rows})():Promise.resolve(fallbackWithdrawalsRead().filter(x=>String(x.user_id)===String(userId)).slice(0,limit)),
    listUserFeatureMatches(userId),
    listNotifications(userId,limit),
    supportList(userId)
  ]);
  return {user,dashboard,transactions,deposits,withdrawals,matches,notifications,support};
}
module.exports={...module.exports,notifyUser,listUsers,setUserStatus,adjustBalance,createFeatureMatch,listFeatureMatches,getFeatureMatch,updateFeatureMatch,joinFeatureMatch,setFeatureRoom,setFeatureWinner,approveFeaturePrize,submitFeatureResult,approveFeatureResult,rejectFeatureResult,listUserFeatureMatches,listNotifications,markNotificationsRead,supportList,supportSend,adminSupport,getUserAdminDetail,getAdminFinance,adminWithdraw,debitAdminEntriesOnCancel};
