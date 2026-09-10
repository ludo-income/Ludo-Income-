const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_JWT_SECRET";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

const defaultDb = {
  settings: {
    siteName: "Ludo Income",
    tagline: "Play. Compete. Enjoy.",
    notice: "Welcome to Ludo Income",
    support: "Support",
    primaryColor: "#6d28d9",
    showNotice: true,
    maintenance: false
  },
  matches: [],
  adminPasswordHash: null
};

function loadDb() {
  try {
    return { ...defaultDb, ...JSON.parse(fs.readFileSync(DB_FILE, "utf8")) };
  } catch {
    saveDb(defaultDb);
    return defaultDb;
  }
}
function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function adminEmail() {
  return String(process.env.ADMIN_EMAIL || "admin@example.com").trim().toLowerCase();
}
async function verifyPassword(password) {
  const db = loadDb();
  if (db.adminPasswordHash) return bcrypt.compare(password, db.adminPasswordHash);
  const initial = String(process.env.ADMIN_PASSWORD || "ChangeThisPassword123!");
  return password === initial;
}
function makeToken(email) {
  return jwt.sign({ email, role: "superadmin" }, JWT_SECRET, { expiresIn: "12h" });
}
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session expired" });
  }
}

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/admin/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email !== adminEmail() || !(await verifyPassword(password))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  res.json({ token: makeToken(email), admin: { email, role: "Super Admin" } });
});

app.get("/api/site", (req, res) => {
  const db = loadDb();
  res.json({ settings: db.settings, matches: db.matches });
});

app.get("/api/admin/settings", auth, (req, res) => {
  res.json(loadDb().settings);
});

app.put("/api/admin/settings", auth, (req, res) => {
  const db = loadDb();
  const allowed = ["siteName","tagline","notice","support","primaryColor","showNotice","maintenance"];
  for (const key of allowed) {
    if (req.body[key] !== undefined) db.settings[key] = req.body[key];
  }
  saveDb(db);
  res.json({ ok: true, settings: db.settings });
});

app.post("/api/admin/password", auth, async (req, res) => {
  const current = String(req.body.currentPassword || "");
  const next = String(req.body.newPassword || "");
  if (next.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });

  if (!(await verifyPassword(current))) {
    return res.status(400).json({ error: "Current password is incorrect" });
  }

  const db = loadDb();
  db.adminPasswordHash = await bcrypt.hash(next, 12);
  saveDb(db);
  res.json({ ok: true, message: "Password changed. Please log in again." });
});

app.get("/api/admin/matches", auth, (req, res) => {
  res.json(loadDb().matches);
});

app.post("/api/admin/matches", auth, (req, res) => {
  const db = loadDb();
  const match = {
    id: String(req.body.id || ("LD" + Date.now())),
    name: String(req.body.name || "").trim(),
    time: String(req.body.time || "").trim(),
    players: String(req.body.players || "2 Players").trim(),
    status: String(req.body.status || "Open").trim()
  };
  if (!match.name) return res.status(400).json({ error: "Match name required" });
  db.matches.unshift(match);
  saveDb(db);
  res.json({ ok: true, match });
});

app.delete("/api/admin/matches/:id", auth, (req, res) => {
  const db = loadDb();
  const before = db.matches.length;
  db.matches = db.matches.filter(m => m.id !== req.params.id);
  if (db.matches.length === before) return res.status(404).json({ error: "Match not found" });
  saveDb(db);
  res.json({ ok: true });
});

/* IMPORTANT: /admin is handled before the public fallback. */
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin", "index.html")));
app.get("/admin/", (req, res) => res.sendFile(path.join(__dirname, "admin", "index.html")));
app.use("/admin", express.static(path.join(__dirname, "admin")));

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log("Ludo Income server running on port " + PORT);
  console.log("Admin route: /admin");
});
