require("dotenv").config();
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const { CLIENT_ID, CLIENT_SECRET, BOT_TOKEN, SESSION_SECRET, OWNER_ID } = process.env;
const BASE_URL = (process.env.BASE_URL || "http://localhost:3000").replace(/\/$/, "");
const PORT = process.env.PORT || 3000;
const API = "https://discord.com/api/v10";
const REDIRECT = `${BASE_URL}/auth/callback`;
for (const k of ["CLIENT_ID", "CLIENT_SECRET", "BOT_TOKEN", "SESSION_SECRET"]) {
  if (!process.env[k]) { console.error(`Variable manquante dans .env : ${k}`); process.exit(1); }
}

const db = new DatabaseSync(process.env.DB_PATH || "grok.db");
db.exec("PRAGMA journal_mode = WAL");
db.exec("CREATE TABLE IF NOT EXISTS guild_config (guild_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)");
// Tables alimentées par le bot Python (voir bot_stats.py) : tout démarre à zéro
db.exec("CREATE TABLE IF NOT EXISTS members (guild_id TEXT, user_id TEXT, username TEXT, avatar TEXT, xp INTEGER NOT NULL DEFAULT 0, messages INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (guild_id, user_id))");
db.exec("CREATE TABLE IF NOT EXISTS command_log (day TEXT, name TEXT, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, name))");
db.exec("CREATE TABLE IF NOT EXISTS daily_stats (day TEXT, guild_id TEXT, messages INTEGER NOT NULL DEFAULT 0, joins INTEGER NOT NULL DEFAULT 0, leaves INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, guild_id))");
db.exec("CREATE TABLE IF NOT EXISTS hourly (hour INTEGER PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)");
db.exec("CREATE TABLE IF NOT EXISTS guild_flags (guild_id TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0, blacklisted INTEGER NOT NULL DEFAULT 0)");
db.exec("CREATE TABLE IF NOT EXISTS broadcasts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT NOT NULL, created_at INTEGER NOT NULL, sent INTEGER NOT NULL DEFAULT 0)");
db.exec("CREATE TABLE IF NOT EXISTS site_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
db.exec("CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, key_hash TEXT NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER)");
db.exec("CREATE TABLE IF NOT EXISTS audit (ts INTEGER, who TEXT, action TEXT)");
db.exec("CREATE TABLE IF NOT EXISTS visits (ts INTEGER, day TEXT, vid TEXT, path TEXT, ref TEXT, dev TEXT, br TEXT, os TEXT, lang TEXT, country TEXT)");
db.exec("CREATE INDEX IF NOT EXISTS visits_ts ON visits(ts)");
const trackSeen = new Map();
const addVisit = v => db.prepare("INSERT INTO visits (ts, day, vid, path, ref, dev, br, os, lang, country) VALUES (?,?,?,?,?,?,?,?,?,?)").run(Date.now(), new Date().toISOString().slice(0, 10), v.vid, v.path, v.ref || "", v.dev || "", v.br || "", v.os || "", v.lang || "", v.country || "");
const parseUA = s => ({ br: /Edg\//.test(s) ? "Edge" : /OPR\/|Opera/.test(s) ? "Opera" : /Firefox/.test(s) ? "Firefox" : /Chrome/.test(s) ? "Chrome" : /Safari/.test(s) ? "Safari" : "Autre", os: /Android/.test(s) ? "Android" : /iPhone|iPad|iOS/.test(s) ? "iOS" : /Windows/.test(s) ? "Windows" : /Mac OS/.test(s) ? "macOS" : /Linux/.test(s) ? "Linux" : "Autre" });
const getCfg = db.prepare("SELECT data FROM guild_config WHERE guild_id = ?");
const setCfg = db.prepare("INSERT INTO guild_config (guild_id, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(guild_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "200kb" }));
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: BASE_URL.startsWith("https"), maxAge: 7 * 24 * 3600 * 1000 },
}));

const BOT = { Authorization: `Bot ${BOT_TOKEN}` };
const discord = async (url, headers, opts = {}) => {
  const r = await fetch(API + url, { ...opts, headers });
  if (!r.ok) throw new Error(`Discord ${r.status} sur ${url}`);
  return r.json();
};

// Serveurs où le bot est présent (cache 30 s) + nombre de membres (cache 5 min)
let botCache = { at: 0, ids: new Set(), list: [] };
async function botGuilds(force = false) {
  if (!force && Date.now() - botCache.at < 30000) return botCache.ids;
  const ids = new Set(), list = [];
  let after = "";
  for (;;) {
    const page = await discord(`/users/@me/guilds?limit=200${after}`, BOT);
    page.forEach(g => { ids.add(g.id); list.push({ id: g.id, name: g.name }); });
    if (page.length < 200) break;
    after = `&after=${page[page.length - 1].id}`;
  }
  botCache = { at: Date.now(), ids, list };
  return ids;
}
let cntCache = { at: 0, m: new Map() };
async function counts() {
  if (Date.now() - cntCache.at < 300000) return cntCache.m;
  const ids = [...await botGuilds()].slice(0, 100), m = new Map();
  await Promise.allSettled(ids.map(async id => {
    const g = await discord(`/guilds/${id}?with_counts=true`, BOT);
    m.set(id, g.approximate_member_count);
  }));
  cntCache = { at: Date.now(), m };
  return m;
}

const canManage = g => g.owner || (BigInt(g.permissions) & 0x8n) || (BigInt(g.permissions) & 0x20n); // ADMINISTRATOR ou MANAGE_GUILD
const mapGuilds = gs => gs.filter(canManage).map(g => ({ id: g.id, name: g.name, icon: g.icon }));

/* ---------- Connexion Discord (OAuth2) ---------- */
app.get("/auth/login", (req, res) => {
  req.session.state = crypto.randomBytes(16).toString("hex");
  const q = new URLSearchParams({ client_id: CLIENT_ID, response_type: "code", redirect_uri: REDIRECT, scope: "identify guilds", state: req.session.state });
  res.redirect(`https://discord.com/oauth2/authorize?${q}`);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.state) return res.redirect("/?error=state");
    delete req.session.state;
    const tok = await fetch(`${API}/oauth2/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: REDIRECT }),
    });
    if (!tok.ok) return res.redirect("/?error=token");
    const { access_token } = await tok.json();
    const h = { Authorization: `Bearer ${access_token}` };
    const [user, guilds] = await Promise.all([discord("/users/@me", h), discord("/users/@me/guilds", h)]);
    req.session.token = access_token;
    req.session.user = { id: user.id, username: user.username, global_name: user.global_name, avatar: user.avatar };
    req.session.guilds = mapGuilds(guilds);
    if (user.id !== OWNER_ID) addVisit({ vid: "u" + user.id, path: "event:login" });
    req.session.save(() => res.redirect("/#servers"));
  } catch (e) { console.error(e.message); res.redirect("/?error=auth"); }
});

app.get("/auth/logout", (req, res) => req.session.destroy(() => res.redirect("/")));
app.get("/auth/bot", (req, res) => { botCache.at = 0; cntCache.at = 0; res.redirect("/#servers"); }); // retour après l'ajout du bot

/* ---------- API ---------- */
const needLogin = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: "not_logged" });
const needGuild = (req, res, next) => (req.session.guilds || []).some(g => g.id === req.params.id) ? next() : res.status(403).json({ error: "forbidden" });
const needOwner = (req, res, next) => OWNER_ID && req.session.user && req.session.user.id === OWNER_ID ? next() : res.status(403).json({ error: "forbidden" });

app.get("/api/me", needLogin, async (req, res) => {
  if (req.query.refresh && req.session.token) { // recharge la liste des serveurs (ex. après ajout du bot)
    try { req.session.guilds = mapGuilds(await discord("/users/@me/guilds", { Authorization: `Bearer ${req.session.token}` })); } catch (e) { console.error(e.message); }
  }
  let bot = new Set(), cn = new Map();
  try { bot = await botGuilds(); cn = await counts(); } catch (e) { console.error(e.message); }
  res.json({
    user: req.session.user, clientId: CLIENT_ID,
    isOwner: !!OWNER_ID && req.session.user.id === OWNER_ID,
    guilds: req.session.guilds.map(g => ({ ...g, botIn: bot.has(g.id), members: cn.get(g.id) || null })),
  });
});

app.get("/api/guilds/:id/config", needLogin, needGuild, (req, res) => {
  const row = getCfg.get(req.params.id);
  res.json({ data: row ? JSON.parse(row.data) : {} });
});

app.get("/api/guilds/:id/meta", needLogin, needGuild, async (req, res) => { // salons et rôles réels du serveur
  try {
    const [ch, ro] = await Promise.all([discord(`/guilds/${req.params.id}/channels`, BOT), discord(`/guilds/${req.params.id}/roles`, BOT)]);
    res.json({
      channels: ch.sort((a, b) => a.position - b.position).map(c => ({ id: c.id, name: c.name, type: c.type })),
      roles: ro.filter(r => r.name !== "@everyone").sort((a, b) => b.position - a.position).map(r => ({ id: r.id, name: r.name })),
    });
  } catch (e) { res.status(502).json({ error: "discord" }); }
});

app.put("/api/guilds/:id/config", needLogin, needGuild, async (req, res) => {
  const cfg = req.body && req.body.config;
  if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) return res.status(400).json({ error: "bad_config" });
  try { if (!(await botGuilds()).has(req.params.id)) return res.status(409).json({ error: "bot_absent" }); } catch (e) { return res.status(502).json({ error: "discord" }); }
  setCfg.run(req.params.id, JSON.stringify(cfg), Date.now());
  res.json({ ok: true });
});

const audit = db.prepare("INSERT INTO audit (ts, who, action) VALUES (?, ?, ?)");
const log = (req, a) => audit.run(Date.now(), req.session.user ? req.session.user.username : "api", a);
const getSite = () => { const r = db.prepare("SELECT v FROM site_settings WHERE k='site'").get(); return Object.assign({ maintenance: 0, announcement: "", pages: { stats: 1, leaderboard: 1, servers: 1 } }, r ? JSON.parse(r.v) : {}); };
app.get("/api/site", (req, res) => res.json(getSite()));

async function statsData() {
  let servers = null, users = null;
  try { servers = (await botGuilds()).size; users = [...(await counts()).values()].reduce((a, b) => a + (b || 0), 0); } catch (e) { console.error(e.message); }
  const days = []; for (let i = 29; i >= 0; i--) days.push(new Date(Date.now() - i * 864e5).toISOString().slice(0, 10));
  const m = {}; days.forEach(d => m[d] = { day: d, commands: 0, messages: 0, joins: 0, leaves: 0 });
  db.prepare("SELECT day, SUM(n) AS n FROM command_log WHERE day >= ? GROUP BY day").all(days[0]).forEach(r => m[r.day] && (m[r.day].commands = r.n));
  db.prepare("SELECT day, SUM(messages) AS a, SUM(joins) AS b, SUM(leaves) AS c FROM daily_stats WHERE day >= ? GROUP BY day").all(days[0]).forEach(r => m[r.day] && Object.assign(m[r.day], { messages: r.a, joins: r.b, leaves: r.c }));
  const daily = days.map(d => m[d]), sum = k => daily.reduce((a, d) => a + d[k], 0), hourly = Array(24).fill(0);
  db.prepare("SELECT hour, n FROM hourly").all().forEach(r => hourly[r.hour] = r.n);
  const one = q => db.prepare(q).get().n;
  return { servers, users, active: one("SELECT COUNT(DISTINCT user_id) AS n FROM members"), messages: one("SELECT COALESCE(SUM(messages),0) AS n FROM daily_stats"),
    commands: one("SELECT COALESCE(SUM(n),0) AS n FROM command_log"), joins30: sum("joins"), leaves30: sum("leaves"), configured: one("SELECT COUNT(*) AS n FROM guild_config"),
    daily, hourly, top: db.prepare("SELECT name, SUM(n) AS n FROM command_log GROUP BY name ORDER BY n DESC LIMIT 8").all() };
}
const lbData = () => db.prepare("SELECT user_id AS id, MAX(username) AS username, MAX(avatar) AS avatar, SUM(xp) AS xp, SUM(messages) AS messages FROM members GROUP BY user_id HAVING SUM(xp) > 0 ORDER BY xp DESC LIMIT 50").all();
app.get("/api/stats", async (req, res) => res.json(await statsData()));
app.get("/api/leaderboard", (req, res) => res.json({ users: lbData() }));

/* API publique (clé requise : en-tête x-api-key) */
const hash = k => crypto.createHash("sha256").update(k).digest("hex");
const needKey = (req, res, next) => {
  const k = req.get("x-api-key"), r = k && db.prepare("SELECT id FROM api_keys WHERE key_hash = ?").get(hash(k));
  if (!r) return res.status(401).json({ error: "invalid_key" });
  db.prepare("UPDATE api_keys SET last_used = ? WHERE id = ?").run(Date.now(), r.id); next();
};
app.get("/api/v1/stats", needKey, async (req, res) => res.json(await statsData()));
app.get("/api/v1/leaderboard", needKey, (req, res) => res.json({ users: lbData() }));
app.get("/api/v1/guilds/:id/config", needKey, (req, res) => { const r = getCfg.get(req.params.id); res.json({ data: r ? JSON.parse(r.data) : {} }); });

/* Panel owner */
const O = [needLogin, needOwner];
app.get("/api/owner", ...O, async (req, res) => {
  try {
    await botGuilds(); const cn = await counts(), fl = {};
    db.prepare("SELECT * FROM guild_flags").all().forEach(f => fl[f.guild_id] = f);
    res.json({
      servers: botCache.list.map(g => ({ ...g, members: cn.get(g.id) || null, configured: !!getCfg.get(g.id), paused: !!(fl[g.id] && fl[g.id].paused), blacklisted: !!(fl[g.id] && fl[g.id].blacklisted) })),
      broadcasts: db.prepare("SELECT * FROM broadcasts ORDER BY id DESC LIMIT 20").all(),
      keys: db.prepare("SELECT id, name, created_at, last_used FROM api_keys").all(),
      audit: db.prepare("SELECT * FROM audit ORDER BY ts DESC LIMIT 50").all(), site: getSite(),
    });
  } catch (e) { res.status(502).json({ error: "discord" }); }
});
app.put("/api/owner/guild/:id", ...O, (req, res) => {
  const { paused, blacklisted } = req.body || {};
  db.prepare("INSERT INTO guild_flags (guild_id, paused, blacklisted) VALUES (?, ?, ?) ON CONFLICT(guild_id) DO UPDATE SET paused = excluded.paused, blacklisted = excluded.blacklisted").run(req.params.id, paused ? 1 : 0, blacklisted ? 1 : 0);
  log(req, `Serveur ${req.params.id} : pause=${!!paused}, blacklist=${!!blacklisted}`); res.json({ ok: true });
});
app.put("/api/owner/site", ...O, (req, res) => {
  const b = req.body || {}, p = b.pages || {};
  const s = { maintenance: b.maintenance ? 1 : 0, announcement: String(b.announcement || "").slice(0, 300), pages: { stats: p.stats ? 1 : 0, leaderboard: p.leaderboard ? 1 : 0, servers: p.servers ? 1 : 0 } };
  db.prepare("INSERT INTO site_settings (k, v) VALUES ('site', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(JSON.stringify(s));
  log(req, "Réglages du site modifiés"); res.json(s);
});
app.post("/api/owner/broadcast", ...O, (req, res) => {
  const title = String(req.body.title || "").slice(0, 100), body = String(req.body.body || "").slice(0, 1800);
  if (!body) return res.status(400).json({ error: "empty" });
  db.prepare("INSERT INTO broadcasts (title, body, created_at) VALUES (?, ?, ?)").run(title, body, Date.now());
  log(req, "Broadcast créé : " + (title || body.slice(0, 30))); res.json({ ok: true });
});
app.post("/api/owner/keys", ...O, (req, res) => {
  const k = "grok_" + crypto.randomBytes(24).toString("hex");
  db.prepare("INSERT INTO api_keys (name, key_hash, created_at) VALUES (?, ?, ?)").run(String(req.body.name || "clé").slice(0, 40), hash(k), Date.now());
  log(req, "Clé API créée"); res.json({ key: k });
});
app.delete("/api/owner/keys/:id", ...O, (req, res) => { db.prepare("DELETE FROM api_keys WHERE id = ?").run(req.params.id); log(req, "Clé API supprimée"); res.json({ ok: true }); });
app.delete("/api/owner/leaderboard", ...O, (req, res) => { db.exec("DELETE FROM members"); log(req, "Leaderboard remis à zéro"); res.json({ ok: true }); });
app.delete("/api/owner/leaderboard/:uid", ...O, (req, res) => { db.prepare("DELETE FROM members WHERE user_id = ?").run(req.params.uid); log(req, "XP supprimé pour " + req.params.uid); res.json({ ok: true }); });

/* ---------- Statistiques du site (privées : panel owner uniquement) ---------- */
app.post("/api/track", (req, res) => {
  const s = req.get("user-agent") || "", b = req.body || {};
  if (/bot|crawl|spider|preview|curl|wget/i.test(s)) return res.json({ ok: true });
  if (OWNER_ID && req.session.user && req.session.user.id === OWNER_ID) return res.json({ ok: true }); // tes visites ne comptent pas
  const now = Date.now(), n = (trackSeen.get(req.ip) || []).filter(t => now - t < 60000);
  if (n.length >= 60) return res.json({ ok: true });
  n.push(now); trackSeen.set(req.ip, n); if (trackSeen.size > 5000) trackSeen.clear();
  const p = String(b.p || ""), v = String(b.v || "").slice(0, 40);
  if (!v || !(/^[a-z]{1,20}$/.test(p) || p === "event:invite" || p === "event:support")) return res.json({ ok: true });
  let ref = ""; try { ref = b.r ? new URL(String(b.r)).hostname.replace(/^www\./, "") : ""; if (ref === new URL(BASE_URL).hostname) ref = ""; } catch (_) {}
  const w = Number(b.w) || 0, u = parseUA(s);
  addVisit({ vid: v, path: p, ref, dev: w < 768 ? "Mobile" : w < 1100 ? "Tablette" : "Ordinateur", br: u.br, os: u.os, lang: (req.get("accept-language") || "").slice(0, 2).toLowerCase(), country: req.get("cf-ipcountry") || "" });
  res.json({ ok: true });
});
app.get("/api/owner/analytics", ...O, (req, res) => {
  const all = (s, ...a) => db.prepare(s).all(...a), one = (s, ...a) => db.prepare(s).get(...a), now = Date.now(), P = "path NOT LIKE 'event:%'";
  const span = from => one(`SELECT COUNT(*) AS v, COUNT(DISTINCT vid) AS u FROM visits WHERE ${P} AND ts >= ?`, from);
  const days = []; for (let i = 29; i >= 0; i--) days.push(new Date(now - i * 864e5).toISOString().slice(0, 10));
  const dm = {}; all(`SELECT day, COUNT(*) AS v, COUNT(DISTINCT vid) AS u FROM visits WHERE ${P} AND day >= ? GROUP BY day`, days[0]).forEach(r => dm[r.day] = r);
  const hourly = Array(24).fill(0); all(`SELECT CAST(strftime('%H', ts/1000, 'unixepoch') AS INTEGER) AS h, COUNT(*) AS n FROM visits WHERE ${P} GROUP BY h`).forEach(r => hourly[r.h] = r.n);
  const top = (col, extra = "") => all(`SELECT ${col} AS k, COUNT(*) AS n FROM visits WHERE ${P} ${extra} GROUP BY ${col} ORDER BY n DESC LIMIT 8`);
  const ev = e => one("SELECT COUNT(*) AS n FROM visits WHERE path = ?", "event:" + e).n;
  res.json({
    live: one(`SELECT COUNT(DISTINCT vid) AS n FROM visits WHERE ${P} AND ts >= ?`, now - 300000).n,
    today: span(now - now % 864e5), week: span(now - 7 * 864e5), month: span(now - 30 * 864e5), all: span(0),
    new7: one(`SELECT COUNT(*) AS n FROM (SELECT vid, MIN(ts) AS f FROM visits WHERE ${P} GROUP BY vid) WHERE f >= ?`, now - 7 * 864e5).n,
    daily: days.map(d => ({ day: d, v: dm[d] ? dm[d].v : 0, u: dm[d] ? dm[d].u : 0 })), hourly,
    pages: top("path"), refs: top("ref"), devs: top("dev"), brs: top("br"), oss: top("os"), langs: top("lang"), countries: top("country", "AND country != ''"),
    ev: { invite: ev("invite"), support: ev("support"), login: ev("login") },
  });
});

app.get(["/", "/index.html"], (req, res) => res.set("Cache-Control", "no-store").sendFile(path.join(__dirname, "public", "index.html")));
app.use(express.static(path.join(__dirname, "public"), { etag: false, setHeaders: r => r.set("Cache-Control", "no-store") }));
app.listen(PORT, () => console.log(`✅ NOUVEAU SITE (v2) chargé : ${BASE_URL}`));
