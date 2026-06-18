import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';
const ADMIN_GITHUB_USERNAME = process.env.ADMIN_GITHUB_USERNAME || '';

// ── DB ────────────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false });

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      encrypted_pat TEXT NOT NULL,
      api_limit_threshold INTEGER DEFAULT 500,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_gists (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      gist_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, gist_id)
    );
  `);
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: CLIENT_URL, credentials: true }));
app.use(express.json());

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── CRYPTO HELPERS (server-side AES-256-GCM) ──────────────────────────────────
// We use Node's built-in crypto for server operations
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

function deriveKey(password, salt) {
  return scryptSync(password, salt, 32);
}

function encrypt(text, password) {
  const salt = randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

function decrypt(data, password) {
  const buf = Buffer.from(data, 'base64');
  const salt = buf.subarray(0, 16);
  const iv = buf.subarray(16, 28);
  const tag = buf.subarray(28, 44);
  const encrypted = buf.subarray(44);
  const key = deriveKey(password, salt);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { username, password, pat } = req.body;
  if (!username || !password || !pat) return res.status(400).json({ error: 'username, password и PAT обязательны' });
  if (username.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  // Validate PAT against GitHub before saving
  const ghRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${pat}`, Accept: 'application/vnd.github+json' }
  });
  if (!ghRes.ok) return res.status(400).json({ error: 'Неверный GitHub PAT-токен или нет прав gist' });

  try {
    const password_hash = await bcrypt.hash(password, 12);
    const encrypted_pat = encrypt(pat, password); // PAT encrypted with user's password
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, encrypted_pat) VALUES ($1, $2, $3) RETURNING id, username',
      [username.toLowerCase(), password_hash, encrypted_pat]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: user.username });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Этот логин уже занят' });
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Логин и пароль обязательны' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    // Decrypt PAT to return to client (stays in memory only)
    const pat = decrypt(user.encrypted_pat, password);
    res.json({ token, username: user.username, pat, threshold: user.api_limit_threshold });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// GET /api/auth/me — refresh session + get PAT (requires re-auth for PAT)
app.get('/api/auth/me', auth, async (req, res) => {
  const result = await pool.query('SELECT id, username, api_limit_threshold FROM users WHERE id = $1', [req.user.id]);
  res.json(result.rows[0] || {});
});

// ── ADMIN VERIFICATION ─────────────────────────────────────────────────────────
// Validates that a GitHub PAT belongs specifically to the site owner's account,
// not just any valid GitHub token. Prevents anyone with a working PAT from
// gaining admin access to every database on the site.
app.post('/api/admin/verify', async (req, res) => {
  const { pat } = req.body;
  if (!pat) return res.status(400).json({ error: 'Токен обязателен' });
  if (!ADMIN_GITHUB_USERNAME) {
    return res.status(500).json({ error: 'Администратор не настроен на сервере (ADMIN_GITHUB_USERNAME не задан)' });
  }
  try {
    const ghRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${pat}`, Accept: 'application/vnd.github+json' }
    });
    if (!ghRes.ok) return res.status(401).json({ error: 'Неверный или просроченный токен' });
    const ghUser = await ghRes.json();
    if (ghUser.login?.toLowerCase() !== ADMIN_GITHUB_USERNAME.toLowerCase()) {
      return res.status(403).json({ error: 'Этот токен не принадлежит администратору сайта' });
    }
    res.json({ ok: true, login: ghUser.login });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка проверки токена' });
  }
});

// GET /api/gists/registered-ids — all gist IDs registered by any regular user.
// Used by the admin panel to exclude user-owned gists from the admin's own
// GitHub gist listing, in the (otherwise possible) case a user's PAT happens
// to be the same GitHub account as the admin's. Restricted to the verified
// admin PAT so this list isn't exposed to arbitrary callers.
app.get('/api/gists/registered-ids', async (req, res) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const pat = header.slice(7);
  try {
    const ghRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${pat}`, Accept: 'application/vnd.github+json' }
    });
    if (!ghRes.ok) return res.status(401).json({ error: 'Unauthorized' });
    const ghUser = await ghRes.json();
    if (!ADMIN_GITHUB_USERNAME || ghUser.login?.toLowerCase() !== ADMIN_GITHUB_USERNAME.toLowerCase()) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const result = await pool.query('SELECT gist_id FROM user_gists');
    res.json(result.rows.map(r => r.gist_id));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});


// PATCH /api/settings/threshold
app.patch('/api/settings/threshold', auth, async (req, res) => {
  const { threshold } = req.body;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 4999)
    return res.status(400).json({ error: 'Порог должен быть от 1 до 4999' });
  await pool.query('UPDATE users SET api_limit_threshold = $1 WHERE id = $2', [threshold, req.user.id]);
  res.json({ ok: true });
});

// PATCH /api/settings/password — change password (re-encrypts PAT)
app.patch('/api/settings/password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Оба пароля обязательны' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    const ok = await bcrypt.compare(oldPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный текущий пароль' });
    const pat = decrypt(user.encrypted_pat, oldPassword);
    const new_hash = await bcrypt.hash(newPassword, 12);
    const new_encrypted_pat = encrypt(pat, newPassword);
    await pool.query('UPDATE users SET password_hash = $1, encrypted_pat = $2 WHERE id = $3', [new_hash, new_encrypted_pat, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── GIST PROXY (encrypted) ────────────────────────────────────────────────────
// All gist data is encrypted with user's password before storing in GitHub
// Server never sees plaintext — encryption/decryption happens in browser via Web Crypto

// GET /api/gists — list user's gists
app.get('/api/gists', auth, async (req, res) => {
  const result = await pool.query('SELECT gist_id, name, created_at FROM user_gists WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

// POST /api/gists/register — register a gist as belonging to this user
app.post('/api/gists/register', auth, async (req, res) => {
  const { gist_id, name } = req.body;
  if (!gist_id || !name) return res.status(400).json({ error: 'gist_id и name обязательны' });
  try {
    await pool.query('INSERT INTO user_gists (user_id, gist_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [req.user.id, gist_id, name]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// DELETE /api/gists/:gistId — unregister gist
app.delete('/api/gists/:gistId', auth, async (req, res) => {
  await pool.query('DELETE FROM user_gists WHERE user_id = $1 AND gist_id = $2', [req.user.id, req.params.gistId]);
  res.json({ ok: true });
});

// PATCH /api/gists/:gistId/name — update name
app.patch('/api/gists/:gistId/name', auth, async (req, res) => {
  const { name } = req.body;
  await pool.query('UPDATE user_gists SET name = $1 WHERE user_id = $2 AND gist_id = $3', [name, req.user.id, req.params.gistId]);
  res.json({ ok: true });
});

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true }));

// ── START ─────────────────────────────────────────────────────────────────────
// The HTTP server always starts and listens, even if the database is down.
// Routes that genuinely need Postgres (registration, login, user gist registry)
// will fail with a clear "database unavailable" error instead of the whole
// process crashing — which previously made every route, including admin
// verification, return a 502 whenever Postgres had a hiccup.
let dbReady = false;

app.listen(PORT, () => console.log(`GistDB server on :${PORT}`));

initDB()
  .then(() => { dbReady = true; console.log('DB ready'); })
  .catch(e => { console.error('DB init failed (server still running, DB-dependent routes will report unavailable):', e.message); });

// Periodically retry DB connection in case Postgres comes back online later
setInterval(() => {
  if (dbReady) return;
  initDB().then(() => { dbReady = true; console.log('DB reconnected'); }).catch(() => {});
}, 30000);
