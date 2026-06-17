import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

// ── DB ────────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') || process.env.DATABASE_URL?.includes('postgres.railway')
    ? { rejectUnauthorized: false }
    : false,
  // Connection pool settings for Railway
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function initDB(retries = 10, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
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
      console.log('DB ready');
      return;
    } catch (e) {
      console.error(`DB init attempt ${i + 1}/${retries} failed:`, e.message);
      if (i < retries - 1) {
        console.log(`Retrying in ${delay / 1000}s...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        throw e;
      }
    }
  }
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
// CORS: allow both with and without trailing slash, handle preflight properly
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (curl, Postman, Railway healthcheck)
    if (!origin) return callback(null, true);
    // Allow the configured client URL
    const allowed = CLIENT_URL.replace(/\/$/, '');
    if (origin === allowed || origin === allowed + '/') {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Handle preflight requests explicitly
app.options('*', cors());

app.use(express.json());

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── CRYPTO HELPERS ────────────────────────────────────────────────────────────
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

// ── HEALTH ────────────────────────────────────────────────────────────────────
// Must respond BEFORE DB is ready so Railway doesn't kill the container during init
app.get('/health', async (_, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'connected' });
  } catch {
    // Return 200 even if DB isn't ready yet — let the app start
    res.json({ ok: true, db: 'connecting' });
  }
});

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, password, pat } = req.body;
  if (!username || !password || !pat) return res.status(400).json({ error: 'username, password и PAT обязательны' });
  if (username.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const ghRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${pat}`, Accept: 'application/vnd.github+json' }
  });
  if (!ghRes.ok) return res.status(400).json({ error: 'Неверный GitHub PAT-токен или нет прав gist' });

  try {
    const password_hash = await bcrypt.hash(password, 12);
    const encrypted_pat = encrypt(pat, password);
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
    const pat = decrypt(user.encrypted_pat, password);
    res.json({ token, username: user.username, pat, threshold: user.api_limit_threshold });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const result = await pool.query('SELECT id, username, api_limit_threshold FROM users WHERE id = $1', [req.user.id]);
  res.json(result.rows[0] || {});
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
app.patch('/api/settings/threshold', auth, async (req, res) => {
  const { threshold } = req.body;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 4999)
    return res.status(400).json({ error: 'Порог должен быть от 1 до 4999' });
  await pool.query('UPDATE users SET api_limit_threshold = $1 WHERE id = $2', [threshold, req.user.id]);
  res.json({ ok: true });
});

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

// ── GIST REGISTRY ─────────────────────────────────────────────────────────────
app.get('/api/gists', auth, async (req, res) => {
  const result = await pool.query('SELECT gist_id, name, created_at FROM user_gists WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

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

app.delete('/api/gists/:gistId', auth, async (req, res) => {
  await pool.query('DELETE FROM user_gists WHERE user_id = $1 AND gist_id = $2', [req.user.id, req.params.gistId]);
  res.json({ ok: true });
});

app.patch('/api/gists/:gistId/name', auth, async (req, res) => {
  const { name } = req.body;
  await pool.query('UPDATE user_gists SET name = $1 WHERE user_id = $2 AND gist_id = $3', [name, req.user.id, req.params.gistId]);
  res.json({ ok: true });
});

// ── START ─────────────────────────────────────────────────────────────────────
// Start HTTP server immediately so Railway healthcheck passes,
// then connect to DB in background with retries
app.listen(PORT, '0.0.0.0', () => console.log(`GistDB server on :${PORT}`));

initDB().catch(e => {
  console.error('DB init failed after all retries:', e);
  process.exit(1);
});
