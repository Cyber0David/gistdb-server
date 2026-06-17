import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT || 8080);
const HOST = '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-please';
const DATABASE_URL = process.env.DATABASE_URL || '';

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'change-this-in-production-please') {
  console.warn('Warning: JWT_SECRET uses default value in production.');
}
if (!DATABASE_URL) {
  console.warn('Warning: DATABASE_URL is not set. API routes will return 503 until DB is available.');
}

// CLIENT_URLS supports comma-separated list (main + preview domains if needed)
const rawClientUrls =
  process.env.CLIENT_URLS ||
  process.env.CLIENT_URL ||
  'http://localhost:5173';

const allowedOrigins = rawClientUrls
  .split(',')
  .map((s) => s.trim().replace(/\/$/, ''))
  .filter(Boolean);

// Set ALLOW_VERCEL_PREVIEW=false if you want to block *.vercel.app preview URLs
const allowVercelPreview = (process.env.ALLOW_VERCEL_PREVIEW || 'true').toLowerCase() === 'true';

// ── DB ────────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    DATABASE_URL.includes('railway') || DATABASE_URL.includes('postgres.railway')
      ? { rejectUnauthorized: false }
      : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

let dbReady = false;

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

async function initDBWithRetry(maxRetries = 20, delayMs = 3000) {
  for (let i = 1; i <= maxRetries; i += 1) {
    try {
      await initDB();
      dbReady = true;
      console.log('DB ready');
      return;
    } catch (e) {
      dbReady = false;
      console.error(`DB init attempt ${i}/${maxRetries} failed:`, e.message);
      if (i < maxRetries) {
        console.log(`Retrying in ${delayMs / 1000}s...`);
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  }

  // Do not kill container. Keep app alive so Railway health checks can pass.
  console.error('DB init failed after all retries. API routes will return 503 until DB is restored.');
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
function isAllowedOrigin(origin) {
  const clean = origin.replace(/\/$/, '');
  if (allowedOrigins.includes(clean)) return true;

  if (allowVercelPreview) {
    try {
      const hostname = new URL(clean).hostname;
      if (hostname.endsWith('.vercel.app')) return true;
    } catch {
      return false;
    }
  }

  return false;
}

const corsOptions = {
  origin(origin, callback) {
    // Allow no-origin requests (curl/Postman/Railway probes)
    if (!origin) return callback(null, true);

    if (isAllowedOrigin(origin)) return callback(null, true);

    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json());

// Block API when DB is unavailable (except /health)
app.use('/api', (req, res, next) => {
  if (!dbReady) {
    return res.status(503).json({ error: 'База данных недоступна. Попробуйте позже.' });
  }
  return next();
});

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
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
app.get('/health', async (_, res) => {
  try {
    await pool.query('SELECT 1');
    return res.status(200).json({ ok: true, db: 'connected' });
  } catch {
    // Keep 200 to avoid premature Railway restarts during startup
    return res.status(200).json({ ok: true, db: 'connecting' });
  }
});

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, password, pat } = req.body;

  if (!username || !password || !pat) {
    return res.status(400).json({ error: 'username, password и PAT обязательны' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Логин минимум 3 символа' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  }

  try {
    const ghRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${pat}`,
        Accept: 'application/vnd.github+json',
      },
    });

    if (!ghRes.ok) {
      return res.status(400).json({ error: 'Неверный GitHub PAT-токен или нет прав gist' });
    }

    const password_hash = await bcrypt.hash(password, 12);
    const encrypted_pat = encrypt(pat, password);

    const result = await pool.query(
      'INSERT INTO users (username, password_hash, encrypted_pat) VALUES ($1, $2, $3) RETURNING id, username',
      [username.toLowerCase(), password_hash, encrypted_pat]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
      expiresIn: '30d',
    });

    return res.json({ token, username: user.username });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Этот логин уже занят' });
    }
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [
      username.toLowerCase(),
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
      expiresIn: '30d',
    });
    const pat = decrypt(user.encrypted_pat, password);

    return res.json({
      token,
      username: user.username,
      pat,
      threshold: user.api_limit_threshold,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, api_limit_threshold FROM users WHERE id = $1',
      [req.user.id]
    );
    return res.json(result.rows[0] || {});
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── SETTINGS ──────────────────────────────────────────────────────────────────
app.patch('/api/settings/threshold', auth, async (req, res) => {
  const { threshold } = req.body;

  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 4999) {
    return res.status(400).json({ error: 'Порог должен быть от 1 до 4999' });
  }

  try {
    await pool.query('UPDATE users SET api_limit_threshold = $1 WHERE id = $2', [
      threshold,
      req.user.id,
    ]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.patch('/api/settings/password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Оба пароля обязательны' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const ok = await bcrypt.compare(oldPassword, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Неверный текущий пароль' });
    }

    const pat = decrypt(user.encrypted_pat, oldPassword);
    const new_hash = await bcrypt.hash(newPassword, 12);
    const new_encrypted_pat = encrypt(pat, newPassword);

    await pool.query(
      'UPDATE users SET password_hash = $1, encrypted_pat = $2 WHERE id = $3',
      [new_hash, new_encrypted_pat, req.user.id]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── GIST REGISTRY ─────────────────────────────────────────────────────────────
app.get('/api/gists', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT gist_id, name, created_at FROM user_gists WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/gists/register', auth, async (req, res) => {
  const { gist_id, name } = req.body;

  if (!gist_id || !name) {
    return res.status(400).json({ error: 'gist_id и name обязательны' });
  }

  try {
    await pool.query(
      'INSERT INTO user_gists (user_id, gist_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
      [req.user.id, gist_id, name]
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/gists/:gistId', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_gists WHERE user_id = $1 AND gist_id = $2', [
      req.user.id,
      req.params.gistId,
    ]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.patch('/api/gists/:gistId/name', auth, async (req, res) => {
  const { name } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Название не может быть пустым' });
  }

  try {
    await pool.query(
      'UPDATE user_gists SET name = $1 WHERE user_id = $2 AND gist_id = $3',
      [name.trim(), req.user.id, req.params.gistId]
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`GistDB server on ${HOST}:${PORT}`);
  console.log('Allowed origins:', allowedOrigins);
});

// Start DB init in background. App remains alive for Railway healthchecks.
void initDBWithRetry();

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});
