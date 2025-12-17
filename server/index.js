import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import path from 'path'
import crypto from 'crypto'
import { authenticator } from 'otplib'
import fs from 'fs'

const app = express()
app.use(express.json({ limit: '10mb' }))

// Debug endpoint for client logs
app.post('/debug/log', (req, res) => {
    const { msg } = req.body || {};
    if (msg) console.log('\x1b[36m[CLIENT-LOG]\x1b[0m', msg);
    res.json({ ok: true });
});

app.use(cors({ origin: true, credentials: true }))
app.use(helmet({ contentSecurityPolicy: false }))
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }))

const dbPath = path.join(process.cwd(), 'server', 'data', 'notes.db')
const db = new Database(dbPath)

// Intrusion Detection: Log file path
const detectionLogPath = path.join(process.cwd(), 'logs', 'detection.log');

// Helper to log intrusion events
function logIntrusion(event, details) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${event}] ${JSON.stringify(details)}\n`;
    try {
        fs.appendFileSync(detectionLogPath, logEntry);
    } catch (e) {
        console.error('Failed to write detection log:', e);
    }
}

// IP Blocking Map (Simple in-memory implementation)
const ipFailures = new Map();
const BLOCK_THRESHOLD = 3;
const BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW = 5000; // 5 seconds

function checkIpBlock(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const record = ipFailures.get(ip);
    if (record && record.blockedUntil > Date.now()) {
        logIntrusion('IP_BLOCKED_ACCESS_ATTEMPT', { ip, blockedUntil: new Date(record.blockedUntil).toISOString() });
        return res.status(403).json({ error: 'ip_blocked', message: 'Too many failed attempts. Try again later.' });
    }
    next();
}

function recordFailure(ip) {
    const now = Date.now();
    let record = ipFailures.get(ip);
    if (!record) {
        record = { attempts: [], blockedUntil: 0 };
        ipFailures.set(ip, record);
    }

    // Add new failure timestamp
    record.attempts.push(now);

    // Remove attempts outside the window
    record.attempts = record.attempts.filter(t => now - t <= ATTEMPT_WINDOW);

    // Check threshold
    if (record.attempts.length >= BLOCK_THRESHOLD) {
        record.blockedUntil = now + BLOCK_DURATION;
        record.attempts = []; // Reset attempts after blocking
        logIntrusion('IP_BLOCKED', { ip, attempts: BLOCK_THRESHOLD, window: '5s', blockedUntil: new Date(record.blockedUntil).toISOString() });
    }
}

app.post('/auth/logout', (req, res) => {
    // Just log the event, client clears token
    logIntrusion('LOGOUT', { ip: req.ip || req.connection.remoteAddress });
    res.json({ ok: true });
});

// Endpoint to report suspicious behavior (e.g., failed unlock) and upload evidence (screenshot/camera)
app.post('/api/report-intrusion', (req, res) => {
    const { type, imageBase64, noteId, details } = req.body || {};
    const ip = req.ip || req.connection.remoteAddress;
    
    // Log the event (including normal events if sent here)
    logIntrusion(type === 'normal_event' ? 'CLIENT_EVENT' : 'CLIENT_REPORTED_INTRUSION', { type, ip, noteId, details });
    
    // Save evidence image if provided
    if (imageBase64) {
        const matches = imageBase64.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
        if (matches && matches.length === 3) {
            const ext = matches[1].split('/')[1] || 'png';
            const buffer = Buffer.from(matches[2], 'base64');
            const filename = `evidence_${Date.now()}_${type}_${Math.random().toString(36).substring(7)}.${ext}`;
            const filepath = path.join(process.cwd(), 'logs', filename);
            try {
                fs.writeFileSync(filepath, buffer);
                logIntrusion('EVIDENCE_SAVED', { filename });
            } catch (e) {
                console.error('Failed to save evidence:', e);
            }
        }
    }
    
    // If it's a login failure or unlock failure, record for IP blocking
    if (type === 'login_fail' || type === 'unlock_fail') {
        recordFailure(ip);
    }
    
    res.json({ ok: true });
});

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  auth_salt TEXT NOT NULL,
  auth_hash TEXT NOT NULL,
  pub_sign_key TEXT,
  pub_enc_key TEXT,
  mfa_enabled INTEGER DEFAULT 0,
  mfa_secret TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  device_name TEXT,
  device_pub_key TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS vault_keys(
  user_id INTEGER PRIMARY KEY,
  vk_envelope TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  umk_salt TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  title_encrypted TEXT,
  title_plain TEXT,
  note_key_envelope TEXT NOT NULL,
  size_padded INTEGER NOT NULL,
  protected INTEGER NOT NULL DEFAULT 0,
  note_salt TEXT,
  shared INTEGER NOT NULL DEFAULT 0,
  share_permission TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS note_blobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  note_id INTEGER NOT NULL,
  chunk_index INTEGER NOT NULL,
  blob_encrypted BLOB NOT NULL,
  FOREIGN KEY(note_id) REFERENCES notes(id)
);
CREATE TABLE IF NOT EXISTS shares(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  note_id INTEGER NOT NULL,
  owner_id INTEGER NOT NULL,
  recipient_id INTEGER NOT NULL,
  nk_envelope_for_recipient TEXT,
  nk_envelope_for_link TEXT,
  share_token TEXT UNIQUE,
  permission TEXT DEFAULT 'ro',
  accepted INTEGER NOT NULL DEFAULT 0,
  accepted_note_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(note_id) REFERENCES notes(id),
  FOREIGN KEY(owner_id) REFERENCES users(id),
  FOREIGN KEY(recipient_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS blind_index(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  term_hash TEXT NOT NULL,
  note_id INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(note_id) REFERENCES notes(id)
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  resource_id TEXT,
  ts TEXT NOT NULL,
  ip TEXT,
  ua TEXT,
  device_id INTEGER
);
CREATE TABLE IF NOT EXISTS csrf_tokens(
  device_id INTEGER PRIMARY KEY,
  token TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`)
try { db.exec('ALTER TABLE notes ADD COLUMN title_plain TEXT') } catch(e) {}
try { db.exec('ALTER TABLE notes ADD COLUMN protected INTEGER NOT NULL DEFAULT 0') } catch(e) {}
try { db.exec('ALTER TABLE notes ADD COLUMN note_salt TEXT') } catch(e) {}
try { db.exec('ALTER TABLE notes ADD COLUMN shared INTEGER NOT NULL DEFAULT 0') } catch(e) {}
try { db.exec('ALTER TABLE notes ADD COLUMN share_permission TEXT') } catch(e) {}
try { db.exec('ALTER TABLE shares ADD COLUMN nk_envelope_for_link TEXT') } catch(e) {}
try { db.exec('ALTER TABLE shares ADD COLUMN share_token TEXT UNIQUE') } catch(e) {}
try { db.exec("ALTER TABLE shares ADD COLUMN permission TEXT DEFAULT 'ro'") } catch(e) {}
try { db.exec('ALTER TABLE shares ADD COLUMN accepted INTEGER NOT NULL DEFAULT 0') } catch(e) {}
try { db.exec('ALTER TABLE shares ADD COLUMN accepted_note_id INTEGER') } catch(e) {}

try { db.exec('ALTER TABLE vault_keys ADD COLUMN umk_salt TEXT') } catch (e) {}
try { db.exec('ALTER TABLE audit ADD COLUMN ua TEXT') } catch (e) {}

const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex')

function now() {
  return new Date().toISOString()
}

function issueTokens(userId, deviceId) {
  const access = jwt.sign({ sub: userId, did: deviceId }, jwtSecret, { expiresIn: '10m' })
  const refresh = jwt.sign({ sub: userId, did: deviceId, type: 'refresh' }, jwtSecret, { expiresIn: '7d' })
  return { access, refresh }
}

function auth(req, res, next) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : ''
  try {
    const payload = jwt.verify(token, jwtSecret)
    req.user = { id: payload.sub, deviceId: payload.did }
    const protectedMethods = ['POST','PUT','DELETE']
    if (protectedMethods.includes(req.method)) {
      const row = db.prepare('SELECT token FROM csrf_tokens WHERE device_id=?').get(req.user.deviceId)
      const csrf = req.headers['x-csrf-token']
      if (!row || !csrf || csrf !== row.token) return res.status(403).json({ error: 'forbidden' })
    }
    next()
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' })
  }
}

function audit(userId, action, resourceId, req) {
  db.prepare('INSERT INTO audit(user_id, action, resource_id, ts, ip, ua, device_id) VALUES(?,?,?,?,?,?,?)')
    .run(userId || null, action, resourceId || null, now(), req.ip || null, req.get('user-agent') || null, req.user?.deviceId || null)
}

app.post('/auth/register', (req, res) => {
  const { email, authPassword, deviceName } = req.body || {}
  if (!email || !authPassword) return res.status(400).json({ error: 'invalid' })
  const authSalt = crypto.randomBytes(16).toString('hex')
  const authHash = bcrypt.hashSync(authPassword + authSalt, 12)
  try {
    const info = db.prepare('INSERT INTO users(email, auth_salt, auth_hash, created_at) VALUES(?,?,?,?)')
      .run(email, authSalt, authHash, now())
    const userId = info.lastInsertRowid
    const devInfo = db.prepare('INSERT INTO devices(user_id, device_name, created_at) VALUES(?,?,?)')
      .run(userId, deviceName || 'device', now())
    const deviceId = devInfo.lastInsertRowid
    const tokens = issueTokens(userId, deviceId)
    const csrf = crypto.randomBytes(16).toString('hex')
    db.prepare('INSERT INTO csrf_tokens(device_id, token, updated_at) VALUES(?,?,?)').run(deviceId, csrf, now())
    audit(userId, 'register', String(userId), req)
    res.json({ userId, deviceId, ...tokens, csrfToken: csrf })
  } catch (e) {
    res.status(409).json({ error: 'exists' })
  }
})

app.post('/auth/login', checkIpBlock, (req, res) => {
  const { email, authPassword, deviceName } = req.body || {}
  
  // Log every login attempt (for SQLi/BruteForce auditing)
  logIntrusion('LOGIN_ATTEMPT', { ip: req.ip || req.connection.remoteAddress, email, deviceName });

  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email)
  if (!user) {
    recordFailure(req.ip || req.connection.remoteAddress)
    logIntrusion('LOGIN_FAILED', { ip: req.ip || req.connection.remoteAddress, reason: 'user_not_found', email });
    return res.status(401).json({ error: 'invalid' })
  }
  const ok = bcrypt.compareSync(authPassword + user.auth_salt, user.auth_hash)
  if (!ok) {
    recordFailure(req.ip || req.connection.remoteAddress)
    logIntrusion('LOGIN_FAILED', { ip: req.ip || req.connection.remoteAddress, reason: 'password_mismatch', email });
    return res.status(401).json({ error: 'invalid' })
  }
  
  logIntrusion('LOGIN_SUCCESS', { ip: req.ip || req.connection.remoteAddress, userId: user.id });

  const devInfo = db.prepare('INSERT INTO devices(user_id, device_name, created_at) VALUES(?,?,?)')
    .run(user.id, deviceName || 'device', now())
  const deviceId = devInfo.lastInsertRowid
  const tokens = issueTokens(user.id, deviceId)
  const csrf = crypto.randomBytes(16).toString('hex')
  db.prepare('INSERT INTO csrf_tokens(device_id, token, updated_at) VALUES(?,?,?)').run(deviceId, csrf, now())
  audit(user.id, 'login', String(user.id), req)
  res.json({ userId: user.id, deviceId, ...tokens, csrfToken: csrf })
})

app.get('/csrf-token', auth, (req, res) => {
  const row = db.prepare('SELECT token FROM csrf_tokens WHERE device_id=?').get(req.user.deviceId)
  if (!row) return res.status(404).json({ error: 'not_found' })
  res.json({ csrfToken: row.token })
})

app.get('/auth/last-login', auth, (req, res) => {
  const row = db.prepare('SELECT ts, ip, ua FROM audit WHERE user_id=? AND action=? ORDER BY ts DESC LIMIT 1')
    .get(req.user.id, 'login')
  if (!row) return res.json({ ts: null, ip: null, ua: null })
  res.json({ ts: row.ts, ip: row.ip || null, ua: row.ua || null })
})

app.post('/mfa/setup', auth, (req, res) => {
  const user = db.prepare('SELECT id, mfa_enabled FROM users WHERE id=?').get(req.user.id)
  if (!user) return res.status(404).json({ error: 'not_found' })
  const secret = authenticator.generateSecret()
  db.prepare('UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE id=?').run(secret, req.user.id)
  audit(req.user.id, 'mfa_setup', String(req.user.id), req)
  const otpauth = authenticator.keyuri(String(req.user.id), 'NotesZeroTrust', secret)
  res.json({ otpauth })
})

app.post('/mfa/verify', auth, (req, res) => {
  const { token } = req.body || {}
  const row = db.prepare('SELECT mfa_secret FROM users WHERE id=?').get(req.user.id)
  if (!row || !row.mfa_secret) return res.status(400).json({ error: 'invalid' })
  const ok = authenticator.verify({ token, secret: row.mfa_secret })
  audit(req.user.id, 'mfa_verify', String(req.user.id), req)
  res.json({ ok })
})

app.post('/vault/bootstrap', auth, (req, res) => {
  const { vkEnvelope, umkSalt } = req.body || {}
  if (!vkEnvelope) return res.status(400).json({ error: 'invalid' })
  const exists = db.prepare('SELECT user_id FROM vault_keys WHERE user_id=?').get(req.user.id)
  if (exists) {
    const current = db.prepare('SELECT umk_salt FROM vault_keys WHERE user_id=?').get(req.user.id)
    const salt = umkSalt || current?.umk_salt || crypto.randomBytes(32).toString('base64')
    db.prepare('UPDATE vault_keys SET vk_envelope=?, umk_salt=?, version=version+1, updated_at=? WHERE user_id=?')
      .run(JSON.stringify(vkEnvelope), salt, now(), req.user.id)
  } else {
    const salt = umkSalt || crypto.randomBytes(32).toString('base64')
    db.prepare('INSERT INTO vault_keys(user_id, vk_envelope, umk_salt, updated_at) VALUES(?,?,?,?)')
      .run(req.user.id, JSON.stringify(vkEnvelope), salt, now())
  }
  audit(req.user.id, 'vault_bootstrap', String(req.user.id), req)
  res.json({ ok: true })
})

app.get('/vault/bootstrap', auth, (req, res) => {
  const row = db.prepare('SELECT vk_envelope, version, umk_salt FROM vault_keys WHERE user_id=?').get(req.user.id)
  if (!row) return res.status(404).json({ error: 'not_found' })
  res.json({ vkEnvelope: JSON.parse(row.vk_envelope), version: row.version, umkSalt: row.umk_salt })
})

app.post('/notes', auth, (req, res) => {
  const { titleEnc, contentEnc, noteKeyEnvelope } = req.body || {}
  if (!titleEnc || !contentEnc || !noteKeyEnvelope) return res.status(400).json({ error: 'invalid' })
  const sizePadded = Buffer.from(contentEnc.ciphertext || '').length
  const info = db.prepare('INSERT INTO notes(user_id, created_at, updated_at, title_encrypted, note_key_envelope, size_padded) VALUES(?,?,?,?,?,?)')
    .run(req.user.id, now(), now(), JSON.stringify(titleEnc), JSON.stringify(noteKeyEnvelope), sizePadded)
  const noteId = info.lastInsertRowid
  db.prepare('INSERT INTO note_blobs(note_id, chunk_index, blob_encrypted) VALUES(?,?,?)')
    .run(noteId, 0, Buffer.from(JSON.stringify(contentEnc)))
  audit(req.user.id, 'create_note', String(noteId), req)
  res.json({ id: noteId })
})

app.post('/notes/plain', auth, (req, res) => {
  const { title, contentHtml } = req.body || {}
  if (typeof title !== 'string' || typeof contentHtml !== 'string') return res.status(400).json({ error: 'invalid' })
  const info = db.prepare('INSERT INTO notes(user_id, created_at, updated_at, title_plain, title_encrypted, note_key_envelope, size_padded, protected) VALUES(?,?,?,?,?,?,?,0)')
    .run(req.user.id, now(), now(), title, JSON.stringify({ alg: 'PLAIN' }), JSON.stringify(null), Buffer.byteLength(contentHtml))
  const noteId = info.lastInsertRowid
  const blob = { alg: 'PLAIN', data: contentHtml }
  db.prepare('INSERT INTO note_blobs(note_id, chunk_index, blob_encrypted) VALUES(?,?,?)')
    .run(noteId, 0, Buffer.from(JSON.stringify(blob)))
  audit(req.user.id, 'create_note_plain', String(noteId), req)
  res.json({ id: noteId })
})

app.put('/notes/:id', auth, (req, res) => {
  const { titleEnc, contentEnc } = req.body || {}
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(req.params.id, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const sizePadded = Buffer.from(contentEnc.ciphertext || '').length
  db.prepare('UPDATE notes SET title_encrypted=?, updated_at=?, size_padded=? WHERE id=?')
    .run(JSON.stringify(titleEnc), now(), sizePadded, note.id)
  db.prepare('UPDATE note_blobs SET blob_encrypted=? WHERE note_id=? AND chunk_index=0')
    .run(Buffer.from(JSON.stringify(contentEnc)), note.id)
  audit(req.user.id, 'update_note', String(note.id), req)
  res.json({ ok: true })
})

app.put('/notes/:id/plain', auth, (req, res) => {
  const { title, contentHtml } = req.body || {}
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(req.params.id, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  db.prepare('UPDATE notes SET title_plain=?, protected=0, updated_at=?, size_padded=? WHERE id=?')
    .run(title, now(), Buffer.byteLength(contentHtml || ''), note.id)
  const blob = { alg: 'PLAIN', data: contentHtml || '' }
  db.prepare('UPDATE note_blobs SET blob_encrypted=? WHERE note_id=? AND chunk_index=0')
    .run(Buffer.from(JSON.stringify(blob)), note.id)
  audit(req.user.id, 'update_note_plain', String(note.id), req)
  res.json({ ok: true })
})

app.put('/notes/:id/protect', auth, (req, res) => {
  const { title, noteSalt, contentEnc } = req.body || {}
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(req.params.id, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const sizePadded = Buffer.from(contentEnc.ciphertext || '').length
  db.prepare('UPDATE notes SET title_plain=?, protected=1, note_salt=?, updated_at=?, size_padded=? WHERE id=?')
    .run(title, noteSalt || null, now(), sizePadded, note.id)
  db.prepare('UPDATE note_blobs SET blob_encrypted=? WHERE note_id=? AND chunk_index=0')
    .run(Buffer.from(JSON.stringify(contentEnc)), note.id)
  audit(req.user.id, 'protect_note', String(note.id), req)
  res.json({ ok: true })
})

app.post('/search/reindex', auth, (req, res) => {
  const { noteId, hashes } = req.body || {}
  if (!noteId || !Array.isArray(hashes)) return res.status(400).json({ error: 'invalid' })
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(noteId, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM blind_index WHERE user_id=? AND note_id=?').run(req.user.id, noteId)
    const insert = db.prepare('INSERT INTO blind_index(user_id, term_hash, note_id) VALUES(?,?,?)')
    hashes.forEach(h => insert.run(req.user.id, h, noteId))
  })
  tx()
  audit(req.user.id, 'reindex_terms', String(noteId), req)
  res.json({ ok: true })
})

app.get('/notes', auth, (req, res) => {
  const rows = db.prepare('SELECT id, updated_at, title_encrypted, title_plain, size_padded, protected, shared, share_permission FROM notes WHERE user_id=? ORDER BY updated_at DESC').all(req.user.id)
  const items = rows.map(r => ({ id: r.id, updatedAt: r.updated_at, titleEnc: r.title_encrypted ? JSON.parse(r.title_encrypted) : null, titlePlain: r.title_plain || null, sizePadded: r.size_padded, protected: r.protected, shared: r.shared || 0, sharePermission: r.share_permission || null }))
  res.json({ items })
})

app.get('/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id=? AND user_id=?').get(req.params.id, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const blob = db.prepare('SELECT blob_encrypted FROM note_blobs WHERE note_id=? ORDER BY chunk_index ASC').get(note.id)
  const content = JSON.parse(blob.blob_encrypted.toString())
  res.json({ id: note.id, protected: note.protected, noteSalt: note.note_salt || null, titlePlain: note.title_plain || null, noteKeyEnvelope: note.note_key_envelope ? JSON.parse(note.note_key_envelope) : null, titleEnc: note.title_encrypted ? JSON.parse(note.title_encrypted) : null, contentEnc: content, shared: note.shared || 0, sharePermission: note.share_permission || null, updatedAt: note.updated_at })
})

app.post('/search/index', auth, (req, res) => {
  const { noteId, hashes } = req.body || {}
  if (!noteId || !Array.isArray(hashes)) return res.status(400).json({ error: 'invalid' })
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(noteId, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const insert = db.prepare('INSERT INTO blind_index(user_id, term_hash, note_id) VALUES(?,?,?)')
  const tx = db.transaction(hs => { hs.forEach(h => insert.run(req.user.id, h, noteId)) })
  tx(hashes)
  audit(req.user.id, 'index_terms', String(noteId), req)
  res.json({ ok: true })
})

app.post('/search', auth, (req, res) => {
  const { hash } = req.body || {}
  if (!hash) return res.status(400).json({ error: 'invalid' })
  const rows = db.prepare('SELECT note_id FROM blind_index WHERE user_id=? AND term_hash=?').all(req.user.id, hash)
  res.json({ ids: rows.map(r => r.note_id) })
})

app.post('/shares', auth, (req, res) => {
  const { noteId, recipientEmail, nkEnvelopeForLink, permission } = req.body || {}
  if (!noteId || !recipientEmail || !nkEnvelopeForLink) return res.status(400).json({ error: 'invalid' })
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(noteId, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const rec = db.prepare('SELECT id FROM users WHERE email=?').get(recipientEmail)
  if (!rec) return res.status(404).json({ error: 'recipient_not_found' })
  const token = crypto.randomBytes(24).toString('hex')
  const info = db.prepare('INSERT INTO shares(note_id, owner_id, recipient_id, nk_envelope_for_link, share_token, permission, created_at) VALUES(?,?,?,?,?,?,?)')
    .run(noteId, req.user.id, rec.id, JSON.stringify(nkEnvelopeForLink), token, (permission === 'rw' ? 'rw' : 'ro'), now())
  audit(req.user.id, 'share_note', String(noteId), req)
  res.json({ id: info.lastInsertRowid, token })
})

app.get('/shares/:token', auth, (req, res) => {
  const share = db.prepare('SELECT * FROM shares WHERE share_token=?').get(req.params.token)
  if (!share) return res.status(404).json({ error: 'not_found' })
  if (share.recipient_id !== req.user.id) return res.status(403).json({ error: 'forbidden' })
  const note = db.prepare('SELECT * FROM notes WHERE id=?').get(share.note_id)
  const blob = db.prepare('SELECT blob_encrypted FROM note_blobs WHERE note_id=? ORDER BY chunk_index ASC').get(note.id)
  res.json({
    noteId: note.id,
    nkEnvelopeForLink: JSON.parse(share.nk_envelope_for_link),
    titlePlain: note.title_plain || null,
    permission: share.permission || 'ro',
    contentEnc: JSON.parse(blob.blob_encrypted.toString())
  })
})

app.post('/shares/:token/accept', auth, (req, res) => {
  const { noteId } = req.body || {}
  const share = db.prepare('SELECT * FROM shares WHERE share_token=?').get(req.params.token)
  if (!share) return res.status(404).json({ error: 'not_found' })
  if (share.recipient_id !== req.user.id) return res.status(403).json({ error: 'forbidden' })
  if (!noteId) return res.status(400).json({ error: 'invalid' })
  db.prepare('UPDATE shares SET accepted=1, accepted_note_id=? WHERE id=?').run(noteId, share.id)
  db.prepare('UPDATE notes SET shared=1, share_permission=? WHERE id=? AND user_id=?').run(share.permission || 'ro', noteId, req.user.id)
  audit(req.user.id, 'share_accept', String(noteId), req)
  res.json({ ok: true })
})

app.post('/shares/sync', auth, (req, res) => {
  const { noteId, title, contentHtml } = req.body || {}
  if (!noteId || typeof title !== 'string' || typeof contentHtml !== 'string') return res.status(400).json({ error: 'invalid' })
  const links = db.prepare('SELECT * FROM shares WHERE (note_id=? OR accepted_note_id=?) AND accepted=1').all(noteId, noteId)
  let updated = 0
  const tx = db.transaction(() => {
    for (const s of links) {
      if (s.note_id === noteId) {
        // owner -> recipient
        if (!s.accepted_note_id) continue
        db.prepare('UPDATE notes SET title_plain=?, updated_at=?, size_padded=?, shared=1, share_permission=? WHERE id=? AND user_id=?')
          .run(title, now(), Buffer.byteLength(contentHtml), s.permission || 'ro', s.accepted_note_id, s.recipient_id)
        const blob = { alg: 'PLAIN', data: contentHtml }
        db.prepare('UPDATE note_blobs SET blob_encrypted=? WHERE note_id=? AND chunk_index=0')
          .run(Buffer.from(JSON.stringify(blob)), s.accepted_note_id)
        updated++
      } else if (s.accepted_note_id === noteId && (s.permission || 'ro') === 'rw') {
        // recipient -> owner (only rw)
        db.prepare('UPDATE notes SET title_plain=?, updated_at=?, size_padded=?, shared=1, share_permission=? WHERE id=? AND user_id=?')
          .run(title, now(), Buffer.byteLength(contentHtml), s.permission || 'ro', s.note_id, s.owner_id)
        const blob = { alg: 'PLAIN', data: contentHtml }
        db.prepare('UPDATE note_blobs SET blob_encrypted=? WHERE note_id=? AND chunk_index=0')
          .run(Buffer.from(JSON.stringify(blob)), s.note_id)
        updated++
      }
    }
  })
  tx()
  audit(req.user.id, 'share_sync', String(noteId), req)
  res.json({ ok: true, updated })
})

app.delete('/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT id FROM notes WHERE id=? AND user_id=?').get(req.params.id, req.user.id)
  if (!note) return res.status(404).json({ error: 'not_found' })
  const tx = db.transaction(id => {
    db.prepare('DELETE FROM note_blobs WHERE note_id=?').run(id)
    db.prepare('DELETE FROM blind_index WHERE note_id=? AND user_id=?').run(id, req.user.id)
    db.prepare('DELETE FROM shares WHERE note_id=? AND owner_id=?').run(id, req.user.id)
    db.prepare('DELETE FROM notes WHERE id=?').run(id)
  })
  tx(note.id)
  audit(req.user.id, 'delete_note', String(note.id), req)
  res.json({ ok: true })
})

app.get('/', (req, res) => {
  res.redirect('/login')
})
app.get('/login', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'client', 'login.html'))
})
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'client', 'dashboard.html'))
})
app.use('/', express.static(path.join(process.cwd(), 'client')))

const port = process.env.PORT || 3333
app.listen(port, () => { console.log(`listening ${port}`) })

