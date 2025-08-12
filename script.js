// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const { URLSearchParams } = require('url');

const app = express();
app.use(express.json());

// Конфиг из .env
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;
const ADMIN_IP = process.env.ADMIN_IP;

const SUPABASE_HEADERS = {
  apikey: SUPABASE_KEY,
  Authorization: `Bearer ${SUPABASE_KEY}`,
  'Content-Type': 'application/json',
};

const KEY_REGEX = /^Tw3ch1k_[0-9oasuxclO68901\-]{16,}$/;
const HWID_REGEX = /^[0-9A-Fa-f\-]{5,}$/;
const IP_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function validateKey(key) {
  return KEY_REGEX.test(key);
}

function validateHwid(hwid) {
  return HWID_REGEX.test(hwid);
}

function validateIp(ip) {
  return IP_REGEX.test(ip);
}

function isAdminRequest(req) {
  const adminHeader = req.headers['x-admin-key'];
  const adminQuery = req.query.d;
  const key = adminHeader || adminQuery;
  return key === ADMIN_KEY;
}

function generateKey(length = 16) {
  const partE = 'oasuxclO';
  const partF = '68901';
  const B = Math.floor(length * 0.7);
  const G = length - B;
  const arr = [];

  for (let i = 0; i < B; i++) arr.push(partF[Math.floor(Math.random() * partF.length)]);
  for (let i = 0; i < G; i++) arr.push(partE[Math.floor(Math.random() * partE.length)]);
  arr.sort(() => Math.random() - 0.5);

  const D = arr.join('');
  const groups = [];
  for (let i = 0; i < D.length; i += 4) {
    groups.push(D.substring(i, i + 4));
  }
  return `Tw3ch1k_${groups.join('-')}`;
}

async function saveKey(key = null) {
  const A = key || generateKey();
  const B = new Date().toISOString();
  const C = { key: A, created_at: B, used: false };

  try {
    const res = await axios.post(`${SUPABASE_URL}/rest/v1/keys`, C, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (res.status === 201) return A;
  } catch (e) {
    // fail silently
  }
  return null;
}

function getUserId(ip, hwid) {
  return Buffer.from(`${ip}_${hwid}`).toString('base64');
}

// Rate limiters
const limiter20PerMinute = rateLimit({ windowMs: 60000, max: 20 });
const limiter10PerMinute = rateLimit({ windowMs: 60000, max: 10 });
const limiter5PerMinute = rateLimit({ windowMs: 60000, max: 5 });

app.post('/api/clean_old_keys', limiter20PerMinute, async (req, res) => {
  if (!isAdminRequest(req)) return res.status(403).json({ error: 'Access denied' });

  const days = parseInt(req.body.days) || 1;
  const cutoff = new Date(Date.now() - days * 24 * 3600 * 1000);

  try {
    const response = await axios.get(`${SUPABASE_URL}/rest/v1/keys`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (response.status !== 200) return res.status(500).json({ error: 'Failed to fetch keys', details: response.data });

    const keys = response.data;
    let deletedCount = 0;

    for (const keyObj of keys) {
      if (!keyObj.created_at) continue;
      const createdDate = new Date(keyObj.created_at);
      if (createdDate < cutoff) {
        try {
          const delRes = await axios.delete(`${SUPABASE_URL}/rest/v1/keys?key=eq.${encodeURIComponent(keyObj.key)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
          if (delRes.status === 204) deletedCount++;
        } catch {}
      }
    }
    return res.json({ deleted: deletedCount });
  } catch {
    return res.status(500).json({ error: 'Failed to fetch keys' });
  }
});

app.get('/api/get_key', limiter10PerMinute, async (req, res) => {
  const key = await saveKey();
  if (!key) return res.status(500).json({ error: 'Failed to save key' });
  return res.json({ key });
});

app.get('/api/verify_key', limiter20PerMinute, async (req, res) => {
  const key = req.query.key;
  if (!key || !validateKey(key)) return res.type('text').send('invalid');

  try {
    const response = await axios.get(`${SUPABASE_URL}/rest/v1/keys?key=eq.${encodeURIComponent(key)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (response.status !== 200 || response.data.length === 0) return res.type('text').send('invalid');

    const keyObj = response.data[0];
    if (keyObj.used) return res.type('text').send('used');

    const createdAt = new Date(keyObj.created_at);
    if (Date.now() - createdAt.getTime() > 24 * 3600 * 1000) return res.type('text').send('expired');

    // Mark as used
    const patchRes = await axios.patch(`${SUPABASE_URL}/rest/v1/keys?key=eq.${encodeURIComponent(key)}`, { used: true }, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (patchRes.status === 204) return res.type('text').send('valid');
  } catch {
    return res.status(500).type('text').send('error');
  }
  return res.status(500).type('text').send('error');
});

app.post('/api/save_user', limiter5PerMinute, async (req, res) => {
  const ip = req.ip || 'unknown_ip';
  const ipToUse = validateIp(ip) ? ip : 'unknown_ip';

  const { cookies = '', hwid, key } = req.body || {};
  if (!hwid || !validateHwid(hwid)) return res.status(400).json({ error: 'Missing or invalid HWID' });

  const userId = getUserId(ipToUse, hwid);

  try {
    // Check if user exists
    const userRes = await axios.get(`${SUPABASE_URL}/rest/v1/users?user_id=eq.${encodeURIComponent(userId)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (userRes.status !== 200) return res.status(500).json({ error: 'Failed to query user' });
    if (userRes.data.length > 0) {
      return res.json({ status: 'exists', key: userRes.data[0].key, registered_at: userRes.data[0].registered_at });
    }
  } catch {
    return res.status(500).json({ error: 'Failed to query user' });
  }

  // Validate or generate key
  let keyToSave = key;
  if (keyToSave) {
    if (!validateKey(keyToSave)) {
      keyToSave = await saveKey();
    } else {
      try {
        const keyCheck = await axios.get(`${SUPABASE_URL}/rest/v1/keys?key=eq.${encodeURIComponent(keyToSave)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
        if (keyCheck.status !== 200 || keyCheck.data.length === 0) keyToSave = await saveKey();
      } catch {
        keyToSave = await saveKey();
      }
    }
  } else {
    keyToSave = await saveKey();
  }

  if (!keyToSave) return res.status(500).json({ error: 'Failed to save key' });

  const now = new Date().toISOString();
  const userObj = { user_id: userId, cookies, hwid, key: keyToSave, registered_at: now };

  try {
    const saveRes = await axios.post(`${SUPABASE_URL}/rest/v1/users`, userObj, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (saveRes.status !== 201) return res.status(500).json({ error: 'Failed to save user' });
  } catch {
    return res.status(500).json({ error: 'Failed to save user' });
  }

  return res.json({ status: 'saved', key: keyToSave, registered_at: now });
});

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/style.css', (req, res) => res.sendFile(__dirname + '/style.css'));

app.get('/user/admin', async (req, res) => {
  if (!isAdminRequest(req)) return res.status(403).send('Access denied');
  try {
    const keysRes = await axios.get(`${SUPABASE_URL}/rest/v1/keys`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    const usersRes = await axios.get(`${SUPABASE_URL}/rest/v1/users`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (keysRes.status !== 200 || usersRes.status !== 200) return res.status(500).send('Failed to fetch data');

    const keys = keysRes.data;
    const users = usersRes.data;

    let html = `
      <html><head><title>Admin Panel</title><style>
        body { font-family: monospace; background: #121212; color: #eee; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #666; padding: 8px; }
        th { background: #222; }
        button { background: #f33; color: white; border: none; padding: 4px 8px; cursor: pointer; }
      </style>
      <script>
        async function del(url, payload) {
          const res = await fetch(url, {
            method: "POST",
            headers: {'Content-Type': 'application/json', 'X-Admin-Key': '${ADMIN_KEY}'},
            body: JSON.stringify(payload)
          });
          alert(await res.text());
          location.reload();
        }
      </script>
      </head><body>
      <h1>🔑 Keys</h1>
      <h2>🧹 Очистка</h2>
      <button onclick="del('/api/clean_old_keys', {days: 1})">Удалить ключи старше 24ч</button>
      <table><tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>`;

    keys.forEach(k => {
      html += `<tr><td>${k.key}</td><td>${k.used}</td><td>${k.created_at}</td>
        <td><button onclick="del('/api/delete_key', {key: '${k.key}'})">Delete</button></td></tr>`;
    });

    html += `</table><h1>👤 Users</h1><table><tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>`;

    users.forEach(u => {
      html += `<tr><td>${u.user_id}</td><td>${u.hwid}</td><td>${u.cookies}</td><td>${u.key}</td><td>${u.registered_at}</td>
        <td><button onclick="del('/api/delete_user', {hwid: '${u.hwid}'})">Delete</button></td></tr>`;
    });

    html += `</table></body></html>`;

    res.send(html);

  } catch {
    res.status(500).send('Failed to fetch data');
  }
});

app.post('/api/delete_key', async (req, res) => {
  if (!isAdminRequest(req)) return res.status(403).send('Access denied');

  const key = req.body.key;
  if (!key || !validateKey(key)) return res.status(400).send('Missing or invalid key');

  try {
    const delRes = await axios.delete(`${SUPABASE_URL}/rest/v1/keys?key=eq.${encodeURIComponent(key)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (delRes.status === 204) return res.send('Key deleted');
    return res.status(500).send(`Failed to delete: ${delRes.data}`);
  } catch {
    return res.status(500).send('Database request failed');
  }
});

app.post('/api/delete_user', async (req, res) => {
  if (!isAdminRequest(req)) return res.status(403).send('Access denied');

  const hwid = req.body.hwid;
  if (!hwid || !validateHwid(hwid)) return res.status(400).send('Missing or invalid hwid');

  try {
    const delRes = await axios.delete(`${SUPABASE_URL}/rest/v1/users?hwid=eq.${encodeURIComponent(hwid)}`, { headers: SUPABASE_HEADERS, timeout: 5000 });
    if (delRes.status === 204) return res.send('User deleted');
    return res.status(500).send(`Failed to delete: ${delRes.data}`);
  } catch {
    return res.status(500).send('Database request failed');
  }
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
