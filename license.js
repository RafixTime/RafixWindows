const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

const DATA_PATH = path.join(__dirname, 'licenses.json');

function readLicenses() {
  const raw = fs.readFileSync(DATA_PATH, 'utf-8');
  return JSON.parse(raw).licenses;
}

function writeLicenses(licenses) {
  fs.writeFileSync(DATA_PATH, JSON.stringify({ licenses }, null, 2));
}

/**
 * POST /api/license/check
 * body: { code: string }
 */
router.post('/check', (req, res) => {
  const { code } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ valid: false, error: 'code is required' });
  }

  const licenses = readLicenses();
  const found = licenses.find((l) => l.code === code.trim());

  if (!found) {
    return res.status(404).json({ valid: false, error: 'code not found' });
  }
  if (found.active === false) {
    return res.status(200).json({ valid: false, error: 'code disabled' });
  }
  if (found.expires_at && new Date(found.expires_at) < new Date()) {
    return res.status(200).json({ valid: false, error: 'code expired' });
  }

  return res.status(200).json({ valid: true, code: found.code, expires_at: found.expires_at });
});

/**
 * POST /api/license/register
 * body: { code: string, expires_at?: string }
 * Требует заголовок x-admin-secret
 *
 * ВАЖНО: на бесплатном плане Render файловая система сбрасывается
 * при каждом передеплое/засыпании. Это нормально для старта,
 * но для постоянного хранения позже стоит вернуться к базе данных.
 */
router.post('/register', (req, res) => {
  const adminSecret = req.header('x-admin-secret');
  if (!process.env.ADMIN_SECRET || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { code, expires_at } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'code is required' });
  }

  const licenses = readLicenses();
  if (licenses.find((l) => l.code === code.trim())) {
    return res.status(409).json({ error: 'code already exists' });
  }

  licenses.push({ code: code.trim(), active: true, expires_at: expires_at || null });
  writeLicenses(licenses);

  return res.status(201).json({ created: true, code: code.trim() });
});

module.exports = router;
