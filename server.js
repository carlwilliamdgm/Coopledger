const http = require('http');
const fs = require('fs');
const path = require('path');
const https = require('https');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Keypair } = require('@stellar/stellar-sdk');
require('dotenv').config();

const pool = require('./db');
const {
  authenticate,
  authorize,
  generateToken,
  generateDemoToken,
  verifyTokenUnsafe,
  isAdminBlocked,
  recordFailedAdminLogin,
  resetAdminFailedAttempts,
  logAdminAction,
} = require('./auth');
const transactionService = require('./transaction');
const webpush = require('web-push');

const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 3000;
/** @type {Map<import('http').ServerResponse, { role: string }>} */
const sseClients = new Map();

let webPushConfigured = false;
/** @type {string|null} */
let cachedVapidPublicKey = null;

function configureWebPushVapid() {
  const subject = String(process.env.VAPID_SUBJECT || '').trim();
  let publicKey = process.env.VAPID_PUBLIC_KEY;
  let privateKey = process.env.VAPID_PRIVATE_KEY;

  if (!publicKey || !privateKey) {
    const generated = webpush.generateVAPIDKeys();
    publicKey = generated.publicKey;
    privateKey = generated.privateKey;
    console.log('Clefs VAPID generees — definissez VAPID_PUBLIC_KEY et VAPID_PRIVATE_KEY dans Railway :');
    console.log(`VAPID_PUBLIC_KEY=${publicKey}`);
    console.log(`VAPID_PRIVATE_KEY=${privateKey}`);
  }

  cachedVapidPublicKey = publicKey || null;

  if (!subject || !publicKey || !privateKey) {
    if (!subject) {
      console.warn('VAPID_SUBJECT non defini (mailto:contact@...). Web Push desactive jusqu a configuration.');
    }
    webPushConfigured = false;
    return;
  }

  webpush.setVapidDetails(subject, publicKey, privateKey);
  webPushConfigured = true;
}

const DEMO_SESSION = {
  data: null,
};

function notificationMatchesDestinataires(userRole, destinataires) {
  const raw = cleanString(destinataires) || 'tous';
  if (raw.toLowerCase() === 'tous') {
    return true;
  }
  if (isAdminRole(userRole)) {
    return true;
  }
  const normalizedUser = normalizeRole(userRole);
  const targets = raw.split(',').map((segment) => normalizeRole(segment)).filter(Boolean);
  return targets.includes(normalizedUser);
}
const BUREAU_POSTES = ['president', 'tresorier', 'secretaire', 'verificateur'];
const CONFIG_KEYS_EDITABLE = ['nom_coop', 'duree_mandat', 'duree_inactivite_mois'];
const CONFIG_KEYS_SECRET = new Set(['stellar_secret_key', 'cle_unique']);
const FEDAPAY_TRANSACTION_ENDPOINT = 'https://sandbox-api.fedapay.com/v1/transactions';
const ALLOWED_MEMBER_ROLES = ['president', 'tresorier', 'secretaire', 'verificateur', 'membre', 'observateur', 'admin'];

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, payload) {
  if (res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendError(res, err) {
  let status = err.status || 500;

  if (err.code === '23505') {
    status = 409;
  } else if (err.code === '23503') {
    status = 400;
  }

  const message = status === 500 ? 'Erreur interne du serveur.' : err.message;

  if (status === 500) {
    console.error(err);
  }

  sendJson(res, status, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new HttpError(413, 'Payload trop volumineux.'));
        req.destroy();
      }
    });

    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new HttpError(400, 'JSON invalide.'));
      }
    });
  });
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new HttpError(413, 'Payload trop volumineux.'));
        req.destroy();
      }
    });

    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function postJson(url, payload, headers = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const parsedUrl = new URL(url);
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      path: parsedUrl.pathname + (parsedUrl.search || ''),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...headers,
      },
    };

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => { responseBody += chunk; });
      res.on('end', () => {
        let data = {};
        try {
          data = responseBody ? JSON.parse(responseBody) : {};
        } catch (err) {
          return reject(new HttpError(502, 'Reponse invalide de FedaPay.'));
        }
        resolve({ status: res.statusCode || 0, ok: res.statusCode >= 200 && res.statusCode < 300, data });
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function addNativeResponseHelpers(res) {
  res.status = (statusCode) => ({
    json: (payload) => sendJson(res, statusCode, payload),
  });
  res.json = (payload) => sendJson(res, 200, payload);
  return res;
}

function runMiddleware(middleware, req, res) {
  addNativeResponseHelpers(res);

  return new Promise((resolve, reject) => {
    const next = (err) => {
      if (err) reject(err);
      else resolve();
    };

    try {
      const result = middleware(req, res, next);

      if (result && typeof result.then === 'function') {
        result
          .then(() => {
            if (res.writableEnded) resolve();
          })
          .catch(reject);
      } else if (res.writableEnded) {
        resolve();
      }
    } catch (err) {
      reject(err);
    }
  });
}

async function requireAuth(req, res) {
  await runMiddleware(authenticate, req, res);
  if (res.writableEnded) {
    throw new HttpError(401, 'Authentification requise.');
  }
}

async function requireRoles(req, res, ...roles) {
  await runMiddleware(authorize(...roles), req, res);
  if (res.writableEnded) {
    throw new HttpError(403, 'Acces non autorise.');
  }
}

function cleanString(value) {
  return String(value ?? '').trim();
}

function parsePositiveInteger(value, fieldName) {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new HttpError(400, `${fieldName} doit etre un entier positif.`);
  }

  return parsed;
}

function parseNonZeroInteger(value, fieldName) {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed === 0) {
    throw new HttpError(400, `${fieldName} doit etre un entier non nul.`);
  }

  return parsed;
}

function getRequestIp(req) {
  return cleanString(req.headers['x-forwarded-for']).split(',')[0]
    || req.socket.remoteAddress
    || '';
}

function normalizeRole(role) {
  return cleanString(role).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function normalizeStatutComparable(value) {
  return cleanString(value).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

function isAdminRole(role) {
  return normalizeRole(role) === 'admin';
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_]{3,20}$/.test(username);
}

function normalizePoste(poste) {
  const normalized = normalizeRole(poste);
  if (normalized === 'tresoriere') return 'tresorier';
  if (normalized === 'secretaire') return 'secretaire';
  if (normalized === 'verificateur') return 'verificateur';
  return normalized;
}

function hideSensitiveMember(member) {
  const { password_hash: _passwordHash, ...safeMember } = member;
  return safeMember;
}

function normalizeConfigCle(cle) {
  return cleanString(cle).toLowerCase();
}

function parseConfigStorageValue(cle, raw) {
  const k = normalizeConfigCle(cle);
  if (!CONFIG_KEYS_EDITABLE.includes(k)) {
    throw new HttpError(400, 'Cle de configuration non modifiable.');
  }
  if (k === 'nom_coop') {
    const v = cleanString(raw);
    if (!v) {
      throw new HttpError(400, 'valeur invalide pour nom_coop.');
    }
    if (v.length > 200) {
      throw new HttpError(400, 'nom_coop trop long.');
    }
    return v;
  }
  return String(parsePositiveInteger(raw, k));
}

async function writeConfigValue(cle, rawValue) {
  const k = normalizeConfigCle(cle);
  const stored = parseConfigStorageValue(k, rawValue);
  await pool.query(
    `INSERT INTO config (cle, valeur) VALUES ($1, $2)
     ON CONFLICT (cle) DO UPDATE SET valeur = EXCLUDED.valeur`,
    [k, stored],
  );
  return stored;
}

function serializeVote(vote) {
  return {
    ...vote,
    pour: Number(vote.pour || 0),
    contre: Number(vote.contre || 0),
  };
}

async function countActiveMembers() {
  const result = await pool.query("SELECT COUNT(*)::int AS total FROM members WHERE statut = 'Actif'");
  return Number(result.rows[0]?.total || 0);
}

async function getMandateExpirationDate() {
  const result = await pool.query('SELECT valeur FROM config WHERE cle = $1', ['duree_mandat']);
  const months = Number(result.rows[0]?.valeur || 12);
  const expiresAt = new Date();
  expiresAt.setMonth(expiresAt.getMonth() + months);
  return expiresAt;
}

async function ensureVacancyForPoste(poste) {
  const cleanPoste = normalizePoste(poste);
  const existing = await pool.query(
    `SELECT * FROM postes_vacants
     WHERE poste = $1 AND statut IN ('vacant', 'candidature')
     ORDER BY created_at DESC
     LIMIT 1`,
    [cleanPoste]
  );

  if (existing.rows[0]) {
    return existing.rows[0];
  }

  const result = await pool.query(
    `INSERT INTO postes_vacants (poste, statut)
     VALUES ($1, $2)
     RETURNING *`,
    [cleanPoste, 'vacant']
  );
  return result.rows[0];
}

async function closeCandidaturePeriodByVacancy(vacancyId, automated = true) {
  const vacancyResult = await pool.query('SELECT * FROM postes_vacants WHERE id = $1', [vacancyId]);
  const vacancy = vacancyResult.rows[0];

  if (!vacancy || !['vacant', 'candidature'].includes(vacancy.statut)) {
    return null;
  }

  const candidates = await pool.query(
    `SELECT candidatures.*, members.nom
     FROM candidatures
     JOIN members ON members.id = candidatures.member_id
     WHERE candidatures.poste = $1
       AND candidatures.statut = 'ouvert'
       AND candidatures.expires_at <= NOW()
     ORDER BY candidatures.created_at ASC`,
    [vacancy.poste]
  );

  if (!candidates.rows.length) {
    await pool.query(
      `UPDATE postes_vacants SET created_at = NOW(), statut = 'candidature' WHERE id = $1`,
      [vacancy.id]
    );
    await createNotification(`Aucune candidature pour ${vacancy.poste}. Periode relancee 72h.`, 'candidature', 'tous');
    return null;
  }

  await pool.query(
    `UPDATE candidatures SET statut = 'fermé'
     WHERE poste = $1 AND statut = 'ouvert'`,
    [vacancy.poste]
  );
  await pool.query('UPDATE postes_vacants SET statut = $1 WHERE id = $2', ['vote', vacancy.id]);

  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);
  const vote = await pool.query(
    `INSERT INTO votes (titre, budget, duree_heures, expires_at, type, poste, poste_vacant_id)
     VALUES ($1, 0, 72, $2, 'election', $3, $4)
     RETURNING *`,
    [`Election ${vacancy.poste}`, expiresAt, vacancy.poste, vacancy.id]
  );

  await createNotification(`Vote d election ouvert pour ${vacancy.poste}.`, 'vote', 'tous');
  return vote.rows[0];
}

async function createMemberRecord({ nom, username, email, password, role = 'membre' }) {
  const cleanNom = cleanString(nom);
  const cleanUsername = cleanString(username);
  const cleanEmail = cleanString(email).toLowerCase();
  const cleanPassword = cleanString(password);
  const cleanRole = normalizePoste(role) || 'membre';

  if (!cleanNom || !cleanUsername || !cleanEmail || !cleanPassword) {
    throw new HttpError(400, 'nom, username, email et password sont obligatoires.');
  }

  if (!isValidUsername(cleanUsername)) {
    throw new HttpError(400, 'username doit contenir 3 a 20 caracteres alphanumeriques ou underscore.');
  }

  const duplicateChecks = await pool.query(
    `SELECT
       EXISTS(SELECT 1 FROM members WHERE lower(username) = lower($1)) AS username_exists,
       EXISTS(SELECT 1 FROM members WHERE lower(email) = lower($2)) AS email_exists,
       EXISTS(SELECT 1 FROM members WHERE lower(nom) = lower($3)) AS nom_exists`,
    [cleanUsername, cleanEmail, cleanNom]
  );
  const duplicates = duplicateChecks.rows[0] || {};
  if (duplicates.username_exists) {
    throw new HttpError(409, 'Cet identifiant est déjà pris');
  }
  if (duplicates.email_exists) {
    throw new HttpError(409, 'Cet email est déjà utilisé');
  }
  if (duplicates.nom_exists) {
    throw new HttpError(409, 'Un membre avec ce nom existe déjà');
  }

  const passwordHash = await bcrypt.hash(cleanPassword, 12);
  const result = await pool.query(
    `INSERT INTO members (nom, username, email, password_hash, role)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, nom, username, email, role, role_expires_at, statut, created_at`,
    [cleanNom, cleanUsername, cleanEmail, passwordHash, cleanRole]
  );

  return result.rows[0];
}

function serveStatic(req, res, pathname) {
  const requestedPath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.normalize(path.join(PUBLIC_DIR, requestedPath));

  if (!filePath.startsWith(PUBLIC_DIR)) {
    throw new HttpError(403, 'Acces interdit.');
  }

  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    throw new HttpError(404, 'Ressource introuvable.');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = mimeTypes[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': contentType });
  fs.createReadStream(filePath).pipe(res);
}

async function createNotification(message, type, destinataires = 'tous') {
  const dest = cleanString(destinataires) || 'tous';
  const result = await pool.query(
    'INSERT INTO notifications (message, type, destinataires) VALUES ($1, $2, $3) RETURNING *',
    [message, type, dest],
  );
  const notification = result.rows[0];
  pushNotification(notification);
  return notification;
}

function pushNotification(notification) {
  const payload = `data: ${JSON.stringify(notification)}\n\n`;

  for (const [client, meta] of sseClients) {
    if (notificationMatchesDestinataires(meta.role, notification.destinataires)) {
      try {
        client.write(payload);
      } catch (err) {
        sseClients.delete(client);
      }
    }
  }

  dispatchWebPush(notification).catch(err => console.error('Web push erreur:', err));
}

async function dispatchWebPush(notification) {
  if (!webPushConfigured) {
    return;
  }

  let memberIds;

  const raw = cleanString(notification.destinataires) || 'tous';
  if (raw.toLowerCase() === 'tous') {
    const allMembers = await pool.query('SELECT id FROM members');
    memberIds = allMembers.rows.map((row) => row.id);
  } else {
    const targets = raw.split(',').map((segment) => normalizeRole(segment)).filter(Boolean);
    if (!targets.length) {
      return;
    }
    const res = await pool.query(
      `SELECT id FROM members
       WHERE translate(lower(role), 'éèêëàâäîïôöùûüç', 'eeeeaaaiioouuuc') = ANY($1::text[])`,
      [targets]
    );
    memberIds = res.rows.map((row) => row.id);
    const admins = await pool.query(
      `SELECT id FROM members
       WHERE translate(lower(role), 'éèêëàâäîïôöùûüç', 'eeeeaaaiioouuuc') = 'admin'`
    );
    const merged = new Set(memberIds);
    admins.rows.forEach((row) => merged.add(row.id));
    memberIds = Array.from(merged);
  }

  if (!memberIds.length) {
    return;
  }

  const subs = await pool.query(
    'SELECT id, subscription FROM push_subscriptions WHERE member_id = ANY($1::int[])',
    [memberIds],
  );

  const body = JSON.stringify({
    title: 'CoopLedger',
    body: notification.message || '',
    data: {
      url: '/',
      type: notification.type || '',
    },
    tag: `coop-${notification.id}`,
  });

  for (const row of subs.rows) {
    const sub = row.subscription;
    try {
      await webpush.sendNotification(sub, body);
    } catch (err) {
      if (Number(err.statusCode) === 410 || Number(err.statusCode) === 404) {
        await pool.query('DELETE FROM push_subscriptions WHERE id = $1', [row.id]);
      }
    }
  }
}

async function register(req, res) {
  const { nom, username, email, password, role } = await readBody(req);
  const requestedRole = normalizePoste(role || 'membre');

  if (!['membre', 'observateur'].includes(requestedRole)) {
    throw new HttpError(403, 'Inscription publique limitee aux roles membre ou observateur.');
  }

  const member = await createMemberRecord({ nom, username, email, password, role: requestedRole });
  const token = generateToken(member);

  await createNotification(`Nouveau membre inscrit: ${member.nom}`, 'membre', 'secretaire');
  sendJson(res, 201, { token, member });
}

async function createMemberByAdmin(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin', 'secretaire', 'secrétaire');

  const body = await readBody(req);
  const member = await createMemberRecord(body);

  await createNotification(`Nouveau membre cree par le bureau: ${member.nom}`, 'membre', 'secretaire');
  sendJson(res, 201, { member });
}

async function updateMemberStatut(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin', 'secretaire', 'secrétaire');

  const memberId = parsePositiveInteger(id, 'member_id');
  const { statut } = await readBody(req);
  const next = cleanString(statut);

  if (!['Actif', 'Inactif'].includes(next)) {
    throw new HttpError(400, 'statut doit etre Actif ou Inactif.');
  }

  const updated = await pool.query(
    `UPDATE members SET statut = $1 WHERE id = $2 RETURNING id, nom, username, role, statut`,
    [next, memberId],
  );

  if (updated.rowCount === 0) {
    throw new HttpError(404, 'Membre introuvable.');
  }

  await createNotification(`Statut mis a jour (${next}): ${updated.rows[0].nom}`, 'membre', 'secretaire');
  sendJson(res, 200, { member: updated.rows[0] });
}

async function getPushPublicKey(req, res) {
  sendJson(res, 200, { public_key: cachedVapidPublicKey || '' });
}

async function pushSubscribe(req, res) {
  await requireAuth(req, res);

  if (!webPushConfigured) {
    throw new HttpError(503, 'Notifications push non configurees (VAPID_SUBJECT ou clefs manquants).');
  }

  const body = await readBody(req);
  const subscription = body.subscription || body;

  if (!subscription || !subscription.endpoint) {
    throw new HttpError(400, 'subscription invalide.');
  }

  const memberId = Number(req.user.id);
  await pool.query(
    `DELETE FROM push_subscriptions WHERE subscription->>'endpoint' = $1`,
    [subscription.endpoint],
  );

  await pool.query(
    `INSERT INTO push_subscriptions (member_id, subscription)
     VALUES ($1, $2::jsonb)`,
    [memberId, subscription],
  );

  sendJson(res, 201, { success: true });
}

function maskInstanceKey(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  if (s.length <= 8) return `${s.slice(0, 2)}••••${s.slice(-2)}`;
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

async function pushUnsubscribe(req, res) {
  await requireAuth(req, res);

  const body = await readBody(req);
  const endpoint = cleanString(body.endpoint || body.subscription?.endpoint || '');

  if (!endpoint) {
    throw new HttpError(400, 'endpoint requis.');
  }

  const memberId = Number(req.user.id);
  await pool.query(
    `DELETE FROM push_subscriptions
     WHERE subscription->>'endpoint' = $1 AND member_id = $2`,
    [endpoint, memberId],
  );

  sendJson(res, 200, { success: true });
}

async function login(req, res) {
  const { username, password } = await readBody(req);
  const cleanUsername = cleanString(username);
  const cleanLogin = cleanUsername.toLowerCase();
  const cleanPassword = cleanString(password);

  if (!cleanUsername || !cleanPassword) {
    throw new HttpError(400, 'username et password sont obligatoires.');
  }

  const adminEmail = cleanString(process.env.ADMIN_EMAIL).toLowerCase();
  if (adminEmail && cleanLogin === adminEmail) {
    if (isAdminBlocked(cleanLogin)) {
      throw new HttpError(403, 'Compte admin bloque apres 3 tentatives echouees.');
    }

    if (cleanPassword !== process.env.ADMIN_PASSWORD) {
      recordFailedAdminLogin(cleanLogin);
      throw new HttpError(401, 'Identifiants invalides.');
    }

    resetAdminFailedAttempts(cleanLogin);

    const admin = {
      id: 0,
      nom: 'Admin',
      email: cleanLogin,
      role: 'admin',
      role_expires_at: null,
    };
    const token = generateToken(admin);
    sendJson(res, 200, { token, member: admin });
    return;
  }

  const result = await pool.query('SELECT * FROM members WHERE username = $1', [cleanUsername]);
  const member = result.rows[0];
  const isAdmin = member && isAdminRole(member.role);

  if (isAdmin && isAdminBlocked(cleanUsername)) {
    throw new HttpError(403, 'Compte admin bloque apres 3 tentatives echouees.');
  }

  const passwordOk = member
    ? await bcrypt.compare(cleanPassword, member.password_hash)
    : false;

  if (!member || !passwordOk) {
    if (isAdmin) {
      recordFailedAdminLogin(cleanUsername);
    }

    throw new HttpError(401, 'Identifiants invalides.');
  }

  if (isAdmin) {
    resetAdminFailedAttempts(cleanUsername);
  }

  const safeMember = hideSensitiveMember(member);
  const token = generateToken(safeMember);
  sendJson(res, 200, { token, member: safeMember });
}

async function initConfig(req, res) {
  const existing = await pool.query('SELECT 1 FROM config WHERE cle = $1 LIMIT 1', ['nom_coop']);

  if (existing.rowCount > 0) {
    throw new HttpError(409, 'CoopLedger est deja configure.');
  }

  const { nom_coop, nomCoop, duree_mandat, dureeMandat } = await readBody(req);
  const coopName = cleanString(nom_coop || nomCoop);
  const mandateDuration = parsePositiveInteger(duree_mandat || dureeMandat, 'duree_mandat');
  const uniqueKey = crypto.randomBytes(32).toString('hex');
  const stellarAccount = Keypair.random();

  if (!coopName) {
    throw new HttpError(400, 'nom_coop est obligatoire.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO config (cle, valeur)
       VALUES ($1, $2), ($3, $4), ($5, $6), ($7, $8), ($9, $10)`,
      [
        'nom_coop',
        coopName,
        'duree_mandat',
        String(mandateDuration),
        'cle_unique',
        uniqueKey,
        'stellar_public_key',
        stellarAccount.publicKey(),
        'stellar_secret_key',
        stellarAccount.secret(),
      ]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  await createNotification('Configuration initiale terminee.', 'config', 'tous');
  sendJson(res, 201, {
    config: {
      nom_coop: coopName,
      duree_mandat: mandateDuration,
      cle_unique: uniqueKey,
      stellar_public_key: stellarAccount.publicKey(),
    },
  });
}

async function getPublicConfig(req, res) {
  const result = await pool.query('SELECT valeur FROM config WHERE cle = $1', ['nom_coop']);
  sendJson(res, 200, { nom_coop: result.rows[0]?.valeur || null });
}

async function listAllConfigAdmin(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const result = await pool.query('SELECT cle, valeur FROM config ORDER BY cle');
  const config = {};
  for (const row of result.rows) {
    if (!CONFIG_KEYS_SECRET.has(row.cle)) {
      config[row.cle] = row.valeur;
    }
  }
  const cleUnique = await pool.query("SELECT valeur FROM config WHERE cle = 'cle_unique' LIMIT 1");
  config.cle_unique_masked = maskInstanceKey(cleUnique.rows[0]?.valeur);
  sendJson(res, 200, { config });
}

async function putConfigKey(req, res, cleParam) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const cle = normalizeConfigCle(decodeURIComponent(cleParam || ''));
  const body = await readBody(req);
  const valeur = body.valeur ?? body.value;
  const stored = await writeConfigValue(cle, valeur);

  await logAdminAction(`Configuration ${cle} mise a jour`, getRequestIp(req));
  await createNotification(
    `Configuration mise à jour par l'administrateur : ${cle}`,
    'config',
    'tous',
  );
  sendJson(res, 200, { cle, valeur: stored });
}

async function listMembers(req, res) {
  await requireAuth(req, res);

  const role = normalizeRole(req.user?.role);
  if (['membre', 'observateur'].includes(role)) {
    throw new HttpError(403, 'Acces non autorise.');
  }

  if (role === 'admin' || role === 'secretaire') {
    const result = await pool.query(
      `SELECT m.id, m.nom, m.username, m.email, m.role, m.role_expires_at, m.statut, m.created_at,
         (SELECT COUNT(*)::int FROM cotisations c WHERE c.member_id = m.id)::int AS cotisations_count
       FROM members m
       ORDER BY m.created_at DESC`
    );
    return sendJson(res, 200, { members: result.rows });
  }

  if (['president', 'tresorier', 'tresoriere', 'verificateur'].includes(role)) {
    const result = await pool.query(
      `SELECT id, nom, role, statut
       FROM members
       ORDER BY created_at DESC`
    );
    return sendJson(res, 200, { members: result.rows });
  }

  throw new HttpError(403, 'Acces non autorise.');
}

async function updateMemberRole(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin', 'secretaire', 'secrétaire');

  const body = await readBody(req);
  const cleanRole = normalizePoste(body.role);
  const normalizedCallerRole = normalizeRole(req.user?.role);
  const isCallerAdmin = normalizedCallerRole === 'admin';

  if (!cleanRole) {
    throw new HttpError(400, 'role est obligatoire.');
  }

  if (!ALLOWED_MEMBER_ROLES.includes(cleanRole)) {
    throw new HttpError(400, 'Role invalide.');
  }

  if (!isCallerAdmin) {
    const voteId = parsePositiveInteger(body.vote_id, 'vote_id');
    const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [voteId]);
    if (!vote.rows[0] || vote.rows[0].statut !== 'validé') {
      throw new HttpError(400, 'Le vote associe doit etre valide.');
    }
  }

  let roleExpiresAt = null;
  if (cleanRole !== 'membre' && cleanRole !== 'observateur' && cleanRole !== 'admin') {
    const durationMonths = body.duree_mandat_mois != null
      ? parsePositiveInteger(body.duree_mandat_mois, 'duree_mandat_mois')
      : null;

    if (durationMonths) {
      roleExpiresAt = new Date();
      roleExpiresAt.setMonth(roleExpiresAt.getMonth() + durationMonths);
    } else {
      roleExpiresAt = await getMandateExpirationDate();
    }
  }

  const result = await pool.query(
    `UPDATE members
     SET role = $1, role_expires_at = $2
     WHERE id = $3
     RETURNING id, nom, username, email, role, role_expires_at, statut, created_at`,
    [cleanRole, roleExpiresAt, id]
  );

  if (result.rowCount === 0) {
    throw new HttpError(404, 'Membre introuvable.');
  }

  await createNotification(`Role attribue a ${result.rows[0].nom}: ${cleanRole}`, 'membre', 'tous');
  if (isCallerAdmin) {
    await logAdminAction(`Role ${cleanRole} attribue au membre ${id}`, getRequestIp(req));
  }
  sendJson(res, 200, { member: result.rows[0] });
}

async function listTransactions(req, res) {
  await requireAuth(req, res);

  const rawUrl = `http://${req.headers.host || 'localhost'}${req.url || ''}`;
  const url = new URL(rawUrl);
  const typeFilter = cleanString(url.searchParams.get('type')).toLowerCase();
  const statutFilter = cleanString(url.searchParams.get('statut')).toLowerCase();
  const dateFrom = cleanString(url.searchParams.get('date_from'));
  const dateTo = cleanString(url.searchParams.get('date_to'));

  const txResult = await pool.query('SELECT * FROM transactions ORDER BY date DESC');
  const cotResult = await pool.query(
    `SELECT
       ('cot_' || id::text) AS id,
       date,
       ('Cotisation (' || mode || ')') AS libelle,
       montant,
       hash,
       explorer,
       statut,
       member_id,
       NULL::integer AS vote_id
     FROM cotisations
     WHERE hash IS NOT NULL AND hash <> ''`
  );

  const rows = [];

  for (const row of txResult.rows) {
    const inferredType = row.type
      || (Number(row.montant) < 0 ? 'depense' : 'recette');
    rows.push({ ...row, type: inferredType, source: 'transaction' });
  }

  for (const row of cotResult.rows) {
    rows.push({
      ...row,
      type: 'cotisation',
      source: 'cotisation',
    });
  }

  rows.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  const filtered = rows.filter((row) => {
    if (typeFilter && typeFilter !== 'tous' && cleanString(row.type).toLowerCase() !== typeFilter) {
      return false;
    }
    if (statutFilter && normalizeStatutComparable(row.statut) !== normalizeStatutComparable(statutFilter)) {
      return false;
    }
    if (dateFrom) {
      const t = new Date(row.date).getTime();
      if (t < new Date(dateFrom).setHours(0, 0, 0, 0)) {
        return false;
      }
    }
    if (dateTo) {
      const t = new Date(row.date).getTime();
      if (t > new Date(dateTo).setHours(23, 59, 59, 999)) {
        return false;
      }
    }
    return true;
  });

  sendJson(res, 200, { transactions: filtered });
}

async function createTransaction(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'tresorier', 'trésorier');

  const { libelle, montant, member_id, vote_id, type } = await readBody(req);
  const cleanLibelle = cleanString(libelle);
  const txType = cleanString(type).toLowerCase() || 'recette';
  const voteId = parsePositiveInteger(vote_id, 'vote_id');

  if (!cleanLibelle) {
    throw new HttpError(400, 'libelle est obligatoire.');
  }

  if (!['recette', 'depense'].includes(txType)) {
    throw new HttpError(400, 'type doit etre recette ou depense.');
  }

  const amountAbs = parseNonZeroInteger(montant, 'montant');
  const amount = txType === 'depense' ? -Math.abs(amountAbs) : Math.abs(amountAbs);

  const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [voteId]);
  if (!vote.rows[0] || vote.rows[0].statut !== 'validé') {
    throw new HttpError(400, 'Le vote associe doit etre valide.');
  }

  let stellar;
  try {
    stellar = await transactionService.enregistrerTransaction(cleanLibelle, amount);
  } catch (err) {
    console.error(err);
    throw new HttpError(502, 'Echec du scellement Stellar.');
  }

  const { hash, explorer } = stellar;
  const id = `tx_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const result = await pool.query(
    `INSERT INTO transactions (id, libelle, montant, type, hash, explorer, member_id, vote_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING *`,
    [id, cleanLibelle, amount, txType, hash, explorer, member_id || null, voteId]
  );

  const avUpdate = await pool.query(
    `UPDATE actions_votees
     SET statut = 'concrétisé', confirme_par = $1, confirme_at = NOW()
     WHERE vote_id = $2 AND statut = 'en_attente'
     RETURNING titre`,
    [Number(req.user.id), voteId],
  );

  if (avUpdate.rowCount > 0) {
    const titreAction = cleanString(avUpdate.rows[0]?.titre) || cleanLibelle;
    await createNotification(
      `Action concrétisée : ${titreAction} — transaction scellée sur Stellar. Hash : ${hash}`,
      'transaction',
      'tous',
    );
  }

  await createNotification(`Transaction scellee: ${cleanLibelle}`, 'transaction', 'tresorier,verificateur');
  sendJson(res, 201, { transaction: result.rows[0] });
}

async function listVotes(req, res) {
  await requireAuth(req, res);
  const memberId = Number(req.user.id);
  const result = await pool.query('SELECT * FROM votes ORDER BY created_at DESC');
  const votes = [];

  for (const row of result.rows) {
    const v = serializeVote(row);
    if (row.type === 'election') {
      const aVote = await pool.query(
        `SELECT 1 FROM vote_results WHERE vote_id = $1 AND member_id = $2`,
        [row.id, memberId],
      );
      v.a_vote = aVote.rowCount > 0;
      if (row.statut !== 'ouvert') {
        const tally = await pool.query(
          `SELECT vr.choix, COUNT(*)::int AS voix,
                  m.nom AS nom_complet
           FROM vote_results vr
           LEFT JOIN candidatures c ON c.id = NULLIF(TRIM(vr.choix), '')::integer
           LEFT JOIN members m ON m.id = c.member_id
           WHERE vr.vote_id = $1
           GROUP BY vr.choix, m.nom
           ORDER BY voix DESC`,
          [row.id],
        );
        v.decompte_voix = tally.rows.map((r) => ({
          candidature_id: r.choix,
          nom_complet: r.nom_complet || '—',
          voix: r.voix,
        }));
      }
    }
    votes.push(v);
  }

  sendJson(res, 200, { votes });
}

async function createVote(req, res) {
  await requireAuth(req, res);

  const body = await readBody(req);
  const voteType = cleanString(body.type).toLowerCase() || 'decision';

  if (voteType === 'election') {
    const activeMembers = await countActiveMembers();
    if (activeMembers < 4) {
      throw new HttpError(403, 'Minimum 4 membres actifs requis pour ouvrir une election.');
    }
  } else if (voteType === 'config') {
    await requireRoles(req, res, 'president', 'président');
  } else {
    await requireRoles(req, res, 'president', 'président');
  }

  const durationHours = Math.max(Number(body.duree_heures || 72), 72);
  if (!Number.isInteger(durationHours)) {
    throw new HttpError(400, 'duree_heures invalide.');
  }

  const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);

  if (voteType === 'config') {
    const cleConfig = normalizeConfigCle(body.cle_config || body.cle);
    const preview = parseConfigStorageValue(cleConfig, body.nouvelle_valeur);
    const cleanTitle = `Configuration : ${cleConfig} → ${preview}`;
    const result = await pool.query(
      `INSERT INTO votes (titre, budget, propose_par, duree_heures, expires_at, type, cle_config, nouvelle_valeur)
       VALUES ($1, 0, $2, $3, $4, 'config', $5, $6)
       RETURNING *`,
      [cleanTitle, req.user.id, durationHours, expiresAt, cleConfig, preview]
    );
    await createNotification(`Nouvelle proposition de configuration: ${cleConfig}`, 'vote', 'tous');
    sendJson(res, 201, { vote: serializeVote(result.rows[0]) });
    return;
  }

  const cleanTitle = cleanString(body.titre);
  const amount = voteType === 'election' ? Number(body.budget || 0) : parsePositiveInteger(body.budget, 'budget');

  if (!cleanTitle) {
    throw new HttpError(400, 'titre est obligatoire.');
  }

  const result = await pool.query(
    `INSERT INTO votes (titre, budget, propose_par, duree_heures, expires_at, type)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [cleanTitle, amount, req.user.id, durationHours, expiresAt, voteType]
  );

  await createNotification(`Nouvelle proposition: ${cleanTitle}`, 'vote', 'tous');
  sendJson(res, 201, { vote: serializeVote(result.rows[0]) });
}

async function castVote(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'membre');

  const { choix } = await readBody(req);
  const cleanChoice = cleanString(choix).toLowerCase();

  const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  if (!vote.rows[0] || vote.rows[0].statut !== 'ouvert') {
    throw new HttpError(400, 'Vote introuvable ou ferme.');
  }

  const currentVote = vote.rows[0];
  const isElection = currentVote.type === 'election';

  if (!isElection && !['pour', 'contre'].includes(cleanChoice)) {
    throw new HttpError(400, 'choix doit etre pour ou contre.');
  }

  if (isElection) {
    const candidate = await pool.query(
      `SELECT id FROM candidatures
       WHERE id = $1 AND poste = $2 AND statut IN ('fermé', 'ferme')`,
      [Number(cleanChoice), currentVote.poste]
    );

    if (candidate.rowCount === 0) {
      throw new HttpError(400, 'Candidat invalide pour cette election.');
    }
  }

  if (currentVote.expires_at && new Date(currentVote.expires_at).getTime() <= Date.now()) {
    throw new HttpError(400, 'Ce vote est expire.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'INSERT INTO vote_results (vote_id, member_id, choix) VALUES ($1, $2, $3)',
      [id, req.user.id, cleanChoice]
    );
    await client.query(
      `UPDATE votes
       SET pour = pour + $1, contre = contre + $2
       WHERE id = $3`,
      [!isElection && cleanChoice === 'pour' ? 1 : 0, !isElection && cleanChoice === 'contre' ? 1 : 0, id]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      throw new HttpError(409, 'Vous avez deja vote.');
    }
    throw err;
  } finally {
    client.release();
  }

  await createNotification('Un vote a ete enregistre.', 'vote', 'tous');
  sendJson(res, 201, { success: true });
}

async function prolongVote(req, res, id) {
  await requireAuth(req, res);

  const callerRole = normalizeRole(req.user?.role);
  if (callerRole !== 'admin') {
    throw new HttpError(403, 'Acces non autorise.');
  }

  const { nouvelle_duree_heures } = await readBody(req);
  const hours = parsePositiveInteger(nouvelle_duree_heures, 'nouvelle_duree_heures');

  const result = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  const vote = result.rows[0];

  if (!vote) {
    throw new HttpError(404, 'Vote introuvable.');
  }

  if (vote.statut !== 'ouvert') {
    throw new HttpError(400, 'Ce vote nest pas ouvert.');
  }

  const expiryMs = vote.expires_at ? new Date(vote.expires_at).getTime() : Date.now();
  const baseMs = Math.max(Date.now(), expiryMs);
  const expiresAt = new Date(baseMs + hours * 60 * 60 * 1000);
  const newDuration = Number(vote.duree_heures || 72) + hours;

  const updated = await pool.query(
    `UPDATE votes SET expires_at = $1, duree_heures = $2 WHERE id = $3 RETURNING *`,
    [expiresAt, newDuration, id],
  );

  await createNotification(`Vote prolonge (${hours}h): ${vote.titre}`, 'vote', 'tous');
  sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
}

async function closeVote(req, res, id, automatedClose = false) {
  if (!automatedClose) {
    await requireAuth(req, res);
  }

  const callerRole = normalizeRole(req.user?.role);
  const isCallerAdmin = callerRole === 'admin';
  const isBureauCloser = ['president', 'tresorier'].includes(callerRole);

  const result = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  const vote = result.rows[0];

  if (!vote) {
    throw new HttpError(404, 'Vote introuvable.');
  }

  if (vote.statut !== 'ouvert') {
    throw new HttpError(400, 'Ce vote est deja ferme.');
  }

  if (!automatedClose) {
    if (!isCallerAdmin) {
      if (!isBureauCloser) {
        throw new HttpError(403, 'Acces non autorise pour la cloture manuelle.');
      }
      const expired = !vote.expires_at || new Date(vote.expires_at).getTime() <= Date.now();
      if (!expired) {
        throw new HttpError(400, 'Ce vote n est pas encore expire.');
      }
    }
  }

  if (vote.type === 'election') {
    const tally = await pool.query(
      `SELECT choix, COUNT(*)::int AS voix
       FROM vote_results
       WHERE vote_id = $1
       GROUP BY choix
       ORDER BY voix DESC`,
      [id]
    );

    const topScore = Number(tally.rows[0]?.voix || 0);
    const winners = tally.rows.filter(row => Number(row.voix) === topScore);

    if (!topScore || winners.length > 1) {
      if (Number(vote.round || 1) < 2) {
        const updated = await pool.query(
          `UPDATE votes
           SET round = round + 1, expires_at = $1
           WHERE id = $2
           RETURNING *`,
          [new Date(Date.now() + 48 * 60 * 60 * 1000), id]
        );
        await createNotification(`Egalite sur l election ${vote.poste}. Vote reconduit 48h.`, 'vote', 'tous');
        sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
        return;
      }

      const rejected = await pool.query(
        `UPDATE votes SET statut = 'rejeté' WHERE id = $1 RETURNING *`,
        [id]
      );
      await createNotification(`Election ${vote.poste} rejetee apres deux egalites.`, 'vote', 'tous');
      sendJson(res, 200, { vote: serializeVote(rejected.rows[0]) });
      return;
    }

    const winnerCandidature = await pool.query(
      `SELECT candidatures.*, members.nom
       FROM candidatures
       JOIN members ON members.id = candidatures.member_id
       WHERE candidatures.id = $1`,
      [Number(winners[0].choix)]
    );
    const candidature = winnerCandidature.rows[0];

    if (!candidature) {
      throw new HttpError(400, 'Candidature gagnante introuvable.');
    }

    const expiresAt = await getMandateExpirationDate();
    await pool.query(
      `UPDATE members
       SET role = $1, role_expires_at = $2
       WHERE id = $3`,
      [vote.poste, expiresAt, candidature.member_id]
    );
    await pool.query('UPDATE postes_vacants SET statut = $1 WHERE id = $2', ['pourvu', vote.poste_vacant_id]);
    await pool.query('UPDATE votes SET statut = $1 WHERE id = $2', ['validé', id]);

    await createNotification(`${candidature.nom} obtient le poste ${vote.poste}.`, 'membre', 'tous');
    sendJson(res, 200, { winner: candidature.member_id, poste: vote.poste });
    return;
  }

  let status = 'rejeté';
  let expiresAt = vote.expires_at;
  let durationHours = vote.duree_heures;

  if (Number(vote.pour) > Number(vote.contre)) {
    status = 'validé';
  } else if (Number(vote.pour) === Number(vote.contre)) {
    if (Number(vote.duree_heures) < 120) {
      status = 'ouvert';
      durationHours = Number(vote.duree_heures) + 48;
      expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    } else {
      status = 'rejeté';
    }
  }

  const updated = await pool.query(
    `UPDATE votes
     SET statut = $1, duree_heures = $2, expires_at = $3
     WHERE id = $4
     RETURNING *`,
    [status, durationHours, expiresAt, id]
  );

  const closed = updated.rows[0];

  if (status === 'ouvert') {
    await createNotification(`Vote "${vote.titre}" prolonge (egalite des voix).`, 'vote', 'tous');
  } else if (status === 'validé') {
    const voteType = cleanString(vote.type).toLowerCase() || 'decision';
    if (voteType === 'config') {
      const applied = await writeConfigValue(vote.cle_config, vote.nouvelle_valeur);
      await createNotification(
        `Configuration mise à jour suite au vote : ${vote.cle_config} → ${applied}`,
        'config',
        'tous',
      );
    } else if (voteType === 'decision') {
      const budgetNum = Number(vote.budget || 0);
      await pool.query(
        `INSERT INTO actions_votees (vote_id, titre, budget)
         VALUES ($1, $2, $3)
         ON CONFLICT (vote_id) DO NOTHING`,
        [id, vote.titre, budgetNum],
      );
      await createNotification(
        `Vote validé : ${vote.titre} — ${budgetNum} FCFA approuvés. En attente de concrétisation.`,
        'vote',
        'tous',
      );
      await createNotification(
        `Action à concrétiser : ${vote.titre} — ${budgetNum} FCFA. Créez la transaction associée.`,
        'vote',
        'tresorier',
      );
    } else {
      await createNotification(`Vote "${vote.titre}" ${status}.`, 'vote', 'tous');
    }
  } else {
    await createNotification(`Vote "${vote.titre}" ${status}.`, 'vote', 'tous');
  }

  sendJson(res, 200, { vote: serializeVote(closed) });
}

async function cancelVote(req, res, id) {
  await requireAuth(req, res);

  const existing = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  if (!existing.rows[0]) {
    throw new HttpError(404, 'Vote introuvable.');
  }

  const vote = existing.rows[0];
  const callerRole = normalizeRole(req.user.role);
  let allowed = false;

  if (callerRole === 'admin') {
    allowed = true;
  } else if (callerRole === 'president') {
    if (vote.type === 'election') {
      allowed = false;
    } else if (
      vote.statut === 'ouvert'
      && Number(vote.propose_par || 0) === Number(req.user.id)
      && Number(vote.pour || 0) === 0
      && Number(vote.contre || 0) === 0
    ) {
      allowed = true;
    }
  }

  if (!allowed) {
    throw new HttpError(403, 'Acces non autorise pour cette annulation.');
  }

  const updated = await pool.query(
    `UPDATE votes SET statut = $1 WHERE id = $2 RETURNING *`,
    ['annulé', id],
  );

  const label = callerRole === 'admin' ? 'Vote annule par la direction' : 'Proposition retiree par le president';
  await createNotification(`${label}`, 'vote', 'tous');
  if (callerRole === 'admin') {
    await logAdminAction(`Vote ${id} annule`, getRequestIp(req));
  }

  sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
}

async function resetMemberPassword(req, res, memberId) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const body = await readBody(req);
  const newPassword = cleanString(body.nouveau_password);
  if (!newPassword || newPassword.length < 6) {
    throw new HttpError(400, 'Minimum 6 caracteres.');
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  const updated = await pool.query(
    `UPDATE members
     SET password_hash = $1
     WHERE id = $2
     RETURNING id`,
    [passwordHash, memberId]
  );

  if (updated.rowCount === 0) {
    throw new HttpError(404, 'Membre introuvable.');
  }

  await logAdminAction(`Mot de passe reinitialise pour le membre ${memberId}`, getRequestIp(req));
  sendJson(res, 200, { success: true });
}

async function createCotisation(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'tresorier', 'trésorier');

  const { member_id, montant, mode } = await readBody(req);
  const memberId = parsePositiveInteger(member_id, 'member_id');
  const amount = parsePositiveInteger(montant, 'montant');
  const cleanMode = cleanString(mode);

  if (!cleanMode) {
    throw new HttpError(400, 'mode est obligatoire.');
  }

  const memberRes = await pool.query('SELECT nom FROM members WHERE id = $1', [memberId]);
  const nomMembre = cleanString(memberRes.rows[0]?.nom) || `membre_${memberId}`;
  const libelleStellar = `Cotisation_${nomMembre.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '_')}_${memberId}`;

  let stellar;
  try {
    stellar = await transactionService.enregistrerTransaction(libelleStellar, amount);
  } catch (err) {
    console.error(err);
    throw new HttpError(502, 'Echec du scellement Stellar.');
  }

  const result = await pool.query(
    `INSERT INTO cotisations (member_id, montant, mode, hash, explorer)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [memberId, amount, cleanMode, stellar.hash, stellar.explorer]
  );

  await createNotification('Cotisation enregistree.', 'cotisation', 'tresorier');
  sendJson(res, 201, { cotisation: result.rows[0] });
}

async function initierFedapay(req, res) {
  await requireAuth(req, res);

  const { montant } = await readBody(req);
  const amount = parsePositiveInteger(montant, 'montant');
  const apiKey = cleanString(process.env.FEDAPAY_SERVER_KEY);
  if (!apiKey) {
    throw new HttpError(500, 'FEDAPAY_SERVER_KEY manquant.');
  }
  const baseUrl = cleanString(process.env.PUBLIC_BASE_URL).replace(/\/$/, '');
  const proto = cleanString(req.headers['x-forwarded-proto']).split(',')[0] || 'http';
  const callbackUrl = baseUrl
    ? `${baseUrl}/api/cotisations/webhook`
    : `${proto}://${req.headers.host}/api/cotisations/webhook`;

  const response = await postJson(FEDAPAY_TRANSACTION_ENDPOINT, {
    description: 'Cotisation CoopLedger',
    amount,
    currency: { iso: 'XOF' },
    callback_url: callbackUrl,
    metadata: { member_id: req.user.id },
  }, {
    Authorization: `Bearer ${apiKey}`,
  });

  const data = response.data;
  console.log('FedaPay response:', JSON.stringify(data));
  if (!response.ok) {
    throw new HttpError(response.status, data.error || 'Erreur lors de la creation de la transaction FedaPay.');
  }

  const token = data?.v1?.token || data?.token || data?.payment_token || data?.transaction?.token;
  const url = data.url || data.payment_url || data.redirect_url || data.transaction?.payment_url;

  if (!token) {
    console.error('FedaPay token absent dans la reponse API:', JSON.stringify(data));
    sendJson(res, 502, { error: 'Paiement temporairement indisponible' });
    return;
  }
  if (!url) {
    throw new HttpError(502, 'Reponse incomplette de FedaPay (URL absente).');
  }

  sendJson(res, 200, { token, url });
}

function timingSafeCompare(valueA, valueB) {
  const bufA = Buffer.from(String(valueA), 'utf8');
  const bufB = Buffer.from(String(valueB), 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function verifyFedapaySignature(rawSignature, rawBody) {
  const secret = process.env.FEDAPAY_SECRET;
  if (!secret || !rawSignature) {
    return false;
  }

  const actualSignature = cleanString(rawSignature).replace(/^sha256=/i, '');
  const hmac = crypto.createHmac('sha256', secret).update(rawBody);
  const expectedHex = hmac.digest('hex');
  const expectedBase64 = Buffer.from(expectedHex, 'hex').toString('base64');

  return timingSafeCompare(actualSignature, expectedHex) || timingSafeCompare(actualSignature, expectedBase64);
}

async function listCandidatures(req, res) {
  await requireAuth(req, res);
  const memberId = Number(req.user.id);

  const vacancies = await pool.query(
    `SELECT * FROM postes_vacants
     WHERE statut IN ('vacant', 'candidature', 'vote', 'annulé', 'pourvu')
     ORDER BY created_at DESC`,
  );

  const enriched = [];

  for (const pv of vacancies.rows) {
    const deadline = new Date(new Date(pv.created_at).getTime() + 72 * 60 * 60 * 1000);

    const candRows = await pool.query(
      `SELECT c.id, c.member_id, c.statut, m.nom AS nom_complet
       FROM candidatures c
       JOIN members m ON m.id = c.member_id
       WHERE c.poste = $1
         AND c.statut IN ('ouvert', 'fermé', 'ferme')`,
      [pv.poste],
    );

    const estCandidat = candRows.rows.some((c) => Number(c.member_id) === memberId);

    const voteRes = await pool.query(
      `SELECT * FROM votes WHERE poste_vacant_id = $1 AND type = 'election'
       ORDER BY id DESC LIMIT 1`,
      [pv.id],
    );
    const electionVote = voteRes.rows[0] || null;

    let decompteVoix = null;
    let aVote = false;
    if (electionVote) {
      const vrCheck = await pool.query(
        `SELECT 1 FROM vote_results WHERE vote_id = $1 AND member_id = $2`,
        [electionVote.id, memberId],
      );
      aVote = vrCheck.rowCount > 0;

      if (electionVote.statut !== 'ouvert') {
        const tally = await pool.query(
          `SELECT vr.choix, COUNT(*)::int AS voix,
                  m.nom AS nom_complet
           FROM vote_results vr
           LEFT JOIN candidatures c ON c.id = NULLIF(TRIM(vr.choix), '')::integer
           LEFT JOIN members m ON m.id = c.member_id
           WHERE vr.vote_id = $1
           GROUP BY vr.choix, m.nom
           ORDER BY voix DESC`,
          [electionVote.id],
        );
        decompteVoix = tally.rows.map((r) => ({
          candidature_id: r.choix,
          nom_complet: r.nom_complet || '—',
          voix: r.voix,
        }));
      }
    }

    enriched.push({
      ...pv,
      date_limite_candidature: deadline.toISOString(),
      nombre_candidatures: candRows.rows.length,
      candidats: candRows.rows.map((c) => ({
        id: c.id,
        member_id: c.member_id,
        nom_complet: c.nom_complet,
        nom: c.nom_complet,
        statut: c.statut,
      })),
      est_candidat: estCandidat,
      election_vote: electionVote,
      decompte_voix: decompteVoix,
      a_vote: aVote,
    });
  }

  sendJson(res, 200, { candidatures: enriched });
}

async function createCandidature(req, res) {
  await requireAuth(req, res);

  const activeMembers = await countActiveMembers();
  if (activeMembers < 4) {
    throw new HttpError(403, 'Minimum 4 membres actifs requis pour ouvrir une election.');
  }

  const member = await pool.query("SELECT id, statut FROM members WHERE id = $1 AND statut = 'Actif'", [req.user.id]);
  if (member.rowCount === 0) {
    throw new HttpError(403, 'Seul un membre actif peut se porter candidat.');
  }

  const { poste } = await readBody(req);
  const cleanPoste = normalizePoste(poste);

  if (!BUREAU_POSTES.includes(cleanPoste)) {
    throw new HttpError(400, 'Poste invalide.');
  }

  const existing = await pool.query(
    `SELECT 1 FROM candidatures
     WHERE member_id = $1 AND statut = 'ouvert' AND expires_at > NOW()
     LIMIT 1`,
    [req.user.id]
  );
  if (existing.rowCount > 0) {
    throw new HttpError(409, 'Vous avez deja une candidature ouverte.');
  }

  const vacancy = await ensureVacancyForPoste(cleanPoste);
  if (vacancy.statut === 'vacant') {
    await pool.query('UPDATE postes_vacants SET statut = $1, created_at = NOW() WHERE id = $2', ['candidature', vacancy.id]);
    vacancy.created_at = new Date();
  }
  const expiresAt = new Date(new Date(vacancy.created_at).getTime() + 72 * 60 * 60 * 1000);
  const result = await pool.query(
    `INSERT INTO candidatures (poste, member_id, expires_at)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [cleanPoste, req.user.id, expiresAt]
  );

  await createNotification(`Nouvelle candidature pour le poste ${cleanPoste}.`, 'candidature', 'secretaire');
  sendJson(res, 201, { candidature: result.rows[0] });
}

async function closeCandidaturePeriod(req, res, id) {
  await requireAuth(req, res);
  const vacancyId = Number(id);
  const isCallerAdmin = normalizeRole(req.user?.role) === 'admin';

  const vacancyResult = await pool.query('SELECT * FROM postes_vacants WHERE id = $1', [vacancyId]);
  const vacancyRow = vacancyResult.rows[0];
  if (!vacancyRow) {
    throw new HttpError(404, 'Election introuvable.');
  }

  if (!isCallerAdmin) {
    const deadlineMs = new Date(vacancyRow.created_at).getTime() + 72 * 60 * 60 * 1000;
    if (Date.now() < deadlineMs) {
      throw new HttpError(403, 'La periode de candidature n est pas encore expiree.');
    }
  }

  await closeCandidaturePeriodByVacancy(vacancyId, false);
  sendJson(res, 200, { success: true });
}

async function annulerCandidatureElection(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const vacancyId = Number(id);
  const vacancyResult = await pool.query('SELECT * FROM postes_vacants WHERE id = $1', [vacancyId]);
  const vacancyRow = vacancyResult.rows[0];
  if (!vacancyRow) {
    throw new HttpError(404, 'Election introuvable.');
  }

  await pool.query(
    `UPDATE candidatures SET statut = 'annulé'
     WHERE poste = $1 AND statut IN ('ouvert', 'fermé', 'ferme')`,
    [vacancyRow.poste],
  );
  await pool.query(
    `UPDATE votes SET statut = 'annulé'
     WHERE poste_vacant_id = $1 AND type = 'election' AND statut = 'ouvert'`,
    [vacancyId],
  );

  const updatedPv = await pool.query(
    `UPDATE postes_vacants SET statut = 'annulé' WHERE id = $1 RETURNING *`,
    [vacancyId],
  );

  await createNotification('Élection annulée par l\'administrateur', 'vote', 'tous');
  await logAdminAction(`Election (poste vacant ${vacancyId}) annulee`, getRequestIp(req));

  sendJson(res, 200, { candidature: updatedPv.rows[0] });
}

async function prolongCandidatureElection(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const vacancyId = Number(id);
  const { nouvelle_duree_heures } = await readBody(req);
  const hours = parsePositiveInteger(nouvelle_duree_heures, 'nouvelle_duree_heures');

  const vacancyResult = await pool.query('SELECT * FROM postes_vacants WHERE id = $1', [vacancyId]);
  const pv = vacancyResult.rows[0];
  if (!pv) {
    throw new HttpError(404, 'Election introuvable.');
  }

  if (pv.statut === 'candidature') {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const oldCreatedMs = new Date(pv.created_at).getTime();
      const newCreatedAt = new Date(oldCreatedMs + hours * 60 * 60 * 1000);
      const newDeadline = new Date(newCreatedAt.getTime() + 72 * 60 * 60 * 1000);
      const updatedPv = await client.query(
        `UPDATE postes_vacants SET created_at = $1 WHERE id = $2 RETURNING *`,
        [newCreatedAt, vacancyId],
      );
      await client.query(
        `UPDATE candidatures SET expires_at = $1 WHERE poste = $2 AND statut = 'ouvert'`,
        [newDeadline, pv.poste],
      );
      await client.query('COMMIT');

      await createNotification("Période prolongée par l'administrateur", 'candidature', 'tous');
      await logAdminAction(
        `Periode de candidature prolongee de ${hours}h (poste vacant ${vacancyId})`,
        getRequestIp(req),
      );
      sendJson(res, 200, { poste_vacant: updatedPv.rows[0] });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    return;
  }

  if (pv.statut === 'vote') {
    const voteRes = await pool.query(
      `SELECT * FROM votes
       WHERE poste_vacant_id = $1 AND type = 'election' AND statut = 'ouvert'
       ORDER BY id DESC LIMIT 1`,
      [vacancyId],
    );
    const vote = voteRes.rows[0];
    if (!vote) {
      throw new HttpError(400, 'Aucun vote d election ouvert pour ce poste.');
    }

    const expiryMs = vote.expires_at ? new Date(vote.expires_at).getTime() : Date.now();
    const baseMs = Math.max(Date.now(), expiryMs);
    const expiresAt = new Date(baseMs + hours * 60 * 60 * 1000);
    const newDuration = Number(vote.duree_heures || 72) + hours;

    const updated = await pool.query(
      `UPDATE votes SET expires_at = $1, duree_heures = $2 WHERE id = $3 RETURNING *`,
      [expiresAt, newDuration, vote.id],
    );

    await createNotification("Période prolongée par l'administrateur", 'vote', 'tous');
    await logAdminAction(
      `Vote d election prolonge de ${hours}h (poste vacant ${vacancyId}, vote ${vote.id})`,
      getRequestIp(req),
    );
    sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
    return;
  }

  throw new HttpError(400, 'Prolongation disponible seulement pour les statuts candidature ou vote.');
}

async function fedapayWebhook(req, res) {
  const rawBody = await readRawBody(req);
  const signatureHeader = req.headers['x-fedapay-signature'] || req.headers['x-fedapay-signature-256'] || req.headers['x-fp-signature'] || req.headers['x-fedapay-signaturesha256'];

  if (!verifyFedapaySignature(signatureHeader, rawBody)) {
    throw new HttpError(401, 'Signature invalide.');
  }

  const payload = rawBody ? JSON.parse(rawBody) : {};
  const status = cleanString(payload.status || payload.statut || payload.transaction?.status).toLowerCase();

  if (!['approved', 'confirmed', 'confirmé', 'confirme', 'paid'].includes(status)) {
    sendJson(res, 202, { success: true, ignored: true });
    return;
  }

  const memberId = parsePositiveInteger(payload.member_id || payload.metadata?.member_id, 'member_id');
  const amount = parsePositiveInteger(payload.montant || payload.amount || payload.transaction?.amount, 'montant');

  const memberRes = await pool.query('SELECT nom FROM members WHERE id = $1', [memberId]);
  const nomMembre = cleanString(memberRes.rows[0]?.nom) || `membre_${memberId}`;
  const libelleStellar = `Cotisation_FedaPay_${nomMembre.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '_')}_${memberId}`;

  let stellar;
  try {
    stellar = await transactionService.enregistrerTransaction(libelleStellar, amount);
  } catch (err) {
    console.error(err);
    throw new HttpError(502, 'Echec du scellement Stellar.');
  }

  const result = await pool.query(
    `INSERT INTO cotisations (member_id, montant, mode, statut, hash, explorer)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [memberId, amount, 'FedaPay', 'confirmé', stellar.hash, stellar.explorer]
  );

  await createNotification('Cotisation FedaPay confirmee.', 'cotisation', 'tresorier');
  sendJson(res, 201, { cotisation: result.rows[0] });
}

async function myCotisations(req, res) {
  await requireAuth(req, res);
  const result = await pool.query(
    'SELECT * FROM cotisations WHERE member_id = $1 ORDER BY date DESC',
    [req.user.id]
  );
  sendJson(res, 200, { cotisations: result.rows });
}

async function createSignalement(req, res, transactionId) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'verificateur', 'vérificateur');

  const { message } = await readBody(req);
  const cleanMessage = cleanString(message) || `Signalement transaction ${transactionId}`;

  const transaction = await pool.query('SELECT id FROM transactions WHERE id = $1', [transactionId]);
  if (transaction.rowCount === 0) {
    throw new HttpError(404, 'Transaction introuvable.');
  }

  await createNotification(cleanMessage, 'signalement', 'verificateur,tresorier');
  sendJson(res, 201, { success: true });
}

async function notificationStream(req, res) {
  await requireAuth(req, res);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.write(': connected\n\n');
  sseClients.set(res, { role: req.user?.role || 'membre' });

  req.on('close', () => {
    sseClients.delete(res);
  });
}

async function listNotifications(req, res) {
  await requireAuth(req, res);
  const result = await pool.query('SELECT * FROM notifications ORDER BY created_at DESC');
  const role = req.user?.role;
  const filtered = result.rows.filter((row) =>
    notificationMatchesDestinataires(role, row.destinataires),
  );
  sendJson(res, 200, { notifications: filtered });
}

async function listActionsVotees(req, res) {
  await requireAuth(req, res);

  const result = await pool.query(
    `SELECT av.id,
            av.vote_id,
            av.titre,
            av.budget,
            av.statut,
            av.confirme_par,
            av.confirme_at,
            av.created_at,
            t.hash AS transaction_hash,
            t.explorer AS transaction_explorer
     FROM actions_votees av
     LEFT JOIN LATERAL (
       SELECT hash, explorer
       FROM transactions
       WHERE transactions.vote_id = av.vote_id
       ORDER BY transactions.date DESC
       LIMIT 1
     ) t ON true
     ORDER BY av.created_at DESC`,
  );
  sendJson(res, 200, { actions_votees: result.rows });
}

async function rappelerActionsVoteesEnAttente() {
  const res = await pool.query(
    `SELECT id, titre, created_at
     FROM actions_votees
     WHERE statut = 'en_attente'
       AND created_at <= NOW() - INTERVAL '48 hours'
       AND (
         dernier_rappel_at IS NULL
         OR dernier_rappel_at <= NOW() - INTERVAL '24 hours'
       )`,
  );

  for (const row of res.rows) {
    const hours = Math.floor((Date.now() - new Date(row.created_at).getTime()) / (3600 * 1000));
    await createNotification(
      `Rappel : ${row.titre} approuvé depuis ${hours}h, transaction non encore créée.`,
      'vote',
      'tresorier',
    );
    await pool.query('UPDATE actions_votees SET dernier_rappel_at = NOW() WHERE id = $1', [row.id]);
  }
}

async function getFedapayPublicKey(req, res) {
  await requireAuth(req, res);
  const key = cleanString(process.env.FEDAPAY_PUBLIC_KEY);
  if (!key) {
    throw new HttpError(500, 'FEDAPAY_PUBLIC_KEY manquant.');
  }
  sendJson(res, 200, { public_key: key });
}

async function computeMonthlyReport() {
  const result = await pool.query(`
    SELECT
      COALESCE(SUM(CASE WHEN montant > 0 THEN montant ELSE 0 END), 0)::int AS total_entrees,
      COALESCE(SUM(CASE WHEN montant < 0 THEN montant ELSE 0 END), 0)::int AS total_sorties,
      COUNT(*)::int AS nombre_transactions
    FROM transactions
    WHERE date >= date_trunc('month', NOW())
  `);
  const cotisations = await pool.query(`
    SELECT COALESCE(SUM(montant), 0)::int AS total_cotisations, COUNT(*)::int AS nombre_cotisations
    FROM cotisations
    WHERE date >= date_trunc('month', NOW())
  `);

  return {
    ...result.rows[0],
    ...cotisations.rows[0],
  };
}

async function saveReport(data, generePar) {
  const mois = new Date().toISOString().slice(0, 7);
  const raw = generePar != null ? cleanString(String(generePar)) : '';
  const label = raw || 'auto';
  const result = await pool.query(
    `INSERT INTO rapports (mois, data, genere_par)
     VALUES ($1, $2::jsonb, $3)
     RETURNING id, mois, data, genere_par, created_at`,
    [mois, JSON.stringify(data), label],
  );
  return result.rows[0];
}

async function monthlyReport(req, res) {
  await requireAuth(req, res);

  const result = await pool.query(
    `SELECT data, mois, genere_par, created_at FROM rapports ORDER BY created_at DESC LIMIT 1`,
  );

  if (result.rowCount === 0) {
    sendJson(res, 200, { rapport: null });
    return;
  }

  const row = result.rows[0];
  sendJson(res, 200, {
    rapport: row.data,
    mois: row.mois,
    genere_par: row.genere_par,
    created_at: row.created_at,
  });
}

async function genererRapport(req, res) {
  await requireAuth(req, res);
  await requireRoles(
    req,
    res,
    'admin',
    'president',
    'président',
    'tresorier',
    'trésorier',
    'verificateur',
    'vérificateur',
  );

  const data = await computeMonthlyReport();
  const row = await saveReport(data, req.user.role);

  await createNotification('Nouveau rapport généré', 'rapport', 'tous');

  sendJson(res, 201, {
    rapport: row.data,
    mois: row.mois,
    genere_par: row.genere_par,
    created_at: row.created_at,
  });
}

function clampScore(value) {
  return Math.max(0, Math.min(25, Math.round(Number(value) || 0)));
}

async function healthScore(req, res) {
  await requireAuth(req, res);

  const financesResult = await pool.query(`
    SELECT
      COALESCE(SUM(CASE WHEN montant > 0 THEN montant ELSE 0 END), 0)::float AS recettes,
      COALESCE(SUM(CASE WHEN montant < 0 THEN ABS(montant) ELSE 0 END), 0)::float AS depenses
    FROM transactions
    WHERE date >= NOW() - INTERVAL '3 months'
  `);

  const recettes = Number(financesResult.rows[0]?.recettes || 0);
  const depenses = Number(financesResult.rows[0]?.depenses || 0);
  const ratioFinances = depenses === 0
    ? (recettes > 0 ? 25 : 0)
    : clampScore((recettes / depenses) * 25);

  const cotisationsResult = await pool.query(`
    WITH active_members AS (
      SELECT id FROM members WHERE statut = 'Actif'
    ),
    contributing_members AS (
      SELECT DISTINCT member_id
      FROM cotisations
      WHERE date >= NOW() - INTERVAL '30 days'
    )
    SELECT
      COUNT(active_members.id)::float AS total_members,
      COUNT(contributing_members.member_id)::float AS contributing_members
    FROM active_members
    LEFT JOIN contributing_members ON contributing_members.member_id = active_members.id
  `);

  const totalMembers = Number(cotisationsResult.rows[0]?.total_members || 0);
  const contributingMembers = Number(cotisationsResult.rows[0]?.contributing_members || 0);
  const regulariteCotisations = totalMembers === 0
    ? 0
    : clampScore((contributingMembers / totalMembers) * 25);

  const participationResult = await pool.query(`
    WITH closed_votes AS (
      SELECT id
      FROM votes
      WHERE statut <> 'ouvert'
      ORDER BY created_at DESC
      LIMIT 5
    ),
    active_members AS (
      SELECT COUNT(*)::float AS total_members
      FROM members
      WHERE statut = 'Actif'
    ),
    vote_participation AS (
      SELECT
        closed_votes.id,
        COUNT(vote_results.id)::float AS voters
      FROM closed_votes
      LEFT JOIN vote_results ON vote_results.vote_id = closed_votes.id
      GROUP BY closed_votes.id
    )
    SELECT
      COALESCE(AVG(
        CASE
          WHEN active_members.total_members = 0 THEN 0
          ELSE vote_participation.voters / active_members.total_members
        END
      ), 0)::float AS average_participation
    FROM vote_participation
    CROSS JOIN active_members
  `);

  const averageParticipation = Number(participationResult.rows[0]?.average_participation || 0);
  const participationVotes = clampScore(averageParticipation * 25);

  const mandatesResult = await pool.query(`
    SELECT lower(unaccented_role) AS role
    FROM (
      SELECT
        translate(lower(role), 'éèêëàâäîïôöùûüç', 'eeeeaaaiioouuuc') AS unaccented_role
      FROM members
      WHERE statut = 'Actif'
        AND role IS NOT NULL
        AND (role_expires_at IS NULL OR role_expires_at > NOW())
    ) roles
  `);

  const bureauRoles = new Set(['president', 'tresorier', 'tresoriere', 'secretaire', 'verificateur']);
  const requiredPosts = [
    ['president'],
    ['tresorier', 'tresoriere'],
    ['secretaire'],
    ['verificateur'],
  ];
  const activeRoles = new Set(
    mandatesResult.rows
      .map(row => row.role)
      .filter(role => bureauRoles.has(role))
  );
  const filledPosts = requiredPosts.filter(aliases => aliases.some(alias => activeRoles.has(alias))).length;
  const mandatsActifs = clampScore((filledPosts / requiredPosts.length) * 25);

  const details = {
    ratio_finances: ratioFinances,
    regularite_cotisations: regulariteCotisations,
    participation_votes: participationVotes,
    mandats_actifs: mandatsActifs,
  };

  sendJson(res, 200, {
    score: Object.values(details).reduce((total, value) => total + value, 0),
    details,
  });
}

async function verifierMembresInactifs() {
  const cfg = await pool.query('SELECT valeur FROM config WHERE cle = $1', ['duree_inactivite_mois']);
  const months = Math.max(1, Number(cfg.rows[0]?.valeur || 3));

  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - months);

  const res = await pool.query(
    `WITH last_activity AS (
       SELECT m.id,
         GREATEST(
           COALESCE((SELECT MAX(vr.created_at) FROM vote_results vr WHERE vr.member_id = m.id), '1970-01-01'::timestamp),
           COALESCE((SELECT MAX(c.date) FROM cotisations c WHERE c.member_id = m.id), '1970-01-01'::timestamp)
         ) AS last_seen
       FROM members m
       WHERE m.statut = 'Actif'
     )
     SELECT id FROM last_activity WHERE last_seen < $1`,
    [cutoff],
  );

  const ids = res.rows.map((row) => row.id).filter(Number.isFinite);

  if (!ids.length) {
    return;
  }

  await pool.query(`UPDATE members SET statut = 'Inactif' WHERE id = ANY($1::int[])`, [ids]);
  await createNotification(
    `${ids.length} membres mis en inactif automatiquement.`,
    'membre',
    'secretaire',
  );
}

async function verifierElectionsAutomatiques() {
  const activeMembers = await countActiveMembers();

  for (const poste of BUREAU_POSTES) {
    const holder = await pool.query(
      `SELECT id FROM members
       WHERE statut = 'Actif'
         AND translate(lower(role), 'éèêëàâäîïôöùûüç', 'eeeeaaaiioouuuc') = ANY($1)
         AND (role_expires_at IS NULL OR role_expires_at > NOW())
       LIMIT 1`,
      [poste === 'tresorier' ? ['tresorier', 'tresoriere'] : [poste]]
    );

    if (holder.rowCount === 0) {
      const vacancy = await ensureVacancyForPoste(poste);

      if (activeMembers < 4) {
        await createNotification('Minimum 4 membres actifs requis pour ouvrir une élection', 'election', 'secretaire');
        continue;
      }

      if (vacancy.statut === 'vacant') {
        await pool.query('UPDATE postes_vacants SET statut = $1, created_at = NOW() WHERE id = $2', ['candidature', vacancy.id]);
        await createNotification(`Periode de candidature ouverte 72h pour ${poste}.`, 'candidature', 'tous');
      }
    }
  }

  const expiredVacancies = await pool.query(
    `SELECT id FROM postes_vacants
     WHERE statut = 'candidature'
       AND created_at <= NOW() - INTERVAL '72 hours'`
  );

  for (const vacancy of expiredVacancies.rows) {
    await closeCandidaturePeriodByVacancy(vacancy.id);
  }

  const expiredElectionVotes = await pool.query(
    `SELECT id FROM votes
     WHERE type = 'election'
       AND statut = 'ouvert'
       AND expires_at <= NOW()`
  );

  const silentCloseRes = {
    writableEnded: false,
    writeHead() {},
    end() {
      silentCloseRes.writableEnded = true;
    },
  };

  for (const vote of expiredElectionVotes.rows) {
    silentCloseRes.writableEnded = false;
    const autoReq = { headers: {}, user: { id: 0, role: 'admin' } };
    await closeVote(autoReq, silentCloseRes, vote.id, true);
  }

  const expiredDecisionVotes = await pool.query(
    `SELECT id FROM votes
     WHERE statut = 'ouvert'
       AND type IN ('decision', 'config')
       AND expires_at IS NOT NULL
       AND expires_at <= NOW()`
  );

  for (const vote of expiredDecisionVotes.rows) {
    silentCloseRes.writableEnded = false;
    const autoReq = { headers: {}, user: { id: 0, role: 'admin' } };
    await closeVote(autoReq, silentCloseRes, vote.id, true);
  }
}

async function maybeAutoGenerateMonthlyReport() {
  const now = new Date();
  if (now.getDate() !== 1) {
    return;
  }

  const mois = now.toISOString().slice(0, 7);
  const exists = await pool.query(
    `SELECT 1 FROM rapports WHERE mois = $1 AND genere_par = $2 LIMIT 1`,
    [mois, 'auto'],
  );

  if (exists.rowCount > 0) {
    return;
  }

  const data = await computeMonthlyReport();
  await saveReport(data, 'auto');
}

function planifierElectionsAutomatiques() {
  verifierElectionsAutomatiques().catch(err => console.error('Erreur verification elections:', err));
  verifierMembresInactifs().catch(err => console.error('Erreur verification inactivite:', err));
  rappelerActionsVoteesEnAttente().catch(err => console.error('Erreur rappels actions votees:', err));
  maybeAutoGenerateMonthlyReport().catch(err => console.error('Erreur rapport mensuel automatique:', err));

  return setInterval(() => {
    verifierElectionsAutomatiques().catch(err => console.error('Erreur verification elections:', err));
    verifierMembresInactifs().catch(err => console.error('Erreur verification inactivite:', err));
    rappelerActionsVoteesEnAttente().catch(err => console.error('Erreur rappels actions votees:', err));
    maybeAutoGenerateMonthlyReport().catch(err => console.error('Erreur rapport mensuel automatique:', err));
  }, 60 * 60 * 1000);
}

function buildDemoDataset() {
  const now = Date.now();
  const iso = (t) => new Date(t).toISOString();

  const members = [
    { id: 1, nom: 'Aminata Diallo', username: 'aminata_d', email: 'a@demo.coop', role: 'president', role_expires_at: null, statut: 'Actif', created_at: iso(now), cotisations_count: 0 },
    { id: 2, nom: 'Jean Kouassi', username: 'jean_k', email: 'j@demo.coop', role: 'tresorier', role_expires_at: null, statut: 'Actif', created_at: iso(now), cotisations_count: 0 },
    { id: 3, nom: 'Fatou NGuessan', username: 'fatou_n', email: 'f@demo.coop', role: 'secretaire', role_expires_at: null, statut: 'Actif', created_at: iso(now), cotisations_count: 0 },
    { id: 4, nom: 'Koffi Mensah', username: 'koffi_m', email: 'k@demo.coop', role: 'verificateur', role_expires_at: null, statut: 'Actif', created_at: iso(now), cotisations_count: 0 },
    { id: 5, nom: 'Awa Bamba', username: 'awa_b', email: 'aw@demo.coop', role: 'membre', role_expires_at: null, statut: 'Actif', created_at: iso(now), cotisations_count: 1 },
  ];

  const transactions = [
    { id: 'tx_demo_1', date: iso(now - 86400000), libelle: 'Vente recolte', montant: 450000, type: 'recette', hash: 'demo_hash_aaaa', explorer: 'https://stellar.expert/explorer/testnet/tx/demo_hash_aaaa', statut: 'scellé', member_id: 1, vote_id: null, source: 'transaction' },
    { id: 'tx_demo_2', date: iso(now - 172800000), libelle: 'Achat engrais', montant: -120000, type: 'depense', hash: 'demo_hash_bbbb', explorer: 'https://stellar.expert/explorer/testnet/tx/demo_hash_bbbb', statut: 'scellé', member_id: 2, vote_id: null, source: 'transaction' },
    { id: 'tx_demo_3', date: iso(now - 3600000), libelle: 'Apport coopératif démo', montant: 80000, type: 'recette', hash: 'demo_hash_cccc', explorer: 'https://stellar.expert/explorer/testnet/tx/demo_hash_cccc', statut: 'scellé', member_id: 3, vote_id: null, source: 'transaction' },
  ];

  const expires = new Date(now + 72 * 3600000);
  const electionDecompte = [
    { candidature_id: '501', nom_complet: 'Jean Kouassi', voix: 3 },
    { candidature_id: '502', nom_complet: 'Koffi Mensah', voix: 2 },
  ];

  const votes = [
    {
      id: 7001,
      titre: 'Reparation toiture hangar',
      budget: 200000,
      pour: 4,
      contre: 1,
      statut: 'ouvert',
      propose_par: 1,
      duree_heures: 72,
      expires_at: expires.toISOString(),
      type: 'decision',
      poste: null,
      poste_vacant_id: null,
      round: 1,
      created_at: iso(now - 3600000),
    },
    {
      id: 7002,
      titre: 'Election tresorier',
      budget: 0,
      pour: 0,
      contre: 0,
      statut: 'validé',
      propose_par: null,
      duree_heures: 72,
      expires_at: iso(now - 86400000),
      type: 'election',
      poste: 'tresorier',
      poste_vacant_id: 9001,
      round: 1,
      created_at: iso(now - 86400000 * 2),
      a_vote: false,
      decompte_voix: electionDecompte,
    },
  ];

  const electionVote = { ...votes[1] };
  const candidatureDeadline = new Date(now - 24 * 3600000);

  const posteVacant = {
    id: 9001,
    poste: 'tresorier',
    statut: 'pourvu',
    created_at: iso(now - 96 * 3600000),
    date_limite_candidature: candidatureDeadline.toISOString(),
    nombre_candidatures: 2,
    candidats: [
      { id: 501, member_id: 2, nom_complet: 'Jean Kouassi', nom: 'Jean Kouassi', statut: 'fermé' },
      { id: 502, member_id: 4, nom_complet: 'Koffi Mensah', nom: 'Koffi Mensah', statut: 'fermé' },
    ],
    est_candidat: false,
    election_vote: electionVote,
    decompte_voix: electionDecompte,
    a_vote: false,
  };

  const notifications = [
    {
      id: 'd1',
      message: 'Démonstration : bienvenue dans CoopLedger.',
      type: 'config',
      destinataires: 'tous',
      created_at: iso(now),
    },
  ];

  return {
    members,
    transactions,
    votes,
    candidatures: [posteVacant],
    notifications,
    lastGeneratedReport: null,
    cotisations: [
      {
        id: 1,
        member_id: 5,
        montant: 5000,
        mode: 'Cash',
        statut: 'confirmé',
        date: iso(now - 86400000),
        hash: 'demo_hash_cot1',
        explorer: 'https://stellar.expert/explorer/testnet/tx/demo_hash_cot1',
      },
    ],
  };
}

async function startDemoSession(req, res) {
  DEMO_SESSION.data = buildDemoDataset();
  const token = generateDemoToken();
  sendJson(res, 200, { token });
}

async function demoNotificationStream(req, res) {
  await requireAuth(req, res);
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.write(': demo\n\n');
  const ping = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (err) {
      clearInterval(ping);
    }
  }, 25000);
  req.on('close', () => clearInterval(ping));
}

async function demoHealthScore(req, res) {
  await requireAuth(req, res);
  sendJson(res, 200, {
    score: 68,
    details: {
      ratio_finances: 17,
      regularite_cotisations: 18,
      participation_votes: 16,
      mandats_actifs: 17,
    },
  });
}

async function demoMonthlyReport(req, res) {
  await requireAuth(req, res);
  const store = DEMO_SESSION.data;
  if (!store) {
    throw new HttpError(400, 'Session demo non initialisee. Appelez POST /api/demo/start.');
  }
  if (!store.lastGeneratedReport) {
    sendJson(res, 200, { rapport: null });
    return;
  }
  sendJson(res, 200, store.lastGeneratedReport);
}

async function routeDemoApi(req, res, pathname) {
  await requireAuth(req, res);
  if (res.writableEnded) {
    return;
  }

  const store = DEMO_SESSION.data;
  if (!store) {
    throw new HttpError(400, 'Session demo non initialisee. Appelez POST /api/demo/start.');
  }

  if (req.method === 'GET' && pathname === '/api/config') {
    return sendJson(res, 200, { nom_coop: 'Coopérative de démonstration' });
  }
  if (req.method === 'GET' && pathname === '/api/members') {
    return sendJson(res, 200, { members: store.members });
  }
  if (req.method === 'GET' && pathname.startsWith('/api/transactions')) {
    const cotLedger = (store.cotisations || []).filter((row) => cleanString(row.hash)).map((row) => ({
      id: `cot_${row.id}`,
      date: row.date,
      libelle: `Cotisation (${row.mode})`,
      montant: row.montant,
      type: 'cotisation',
      hash: row.hash,
      explorer: row.explorer || '',
      statut: row.statut,
      member_id: row.member_id,
      vote_id: null,
      source: 'cotisation',
    }));
    const merged = [...store.transactions.map((tx) => ({ ...tx, source: tx.source || 'transaction' })), ...cotLedger]
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    const url = new URL(req.url || '/api/transactions', 'http://localhost');
    let rows = merged;
    const typeFilter = cleanString(url.searchParams.get('type')).toLowerCase();
    const statutFilter = cleanString(url.searchParams.get('statut')).toLowerCase();
    if (typeFilter && typeFilter !== 'tous') {
      rows = rows.filter((row) => cleanString(row.type || (Number(row.montant) < 0 ? 'depense' : 'recette')).toLowerCase() === typeFilter);
    }
    if (statutFilter) {
      rows = rows.filter((row) => cleanString(row.statut).toLowerCase() === statutFilter);
    }
    return sendJson(res, 200, { transactions: rows });
  }
  if (req.method === 'GET' && pathname === '/api/votes') {
    return sendJson(res, 200, { votes: store.votes.map(serializeVote) });
  }
  if (req.method === 'GET' && pathname === '/api/actions-votees') {
    return sendJson(res, 200, { actions_votees: [] });
  }
  if (req.method === 'GET' && pathname === '/api/config/all') {
    return sendJson(res, 200, {
      config: {
        nom_coop: 'Coopérative de démonstration',
        duree_mandat: '12',
        duree_inactivite_mois: '3',
        cle_unique_masked: 'demo…demo',
      },
    });
  }
  if (req.method === 'GET' && pathname === '/api/candidatures') {
    return sendJson(res, 200, { candidatures: store.candidatures });
  }
  if (req.method === 'GET' && pathname === '/api/notifications') {
    return sendJson(res, 200, { notifications: store.notifications });
  }
  if (req.method === 'GET' && pathname === '/api/cotisations/me') {
    return sendJson(res, 200, { cotisations: store.cotisations });
  }
  if (req.method === 'GET' && pathname === '/api/notifications/stream') {
    return demoNotificationStream(req, res);
  }
  if (req.method === 'GET' && pathname === '/api/sante') {
    return demoHealthScore(req, res);
  }
  if (req.method === 'GET' && pathname === '/api/rapport/mensuel') {
    return demoMonthlyReport(req, res);
  }
  if (req.method === 'POST' && pathname === '/api/rapport/generer') {
    await requireRoles(
      req,
      res,
      'admin',
      'president',
      'président',
      'tresorier',
      'trésorier',
      'verificateur',
      'vérificateur',
    );
    if (res.writableEnded) {
      return;
    }
    const createdAt = new Date().toISOString();
    const mois = createdAt.slice(0, 7);
    const rapport = {
      total_entrees: 530000,
      total_sorties: -120000,
      nombre_transactions: 3,
      total_cotisations: 5000,
      nombre_cotisations: 1,
    };
    const payload = {
      rapport,
      mois,
      genere_par: cleanString(req.user?.role) || 'demo',
      created_at: createdAt,
    };
    store.lastGeneratedReport = payload;
    store.notifications.unshift({
      id: `r_${Date.now()}`,
      message: 'Nouveau rapport généré',
      type: 'rapport',
      destinataires: 'tous',
      created_at: createdAt,
    });
    return sendJson(res, 201, payload);
  }
  if (req.method === 'GET' && pathname === '/api/fedapay/public-key') {
    return sendJson(res, 200, { public_key: 'demo_public_key' });
  }
  if (req.method === 'GET' && pathname === '/api/push/public-key') {
    return sendJson(res, 200, { public_key: '' });
  }
  if (req.method === 'POST' && pathname === '/api/push/unsubscribe') {
    return sendJson(res, 200, { success: true });
  }
  if (req.method === 'POST' && pathname === '/api/fedapay/initier') {
    return sendJson(res, 502, { error: 'Paiement temporairement indisponible' });
  }

  throw new HttpError(404, 'Route API introuvable (mode demo).');
}

async function routeApi(req, res, pathname) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const bearer = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length)
    : null;
  if (bearer) {
    const decoded = verifyTokenUnsafe(bearer);
    if (decoded) {
      req.user = decoded;
    }
  }

  if (req.method === 'POST' && pathname === '/api/demo/start') {
    return startDemoSession(req, res);
  }

  if (req.user && normalizeRole(req.user.role) === 'demo') {
    return routeDemoApi(req, res, pathname);
  }

  if (req.method === 'POST' && pathname === '/api/auth/register') return register(req, res);
  if (req.method === 'POST' && pathname === '/api/auth/login') return login(req, res);

  if (req.method === 'POST' && pathname === '/api/config/init') return initConfig(req, res);
  if (req.method === 'GET' && pathname === '/api/config') return getPublicConfig(req, res);
  if (req.method === 'GET' && pathname === '/api/config/all') return listAllConfigAdmin(req, res);

  const configKeyPutMatch = req.method === 'PUT' && pathname.match(/^\/api\/config\/([^/]+)$/);
  if (configKeyPutMatch && configKeyPutMatch[1] !== 'init') {
    return putConfigKey(req, res, configKeyPutMatch[1]);
  }

  if (req.method === 'GET' && pathname === '/api/members') return listMembers(req, res);
  if (req.method === 'POST' && pathname === '/api/members/create') return createMemberByAdmin(req, res);

  const memberRoleMatch = pathname.match(/^\/api\/members\/(\d+)\/role$/);
  if (req.method === 'PUT' && memberRoleMatch) return updateMemberRole(req, res, Number(memberRoleMatch[1]));

  const resetPasswordMatch = pathname.match(/^\/api\/members\/(\d+)\/reset-password$/);
  if (req.method === 'POST' && resetPasswordMatch) {
    return resetMemberPassword(req, res, Number(resetPasswordMatch[1]));
  }

  if (req.method === 'GET' && pathname === '/api/transactions') return listTransactions(req, res);
  if (req.method === 'POST' && pathname === '/api/transactions') return createTransaction(req, res);

  const signalementMatch = pathname.match(/^\/api\/transactions\/([^/]+)\/signalement$/);
  if (req.method === 'POST' && signalementMatch) {
    return createSignalement(req, res, decodeURIComponent(signalementMatch[1]));
  }

  if (req.method === 'GET' && pathname === '/api/votes') return listVotes(req, res);
  if (req.method === 'POST' && pathname === '/api/votes') return createVote(req, res);

  if (req.method === 'GET' && pathname === '/api/candidatures') return listCandidatures(req, res);
  if (req.method === 'POST' && pathname === '/api/candidatures') return createCandidature(req, res);

  const candidatureCloseMatch = pathname.match(/^\/api\/candidatures\/(\d+)\/close$/);
  if (req.method === 'POST' && candidatureCloseMatch) {
    return closeCandidaturePeriod(req, res, Number(candidatureCloseMatch[1]));
  }

  const candidatureAnnulerMatch = pathname.match(/^\/api\/candidatures\/(\d+)\/annuler$/);
  if (req.method === 'POST' && candidatureAnnulerMatch) {
    return annulerCandidatureElection(req, res, Number(candidatureAnnulerMatch[1]));
  }

  const candidatureProlongMatch = pathname.match(/^\/api\/candidatures\/(\d+)\/prolong$/);
  if (req.method === 'POST' && candidatureProlongMatch) {
    return prolongCandidatureElection(req, res, Number(candidatureProlongMatch[1]));
  }

  const voteProlongMatch = pathname.match(/^\/api\/votes\/(\d+)\/prolong$/);
  if (req.method === 'POST' && voteProlongMatch) {
    return prolongVote(req, res, Number(voteProlongMatch[1]));
  }

  const voteActionMatch = pathname.match(/^\/api\/votes\/(\d+)\/(vote|close|annuler)$/);
  if (voteActionMatch && req.method === 'POST') {
    if (voteActionMatch[2] === 'vote') return castVote(req, res, Number(voteActionMatch[1]));
    if (voteActionMatch[2] === 'close') return closeVote(req, res, Number(voteActionMatch[1]));
    return cancelVote(req, res, Number(voteActionMatch[1]));
  }

  const memberStatMatch = pathname.match(/^\/api\/members\/(\d+)\/statut$/);
  if (req.method === 'POST' && memberStatMatch) {
    return updateMemberStatut(req, res, Number(memberStatMatch[1]));
  }

  if (req.method === 'GET' && pathname === '/api/push/public-key') return getPushPublicKey(req, res);
  if (req.method === 'POST' && pathname === '/api/push/subscribe') return pushSubscribe(req, res);
  if (req.method === 'POST' && pathname === '/api/push/unsubscribe') return pushUnsubscribe(req, res);

  if (req.method === 'POST' && pathname === '/api/cotisations') return createCotisation(req, res);
  if (req.method === 'POST' && pathname === '/api/fedapay/initier') return initierFedapay(req, res);
  if (req.method === 'GET' && pathname === '/api/fedapay/public-key') return getFedapayPublicKey(req, res);
  if (req.method === 'POST' && pathname === '/api/cotisations/webhook') return fedapayWebhook(req, res);
  if (req.method === 'GET' && pathname === '/api/cotisations/me') return myCotisations(req, res);

  if (req.method === 'GET' && pathname === '/api/notifications/stream') return notificationStream(req, res);
  if (req.method === 'GET' && pathname === '/api/notifications') return listNotifications(req, res);
  if (req.method === 'GET' && pathname === '/api/actions-votees') return listActionsVotees(req, res);
  if (req.method === 'GET' && pathname === '/api/rapport/mensuel') return monthlyReport(req, res);
  if (req.method === 'POST' && pathname === '/api/rapport/generer') return genererRapport(req, res);
  if (req.method === 'GET' && pathname === '/api/sante') return healthScore(req, res);

  throw new HttpError(404, 'Route API introuvable.');
}

const httpServer = http.createServer(async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname.startsWith('/api/')) {
      await routeApi(req, res, url.pathname);
      return;
    }

    serveStatic(req, res, url.pathname);
  } catch (err) {
    if (!res.writableEnded) {
      sendError(res, err);
    }
  }
});

configureWebPushVapid();

httpServer.listen(PORT, () => {
  console.log(`CoopLedger en ligne sur le port ${PORT}`);
  console.log(`Dashboard : http://localhost:${PORT}`);
});

planifierElectionsAutomatiques();
