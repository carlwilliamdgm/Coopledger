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
  isAdminBlocked,
  recordFailedAdminLogin,
  resetAdminFailedAttempts,
  logAdminAction,
} = require('./auth');
const transactionService = require('./transaction');

const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = process.env.PORT || 3000;
const sseClients = new Set();
const BUREAU_POSTES = ['president', 'tresorier', 'secretaire', 'verificateur'];
const FEDAPAY_TRANSACTION_ENDPOINT = 'https://sandbox-api.fedapay.com/v1/transactions';

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
    await createNotification(`Aucune candidature pour ${vacancy.poste}. Periode relancee 72h.`, 'candidature');
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

  await createNotification(`Vote d election ouvert pour ${vacancy.poste}.`, 'vote');
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

async function createNotification(message, type) {
  const result = await pool.query(
    'INSERT INTO notifications (message, type) VALUES ($1, $2) RETURNING *',
    [message, type]
  );
  const notification = result.rows[0];
  pushNotification(notification);
  return notification;
}

function pushNotification(notification) {
  const payload = `data: ${JSON.stringify(notification)}\n\n`;

  for (const client of sseClients) {
    client.write(payload);
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

  await createNotification(`Nouveau membre inscrit: ${member.nom}`, 'membre');
  sendJson(res, 201, { token, member });
}

async function createMemberByAdmin(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin');

  const body = await readBody(req);
  const member = await createMemberRecord(body);

  await createNotification(`Membre cree par l admin: ${member.nom}`, 'membre');
  sendJson(res, 201, { member });
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

  await createNotification('Configuration initiale terminee.', 'config');
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

async function listMembers(req, res) {
  await requireAuth(req, res);
  const result = await pool.query(
    `SELECT id, nom, username, email, role, role_expires_at, statut, created_at
     FROM members
     ORDER BY created_at DESC`
  );
  sendJson(res, 200, { members: result.rows });
}

async function updateMemberRole(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'admin', 'secretaire', 'secrétaire');

  const { role, vote_id, role_expires_at } = await readBody(req);
  const cleanRole = cleanString(role);
  const voteId = parsePositiveInteger(vote_id, 'vote_id');

  if (!cleanRole) {
    throw new HttpError(400, 'role est obligatoire.');
  }

  const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [voteId]);
  if (!vote.rows[0] || vote.rows[0].statut !== 'validé') {
    throw new HttpError(400, 'Le vote associe doit etre valide.');
  }

  const result = await pool.query(
    `UPDATE members
     SET role = $1, role_expires_at = $2
     WHERE id = $3
     RETURNING id, nom, username, email, role, role_expires_at, statut, created_at`,
    [cleanRole, role_expires_at || null, id]
  );

  if (result.rowCount === 0) {
    throw new HttpError(404, 'Membre introuvable.');
  }

  await createNotification(`Role attribue a ${result.rows[0].nom}: ${cleanRole}`, 'membre');
  await logAdminAction(`Role ${cleanRole} attribue au membre ${id}`, getRequestIp(req));
  sendJson(res, 200, { member: result.rows[0] });
}

async function listTransactions(req, res) {
  await requireAuth(req, res);
  const result = await pool.query('SELECT * FROM transactions ORDER BY date DESC');
  sendJson(res, 200, { transactions: result.rows });
}

async function createTransaction(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'tresorier', 'trésorier');

  const { libelle, montant, member_id, vote_id } = await readBody(req);
  const cleanLibelle = cleanString(libelle);
  const amount = parseNonZeroInteger(montant, 'montant');
  const voteId = parsePositiveInteger(vote_id, 'vote_id');

  if (!cleanLibelle) {
    throw new HttpError(400, 'libelle est obligatoire.');
  }

  const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [voteId]);
  if (!vote.rows[0] || vote.rows[0].statut !== 'validé') {
    throw new HttpError(400, 'Le vote associe doit etre valide.');
  }

  const hash = await transactionService.enregistrerTransaction(cleanLibelle, amount);
  const id = `tx_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const explorer = `https://stellar.expert/explorer/testnet/tx/${hash}`;
  const result = await pool.query(
    `INSERT INTO transactions (id, libelle, montant, hash, explorer, member_id, vote_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [id, cleanLibelle, amount, hash, explorer, member_id || null, voteId]
  );

  await createNotification(`Transaction scellee: ${cleanLibelle}`, 'transaction');
  sendJson(res, 201, { transaction: result.rows[0] });
}

async function listVotes(req, res) {
  await requireAuth(req, res);
  const result = await pool.query('SELECT * FROM votes ORDER BY created_at DESC');
  sendJson(res, 200, { votes: result.rows.map(serializeVote) });
}

async function createVote(req, res) {
  await requireAuth(req, res);

  const { titre, budget, duree_heures, type = 'decision' } = await readBody(req);
  const voteType = cleanString(type).toLowerCase() || 'decision';

  if (voteType === 'election') {
    const activeMembers = await countActiveMembers();
    if (activeMembers < 4) {
      throw new HttpError(403, 'Minimum 4 membres actifs requis pour ouvrir une election.');
    }
  } else {
    await requireRoles(req, res, 'president', 'président');
  }

  const cleanTitle = cleanString(titre);
  const amount = voteType === 'election' ? Number(budget || 0) : parsePositiveInteger(budget, 'budget');
  const durationHours = Math.max(Number(duree_heures || 72), 72);

  if (!cleanTitle || !Number.isInteger(durationHours)) {
    throw new HttpError(400, 'titre et duree_heures valide sont obligatoires.');
  }

  const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
  const result = await pool.query(
    `INSERT INTO votes (titre, budget, propose_par, duree_heures, expires_at, type)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [cleanTitle, amount, req.user.id, durationHours, expiresAt, voteType]
  );

  await createNotification(`Nouvelle proposition: ${cleanTitle}`, 'vote');
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

  await createNotification('Un vote a ete enregistre.', 'vote');
  sendJson(res, 201, { success: true });
}

async function closeVote(req, res, id) {
  if (!req.user) {
    await requireAuth(req, res);
  }

  const result = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  const vote = result.rows[0];

  if (!vote) {
    throw new HttpError(404, 'Vote introuvable.');
  }

  if (vote.statut !== 'ouvert') {
    throw new HttpError(400, 'Ce vote est deja ferme.');
  }

  if (vote.expires_at && new Date(vote.expires_at).getTime() > Date.now()) {
    throw new HttpError(400, 'Ce vote n est pas encore expire.');
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
        await createNotification(`Egalite sur l election ${vote.poste}. Vote reconduit 48h.`, 'vote');
        sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
        return;
      }

      const rejected = await pool.query(
        `UPDATE votes SET statut = 'rejeté' WHERE id = $1 RETURNING *`,
        [id]
      );
      await createNotification(`Election ${vote.poste} rejetee apres deux egalites.`, 'vote');
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

    await createNotification(`${candidature.nom} obtient le poste ${vote.poste}.`, 'membre');
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

  await createNotification(`Vote "${vote.titre}" ${status}.`, 'vote');
  sendJson(res, 200, { vote: serializeVote(updated.rows[0]) });
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

  const result = await pool.query(
    `INSERT INTO cotisations (member_id, montant, mode)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [memberId, amount, cleanMode]
  );

  await createNotification('Cotisation enregistree.', 'cotisation');
  sendJson(res, 201, { cotisation: result.rows[0] });
}

async function initierFedapay(req, res) {
  await requireAuth(req, res);

  const { montant } = await readBody(req);
  const amount = parsePositiveInteger(montant, 'montant');
  const apiKey = process.env.FEDAPAY_SERVER_KEY || 'sk_sandbox_YQWarfYpVd68IEEZ0MHICcn3';

  const response = await postJson(FEDAPAY_TRANSACTION_ENDPOINT, {
    description: 'Cotisation CoopLedger',
    amount,
    currency: { iso: 'XOF' },
    callback_url: 'https://coopledger-demo.up.railway.app/api/cotisations/webhook',
    metadata: { member_id: req.user.id },
  }, {
    Authorization: `Bearer ${apiKey}`,
  });

  const data = response.data;
  if (!response.ok) {
    throw new HttpError(response.status, data.error || 'Erreur lors de la creation de la transaction FedaPay.');
  }

  const token = data.token || data.transaction?.token;
  const url = data.url || data.payment_url || data.redirect_url || data.transaction?.payment_url;

  if (!token || !url) {
    throw new HttpError(502, 'Reponse incomplette de FedaPay.');
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

  const vacancies = await pool.query(`
    SELECT postes_vacants.*,
      COALESCE(json_agg(
        json_build_object('id', candidatures.id, 'member_id', candidatures.member_id, 'nom', members.nom, 'username', members.username)
      ) FILTER (WHERE candidatures.id IS NOT NULL), '[]') AS candidats
    FROM postes_vacants
    LEFT JOIN candidatures ON candidatures.poste = postes_vacants.poste
      AND candidatures.statut IN ('ouvert', 'fermé', 'ferme')
    LEFT JOIN members ON members.id = candidatures.member_id
    WHERE postes_vacants.statut IN ('vacant', 'candidature', 'vote')
    GROUP BY postes_vacants.id
    ORDER BY postes_vacants.created_at DESC
  `);

  sendJson(res, 200, { candidatures: vacancies.rows });
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

  await createNotification(`Nouvelle candidature pour le poste ${cleanPoste}.`, 'candidature');
  sendJson(res, 201, { candidature: result.rows[0] });
}

async function closeCandidaturePeriod(req, res, id) {
  await requireAuth(req, res);
  await closeCandidaturePeriodByVacancy(Number(id), false);
  sendJson(res, 200, { success: true });
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
  const result = await pool.query(
    `INSERT INTO cotisations (member_id, montant, mode, statut)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [memberId, amount, 'FedaPay', 'confirmé']
  );

  await createNotification('Cotisation FedaPay confirmee.', 'cotisation');
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

  await createNotification(cleanMessage, 'signalement');
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
  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
}

async function monthlyReport(req, res) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'president', 'président', 'tresorier', 'trésorier', 'verificateur', 'vérificateur');

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

  sendJson(res, 200, {
    mois: new Date().toISOString().slice(0, 7),
    ...result.rows[0],
    ...cotisations.rows[0],
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
        await createNotification('Minimum 4 membres actifs requis pour ouvrir une élection', 'election');
        continue;
      }

      if (vacancy.statut === 'vacant') {
        await pool.query('UPDATE postes_vacants SET statut = $1, created_at = NOW() WHERE id = $2', ['candidature', vacancy.id]);
        await createNotification(`Periode de candidature ouverte 72h pour ${poste}.`, 'candidature');
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

  for (const vote of expiredElectionVotes.rows) {
    const fakeReq = { headers: {}, user: { id: 0, role: 'admin' } };
    const fakeRes = { writableEnded: false };
    fakeRes.writeHead = () => {};
    fakeRes.end = () => { fakeRes.writableEnded = true; };
    await closeVote(fakeReq, fakeRes, vote.id);
  }
}

function planifierElectionsAutomatiques() {
  verifierElectionsAutomatiques().catch(err => console.error('Erreur verification elections:', err));
  return setInterval(() => {
    verifierElectionsAutomatiques().catch(err => console.error('Erreur verification elections:', err));
  }, 60 * 60 * 1000);
}

async function routeApi(req, res, pathname) {
  if (req.method === 'POST' && pathname === '/api/auth/register') return register(req, res);
  if (req.method === 'POST' && pathname === '/api/auth/login') return login(req, res);

  if (req.method === 'POST' && pathname === '/api/config/init') return initConfig(req, res);
  if (req.method === 'GET' && pathname === '/api/config') return getPublicConfig(req, res);

  if (req.method === 'GET' && pathname === '/api/members') return listMembers(req, res);
  if (req.method === 'POST' && pathname === '/api/members/create') return createMemberByAdmin(req, res);

  const memberRoleMatch = pathname.match(/^\/api\/members\/(\d+)\/role$/);
  if (req.method === 'PUT' && memberRoleMatch) return updateMemberRole(req, res, Number(memberRoleMatch[1]));

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

  const voteActionMatch = pathname.match(/^\/api\/votes\/(\d+)\/(vote|close)$/);
  if (voteActionMatch && req.method === 'POST') {
    return voteActionMatch[2] === 'vote'
      ? castVote(req, res, Number(voteActionMatch[1]))
      : closeVote(req, res, Number(voteActionMatch[1]));
  }

  if (req.method === 'POST' && pathname === '/api/cotisations') return createCotisation(req, res);
  if (req.method === 'POST' && pathname === '/api/fedapay/initier') return initierFedapay(req, res);
  if (req.method === 'POST' && pathname === '/api/cotisations/webhook') return fedapayWebhook(req, res);
  if (req.method === 'GET' && pathname === '/api/cotisations/me') return myCotisations(req, res);

  if (req.method === 'GET' && pathname === '/api/notifications/stream') return notificationStream(req, res);
  if (req.method === 'GET' && pathname === '/api/rapport/mensuel') return monthlyReport(req, res);
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

httpServer.listen(PORT, () => {
  console.log(`CoopLedger en ligne sur le port ${PORT}`);
  console.log(`Dashboard : http://localhost:${PORT}`);
});

planifierElectionsAutomatiques();
