const http = require('http');
const fs = require('fs');
const path = require('path');
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

    req.on('error', reject);
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
  return cleanString(role).toLowerCase();
}

function isAdminRole(role) {
  return normalizeRole(role) === 'admin';
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
  const { nom, email, password } = await readBody(req);
  const cleanNom = cleanString(nom);
  const cleanEmail = cleanString(email).toLowerCase();
  const cleanPassword = cleanString(password);

  if (!cleanNom || !cleanEmail || !cleanPassword) {
    throw new HttpError(400, 'nom, email et password sont obligatoires.');
  }

  const passwordHash = await bcrypt.hash(cleanPassword, 12);
  const result = await pool.query(
    `INSERT INTO members (nom, email, password_hash)
     VALUES ($1, $2, $3)
     RETURNING id, nom, email, role, role_expires_at, statut, created_at`,
    [cleanNom, cleanEmail, passwordHash]
  );
  const member = result.rows[0];
  const token = generateToken(member);

  await createNotification(`Nouveau membre inscrit: ${member.nom}`, 'membre');
  sendJson(res, 201, { token, member });
}

async function login(req, res) {
  const { email, password } = await readBody(req);
  const cleanEmail = cleanString(email).toLowerCase();
  const cleanPassword = cleanString(password);

  if (!cleanEmail || !cleanPassword) {
    throw new HttpError(400, 'email et password sont obligatoires.');
  }

  const result = await pool.query('SELECT * FROM members WHERE email = $1', [cleanEmail]);
  const member = result.rows[0];
  const isAdmin = member && isAdminRole(member.role);

  if (isAdmin && isAdminBlocked(cleanEmail)) {
    throw new HttpError(403, 'Compte admin bloque apres 3 tentatives echouees.');
  }

  const passwordOk = member
    ? await bcrypt.compare(cleanPassword, member.password_hash)
    : false;

  if (!member || !passwordOk) {
    if (isAdmin) {
      recordFailedAdminLogin(cleanEmail);
    }

    throw new HttpError(401, 'Identifiants invalides.');
  }

  if (isAdmin) {
    resetAdminFailedAttempts(cleanEmail);
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
    `SELECT id, nom, email, role, role_expires_at, statut, created_at
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
     RETURNING id, nom, email, role, role_expires_at, statut, created_at`,
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
  await requireRoles(req, res, 'president', 'président');

  const { titre, budget, duree_heures } = await readBody(req);
  const cleanTitle = cleanString(titre);
  const amount = parsePositiveInteger(budget, 'budget');
  const durationHours = Math.max(Number(duree_heures || 72), 72);

  if (!cleanTitle || !Number.isInteger(durationHours)) {
    throw new HttpError(400, 'titre et duree_heures valide sont obligatoires.');
  }

  const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
  const result = await pool.query(
    `INSERT INTO votes (titre, budget, propose_par, duree_heures, expires_at)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [cleanTitle, amount, req.user.id, durationHours, expiresAt]
  );

  await createNotification(`Nouvelle proposition: ${cleanTitle}`, 'vote');
  sendJson(res, 201, { vote: serializeVote(result.rows[0]) });
}

async function castVote(req, res, id) {
  await requireAuth(req, res);
  await requireRoles(req, res, 'membre');

  const { choix } = await readBody(req);
  const cleanChoice = cleanString(choix).toLowerCase();

  if (!['pour', 'contre'].includes(cleanChoice)) {
    throw new HttpError(400, 'choix doit etre pour ou contre.');
  }

  const vote = await pool.query('SELECT * FROM votes WHERE id = $1', [id]);
  if (!vote.rows[0] || vote.rows[0].statut !== 'ouvert') {
    throw new HttpError(400, 'Vote introuvable ou ferme.');
  }

  if (vote.rows[0].expires_at && new Date(vote.rows[0].expires_at).getTime() <= Date.now()) {
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
      [cleanChoice === 'pour' ? 1 : 0, cleanChoice === 'contre' ? 1 : 0, id]
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
  await requireAuth(req, res);

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

async function fedapayWebhook(req, res) {
  const payload = await readBody(req);
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

async function routeApi(req, res, pathname) {
  if (req.method === 'POST' && pathname === '/api/auth/register') return register(req, res);
  if (req.method === 'POST' && pathname === '/api/auth/login') return login(req, res);

  if (req.method === 'POST' && pathname === '/api/config/init') return initConfig(req, res);
  if (req.method === 'GET' && pathname === '/api/config') return getPublicConfig(req, res);

  if (req.method === 'GET' && pathname === '/api/members') return listMembers(req, res);

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

  const voteActionMatch = pathname.match(/^\/api\/votes\/(\d+)\/(vote|close)$/);
  if (voteActionMatch && req.method === 'POST') {
    return voteActionMatch[2] === 'vote'
      ? castVote(req, res, Number(voteActionMatch[1]))
      : closeVote(req, res, Number(voteActionMatch[1]));
  }

  if (req.method === 'POST' && pathname === '/api/cotisations') return createCotisation(req, res);
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
