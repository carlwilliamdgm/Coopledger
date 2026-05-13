const jwt = require('jsonwebtoken');
const pool = require('./db');

const MAX_ADMIN_FAILED_ATTEMPTS = 3;
const adminLoginAttempts = new Map();

function getJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET doit etre definie pour signer les tokens.');
  }

  return process.env.JWT_SECRET;
}

function verifyTokenUnsafe(token) {
  try {
    return jwt.verify(token, getJwtSecret());
  } catch {
    return null;
  }
}

function normalizeRole(role) {
  return String(role || 'membre')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function isRoleExpired(roleExpiresAt) {
  return roleExpiresAt && new Date(roleExpiresAt).getTime() <= Date.now();
}

function generateToken(member) {
  const payload = {
    id: member.id,
    nom: member.nom,
    email: member.email,
    role: member.role,
    role_expires_at: member.role_expires_at,
  };

  const expiresIn = normalizeRole(member.role) === 'admin' ? '1h' : '24h';
  return jwt.sign(payload, getJwtSecret(), { expiresIn });
}

function generateDemoToken() {
  const payload = {
    id: 0,
    nom: 'Démonstration',
    email: 'demo@coopledger.local',
    role: 'demo',
    role_expires_at: null,
  };
  return jwt.sign(payload, getJwtSecret(), { expiresIn: '30m' });
}

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Token absent.' });
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret());

    if (normalizeRole(decoded.role) === 'demo') {
      req.user = decoded;
      return next();
    }

    if (isRoleExpired(decoded.role_expires_at)) {
      await pool.query(
        'UPDATE members SET role = $1, role_expires_at = NULL WHERE id = $2',
        ['membre', decoded.id]
      );

      decoded.role = 'membre';
      decoded.role_expires_at = null;
    }

    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalide.' });
  }
}

function authorize(...roles) {
  const allowedRoles = roles.map(normalizeRole);

  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(normalizeRole(req.user.role))) {
      return res.status(403).json({ error: 'Acces non autorise.' });
    }

    return next();
  };
}

async function logAdminAction(action, ip) {
  await pool.query(
    'INSERT INTO admin_logs (action, ip) VALUES ($1, $2)',
    [action, ip]
  );
}

function getAdminAttemptKey(email = 'admin') {
  return String(email || 'admin').toLowerCase();
}

function isAdminBlocked(email) {
  const key = getAdminAttemptKey(email);
  return (adminLoginAttempts.get(key) || 0) >= MAX_ADMIN_FAILED_ATTEMPTS;
}

function recordFailedAdminLogin(email) {
  const key = getAdminAttemptKey(email);
  const attempts = (adminLoginAttempts.get(key) || 0) + 1;
  adminLoginAttempts.set(key, attempts);

  return {
    attempts,
    blocked: attempts >= MAX_ADMIN_FAILED_ATTEMPTS,
  };
}

function resetAdminFailedAttempts(email) {
  adminLoginAttempts.delete(getAdminAttemptKey(email));
}

module.exports = {
  generateToken,
  generateDemoToken,
  verifyTokenUnsafe,
  authenticate,
  authorize,
  logAdminAction,
  isAdminBlocked,
  recordFailedAdminLogin,
  resetAdminFailedAttempts,
};
