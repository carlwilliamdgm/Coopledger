const { Pool } = require('pg');
require('dotenv').config();

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL doit etre definie pour se connecter a PostgreSQL.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      nom VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) DEFAULT 'membre',
      role_expires_at TIMESTAMP,
      statut VARCHAR(20) DEFAULT 'Actif',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS votes (
      id SERIAL PRIMARY KEY,
      titre VARCHAR(200) NOT NULL,
      budget INTEGER NOT NULL,
      pour INTEGER DEFAULT 0,
      contre INTEGER DEFAULT 0,
      statut VARCHAR(20) DEFAULT 'ouvert',
      propose_par INTEGER REFERENCES members(id),
      duree_heures INTEGER DEFAULT 72,
      expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id VARCHAR(50) PRIMARY KEY,
      date TIMESTAMP DEFAULT NOW(),
      libelle VARCHAR(200) NOT NULL,
      montant INTEGER NOT NULL,
      hash TEXT NOT NULL,
      explorer TEXT,
      statut VARCHAR(20) DEFAULT 'scellé',
      member_id INTEGER REFERENCES members(id),
      vote_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS vote_results (
      id SERIAL PRIMARY KEY,
      vote_id INTEGER REFERENCES votes(id),
      member_id INTEGER REFERENCES members(id),
      choix VARCHAR(10) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(vote_id, member_id)
    );

    CREATE TABLE IF NOT EXISTS cotisations (
      id SERIAL PRIMARY KEY,
      member_id INTEGER REFERENCES members(id),
      montant INTEGER NOT NULL,
      mode VARCHAR(20) NOT NULL,
      statut VARCHAR(20) DEFAULT 'confirmé',
      date TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      message TEXT NOT NULL,
      type VARCHAR(50),
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS config (
      id SERIAL PRIMARY KEY,
      cle VARCHAR(100) UNIQUE NOT NULL,
      valeur TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT NOW(),
      ip VARCHAR(50)
    );
  `);
}

const ready = initDatabase().catch((err) => {
  console.error('Erreur lors de l initialisation PostgreSQL:', err);
  process.exitCode = 1;
  throw err;
});

module.exports = pool;
module.exports.initDatabase = initDatabase;
module.exports.ready = ready;
