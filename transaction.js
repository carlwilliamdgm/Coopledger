const {
  Horizon,
  Keypair,
  TransactionBuilder,
  Networks,
  Operation,
  BASE_FEE,
} = require('@stellar/stellar-sdk');
require('dotenv').config();

const pool = require('./db');

function cleanString(value) {
  return String(value ?? '').trim();
}

function resolveNetwork() {
  const net = cleanString(process.env.STELLAR_NETWORK).toLowerCase();
  if (net === 'public' || net === 'pubnet' || net === 'mainnet') {
    return {
      horizon: cleanString(process.env.STELLAR_HORIZON_URL) || 'https://horizon.stellar.org',
      passphrase: Networks.PUBLIC,
      explorerBase: cleanString(process.env.STELLAR_EXPERT_TX_BASE)
        || 'https://stellar.expert/explorer/public/tx/',
    };
  }

  return {
    horizon: cleanString(process.env.STELLAR_HORIZON_URL) || 'https://horizon-testnet.stellar.org',
    passphrase: Networks.TESTNET,
    explorerBase: cleanString(process.env.STELLAR_EXPERT_TX_BASE)
      || 'https://stellar.expert/explorer/testnet/tx/',
  };
}

async function loadStellarKeypairFromConfig() {
  const fromDb = await pool.query(
    `SELECT cle, valeur FROM config WHERE cle IN ('stellar_public_key','stellar_secret_key')`,
  );
  let publicKey = null;
  let secret = null;
  for (const row of fromDb.rows) {
    if (row.cle === 'stellar_public_key') publicKey = cleanString(row.valeur);
    if (row.cle === 'stellar_secret_key') secret = cleanString(row.valeur);
  }

  secret = secret || cleanString(process.env.STELLAR_SECRET_KEY) || cleanString(process.env.SECRET_KEY);
  publicKey = publicKey || cleanString(process.env.STELLAR_PUBLIC_KEY) || cleanString(process.env.PUBLIC_KEY);

  if (!secret) {
    throw new Error('Cle Stellar secretes introuvable (config stellar_secret_key ou variable STELLAR_SECRET_KEY).');
  }

  const keypair = Keypair.fromSecret(secret);
  if (publicKey && publicKey !== keypair.publicKey()) {
    throw new Error('STELLAR_PUBLIC_KEY ne correspond pas a la cle secrete.');
  }

  return { keypair, publicKey: keypair.publicKey() };
}

function sanitizeManageDataKey(libelle) {
  const ascii = cleanString(libelle).replace(/[^a-zA-Z0-9_]/g, '_');
  const trimmed = ascii.substring(0, 64) || 'coopledger_tx';
  return trimmed;
}

/**
 * Scelle un mouvement financier sur Stellar (manageData).
 * @param {string} libelle
 * @param {number} montant
 * @returns {Promise<{ hash: string, explorer: string }>}
 */
async function enregistrerTransaction(libelle, montant) {
  const { horizon, passphrase, explorerBase } = resolveNetwork();
  const server = new Horizon.Server(horizon);
  const { keypair, publicKey } = await loadStellarKeypairFromConfig();
  const account = await server.loadAccount(publicKey);
  const dataKey = sanitizeManageDataKey(libelle);
  const valueStr = String(montant);
  const dataValueBytes = Buffer.from(valueStr, 'utf8');
  if (dataValueBytes.length > 64) {
    throw new Error('Valeur de donnee Stellar trop longue (max 64 octets).');
  }

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: passphrase,
  })
    .addOperation(Operation.manageData({
      name: dataKey,
      value: valueStr,
    }))
    .setTimeout(60)
    .build();

  transaction.sign(keypair);
  const result = await server.submitTransaction(transaction);
  const hash = result.hash;
  const explorer = `${explorerBase.replace(/\/$/, '/')}/${hash}`;

  return { hash, explorer };
}

module.exports = {
  enregistrerTransaction,
};
