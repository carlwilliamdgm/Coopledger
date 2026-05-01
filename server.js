const http = require('http');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const { Horizon, Keypair, TransactionBuilder, Networks, Operation, BASE_FEE } = require('@stellar/stellar-sdk');

const server = new Horizon.Server('https://horizon-testnet.stellar.org');
const DATA_DIR = path.join(__dirname, 'data');
const TRANSACTIONS_FILE = path.join(DATA_DIR, 'transactions.json');
const MEMBERS_FILE = path.join(DATA_DIR, 'members.json');

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function readTransactions() {
  try {
    const data = fs.readFileSync(TRANSACTIONS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

function saveTransactions(transactions) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(TRANSACTIONS_FILE, JSON.stringify(transactions, null, 2));
}

function readMembers() {
  try {
    const data = fs.readFileSync(MEMBERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

function saveMembers(members) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(MEMBERS_FILE, JSON.stringify(members, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('JSON invalide.'));
      }
    });
  });
}

function parseMontant(value) {
  const normalized = String(value ?? '').replace(/\s/g, '').replace(',', '.');
  const montant = Number(normalized);

  if (!Number.isInteger(montant) || montant === 0) {
    throw new Error('Le montant doit etre un nombre entier non nul.');
  }

  return montant;
}

// Enregistrer une transaction sur Stellar
async function enregistrerStellar(libelle, montant) {
  const sourceKeypair = Keypair.fromSecret(process.env.SECRET_KEY);
  const sourcePublicKey = process.env.PUBLIC_KEY;

  const account = await server.loadAccount(sourcePublicKey);

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(Operation.manageData({
      name: libelle.substring(0, 64),
      value: montant.toString().substring(0, 64),
    }))
    .setTimeout(30)
    .build();

  transaction.sign(sourceKeypair);
  const result = await server.submitTransaction(transaction);
  return result.hash;
}

// Servir les fichiers statiques
function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

// Serveur HTTP
const httpServer = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'GET' && req.url === '/api/transactions') {
    sendJson(res, 200, { transactions: readTransactions() });
    return;
  }

  if (req.method === 'GET' && req.url === '/api/members') {
    sendJson(res, 200, { members: readMembers() });
    return;
  }

  if (req.method === 'POST' && req.url === '/api/members') {
    try {
      const { nom, role, cotisations, statut } = await parseBody(req);
      const nomNettoye = String(nom ?? '').trim();
      const roleNettoye = String(role ?? '').trim();
      const cotisationsValides = Number(String(cotisations ?? '').replace(/\s/g, '').replace(',', '.'));
      const statutNettoye = String(statut || 'Actif').trim();

      if (!nomNettoye) {
        throw new Error('Le nom du membre est obligatoire.');
      }

      if (!roleNettoye) {
        throw new Error('Le role du membre est obligatoire.');
      }

      if (!Number.isInteger(cotisationsValides) || cotisationsValides < 0) {
        throw new Error('Les cotisations doivent etre un entier positif ou nul.');
      }

      const members = readMembers();
      const nextNumber = members.length + 1;
      const member = {
        id: String(nextNumber).padStart(3, '0'),
        nom: nomNettoye,
        role: roleNettoye,
        cotisations: cotisationsValides,
        statut: statutNettoye
      };

      members.push(member);
      saveMembers(members);
      sendJson(res, 200, { success: true, member });
    } catch (err) {
      sendJson(res, 400, { error: err.message });
    }
    return;
  }

  // API Transaction
  if (req.method === 'POST' && req.url === '/api/transaction') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { libelle, montant } = JSON.parse(body);
        const libelleNettoye = String(libelle ?? '').trim();
        const montantValide = parseMontant(montant);

        if (!libelleNettoye) {
          throw new Error('Le libelle est obligatoire.');
        }

        const hash = await enregistrerStellar(libelleNettoye, montantValide);
        const transaction = {
          id: Date.now().toString(),
          date: new Date().toISOString(),
          libelle: libelleNettoye,
          montant: montantValide,
          hash,
          explorer: `https://stellar.expert/explorer/testnet/tx/${hash}`,
          statut: 'Scelle'
        };

        const transactions = readTransactions();
        transactions.unshift(transaction);
        saveTransactions(transactions);

        sendJson(res, 200, { success: true, transaction });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
    });
    return;
  }

  // Fichiers statiques
  const routes = {
    '/': ['public/index.html', 'text/html'],
    '/css/style.css': ['public/css/style.css', 'text/css'],
    '/js/app.js': ['public/js/app.js', 'application/javascript'],
  };

  const route = routes[req.url];
  if (route) {
    serveFile(res, path.join(__dirname, route[0]), route[1]);
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

const PORT = process.env.PORT || 3000;

httpServer.listen(PORT, () => {
  console.log(`CoopLedger en ligne sur le port ${PORT}`);
  console.log('Reseau : Stellar Testnet');
  console.log(`Dashboard : http://localhost:${PORT}`);
});
