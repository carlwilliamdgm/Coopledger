const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const pool = require('./db');

function formatMontant(montant) {
  return `${Number(montant || 0).toLocaleString('fr-FR')} FCFA`;
}

function formatDate(dateValue) {
  return new Date(dateValue).toLocaleDateString('fr-FR');
}

function getPeriode(mois, annee) {
  const month = Number(mois);
  const year = Number(annee);

  if (!Number.isInteger(month) || month < 1 || month > 12) {
    throw new Error('Le mois doit etre un entier entre 1 et 12.');
  }

  if (!Number.isInteger(year) || year < 1900) {
    throw new Error('L annee doit etre un entier valide.');
  }

  const debut = new Date(Date.UTC(year, month - 1, 1));
  const fin = new Date(Date.UTC(year, month, 1));

  return { month, year, debut, fin };
}

function collectPdfBuffer(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

function drawRow(doc, label, value, y, options = {}) {
  if (options.header) {
    doc.font('Helvetica-Bold');
  } else {
    doc.font('Helvetica');
  }

  doc.text(label, 72, y, { width: 280 });
  doc.text(value, 360, y, { width: 160, align: 'right' });
}

async function genererRapportMensuel(mois, annee) {
  const { month, year, debut, fin } = getPeriode(mois, annee);

  const totalsResult = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN montant > 0 THEN montant ELSE 0 END), 0)::int AS recettes,
       COALESCE(SUM(CASE WHEN montant < 0 THEN ABS(montant) ELSE 0 END), 0)::int AS depenses
     FROM transactions
     WHERE date >= $1 AND date < $2`,
    [debut, fin]
  );

  const cotisationsResult = await pool.query(
    `SELECT COALESCE(SUM(montant), 0)::int AS cotisations
     FROM cotisations
     WHERE date >= $1 AND date < $2`,
    [debut, fin]
  );

  const transactionsResult = await pool.query(
    `SELECT date, libelle, montant, hash
     FROM transactions
     WHERE date >= $1 AND date < $2
     ORDER BY date ASC`,
    [debut, fin]
  );

  const recettes = Number(totalsResult.rows[0]?.recettes || 0);
  const depenses = Number(totalsResult.rows[0]?.depenses || 0);
  const cotisations = Number(cotisationsResult.rows[0]?.cotisations || 0);
  const bilanNet = recettes + cotisations - depenses;

  const doc = new PDFDocument({ margin: 56, size: 'A4' });
  const bufferPromise = collectPdfBuffer(doc);

  doc.font('Helvetica-Bold').fontSize(22).fillColor('#1B4F72').text('CoopLedger', { align: 'center' });
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(12).fillColor('#333333').text('Rapport mensuel de gouvernance financiere', { align: 'center' });
  doc.moveDown(1.5);
  doc.font('Helvetica-Bold').fontSize(14).text(`Periode du rapport : ${String(month).padStart(2, '0')}/${year}`);
  doc.moveDown(1);

  const tableTop = doc.y + 8;
  doc.rect(72, tableTop, 448, 116).stroke('#1B4F72');
  drawRow(doc, 'Indicateur', 'Montant', tableTop + 14, { header: true });
  doc.moveTo(72, tableTop + 36).lineTo(520, tableTop + 36).stroke('#1B4F72');
  drawRow(doc, 'Recettes', formatMontant(recettes), tableTop + 50);
  drawRow(doc, 'Depenses', formatMontant(depenses), tableTop + 68);
  drawRow(doc, 'Cotisations collectees', formatMontant(cotisations), tableTop + 86);
  drawRow(doc, 'Bilan net', formatMontant(bilanNet), tableTop + 104, { header: true });

  doc.y = tableTop + 148;
  doc.font('Helvetica-Bold').fontSize(14).text('Transactions du mois');
  doc.moveDown(0.7);

  if (!transactionsResult.rows.length) {
    doc.font('Helvetica').fontSize(11).text('Aucune transaction enregistree pour cette periode.');
  } else {
    transactionsResult.rows.forEach(transaction => {
      if (doc.y > 720) {
        doc.addPage();
      }

      doc.font('Helvetica-Bold').fontSize(10).text(`${formatDate(transaction.date)} - ${transaction.libelle}`);
      doc.font('Helvetica').fontSize(10)
        .text(`Montant : ${formatMontant(transaction.montant)}`)
        .text(`Hash Stellar : ${transaction.hash || '-'}`, { width: 480 });
      doc.moveDown(0.6);
    });
  }

  doc.end();
  return bufferPromise;
}

function getMoisPrecedent(date = new Date()) {
  const previous = new Date(date.getFullYear(), date.getMonth() - 1, 1);
  return {
    mois: previous.getMonth() + 1,
    annee: previous.getFullYear(),
  };
}

function planifierRapportMensuel() {
  let lastGeneratedKey = null;

  const verifier = async () => {
    const now = new Date();

    if (now.getDate() !== 1 || now.getHours() !== 0) {
      return;
    }

    const { mois, annee } = getMoisPrecedent(now);
    const key = `${annee}-${String(mois).padStart(2, '0')}`;

    if (lastGeneratedKey === key) {
      return;
    }

    const buffer = await genererRapportMensuel(mois, annee);
    const rapportsDir = path.join(__dirname, 'rapports');
    fs.mkdirSync(rapportsDir, { recursive: true });
    fs.writeFileSync(path.join(rapportsDir, `rapport-${key}.pdf`), buffer);
    lastGeneratedKey = key;
  };

  verifier().catch(err => console.error('Erreur generation rapport mensuel:', err));

  return setInterval(() => {
    verifier().catch(err => console.error('Erreur generation rapport mensuel:', err));
  }, 60 * 60 * 1000);
}

module.exports = {
  genererRapportMensuel,
  planifierRapportMensuel,
};
