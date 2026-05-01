let transactions = [];
let members = [];
let demoIndex = 0;
let currentProfile = 'president';

const profiles = {
  president: {
    name: 'Kofi AGBEKO',
    role: 'President',
    description: 'Peut proposer une operation soumise au vote et gerer la cooperative.',
    canSuggest: true,
    canTransact: false,
    canVote: false,
    canManageMembers: true
  },
  tresoriere: {
    name: 'Ama TCHAMDJA',
    role: 'Tresoriere',
    description: 'Peut ajouter une transaction financiere scellee et gerer les membres.',
    canSuggest: false,
    canTransact: true,
    canVote: false,
    canManageMembers: true
  },
  secretaire: {
    name: 'Koffi BOUKPESSI',
    role: 'Secretaire',
    description: 'Peut gerer les personnes de la cooperative et consulter les preuves.',
    canSuggest: false,
    canTransact: false,
    canVote: false,
    canManageMembers: true
  },
  membre: {
    name: 'Abla GNASSINGBE',
    role: 'Membre',
    description: 'Peut consulter les preuves et voter les operations.',
    canSuggest: false,
    canTransact: false,
    canVote: true,
    canManageMembers: false
  },
  observateur: {
    name: 'Partenaire externe',
    role: 'Observateur',
    description: 'Peut seulement consulter et verifier les preuves.',
    canSuggest: false,
    canTransact: false,
    canVote: false,
    canManageMembers: false
  }
};

const demoSteps = [
  {
    page: 'dashboard',
    profile: 'observateur',
    title: 'Tableau de bord',
    text: 'On commence avec une vue claire de la cooperative : solde, activite du mois, votes et score de transparence.'
  },
  {
    page: 'transactions',
    profile: 'observateur',
    title: 'Historique scelle',
    text: 'Chaque ligne importante peut etre reliee a une preuve blockchain. Le hash sert de trace publique.'
  },
  {
    page: 'transactions',
    profile: 'tresoriere',
    title: 'Nouvelle transaction',
    text: 'En role Tresoriere, le bouton d ajout est disponible pour sceller une transaction.'
  },
  {
    page: 'vote',
    profile: 'president',
    title: 'Proposition du president',
    text: 'En role President, une operation peut etre suggeree et transmise aux membres pour vote.'
  },
  {
    page: 'vote',
    profile: 'membre',
    title: 'Vote des membres',
    text: 'En role Membre, les boutons de vote sont actifs. En Observateur, la consultation reste seule autorisee.'
  },
  {
    page: 'membres',
    profile: 'secretaire',
    title: 'Gestion des personnes',
    text: 'Les responsables et collaborateurs peuvent ajouter une personne a la cooperative.'
  }
];

function formatDate(dateValue) {
  return new Date(dateValue).toLocaleDateString('fr-FR');
}

function formatMontant(montant) {
  const prefix = montant > 0 ? '+' : '';
  return `${prefix}${montant.toLocaleString('fr-FR')} FCFA`;
}

function shortHash(hash) {
  return `${hash.substring(0, 16)}...`;
}

// Navigation entre pages
function showPage(pageId, navTarget) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById('page-' + pageId).classList.add('active');

  const activeNav = navTarget || document.querySelector(`.nav-item[onclick*="${pageId}"]`);
  if (activeNav) {
    activeNav.classList.add('active');
  }
}

function renderTransactions() {
  const tbody = document.getElementById('transactions-list');

  if (!transactions.length) {
    tbody.innerHTML = '<tr><td colspan="5">Aucune transaction enregistree.</td></tr>';
    return;
  }

  tbody.innerHTML = transactions.map(transaction => {
    const isPositif = transaction.montant > 0;
    return `
      <tr>
        <td>${formatDate(transaction.date)}</td>
        <td>${transaction.libelle}</td>
        <td class="${isPositif ? 'montant-positif' : 'montant-negatif'}">
          ${formatMontant(transaction.montant)}
        </td>
        <td class="hash">
          <button class="hash-button" onclick="afficherRecu('${transaction.id}')">${shortHash(transaction.hash)}</button>
        </td>
        <td><span class="badge-scelle">Scelle</span></td>
      </tr>
    `;
  }).join('');

  document.getElementById('proof-count').textContent = transactions.length;
  document.getElementById('proof-last').textContent = formatDate(transactions[0].date);
}

function renderMembers() {
  const tbody = document.getElementById('members-list');

  if (!members.length) {
    tbody.innerHTML = '<tr><td colspan="5">Aucun membre enregistre.</td></tr>';
    document.getElementById('members-count').textContent = '0';
    document.getElementById('sidebar-members-count').textContent = '0 personne';
    return;
  }

  tbody.innerHTML = members.map(member => `
    <tr>
      <td>${member.id}</td>
      <td>${member.nom}</td>
      <td>${member.role}</td>
      <td>${member.cotisations.toLocaleString('fr-FR')} FCFA</td>
      <td><span class="${member.statut === 'Actif' ? 'badge-actif' : 'badge-inactif'}">${member.statut}</span></td>
    </tr>
  `).join('');

  document.getElementById('members-count').textContent = members.length;
  document.getElementById('sidebar-members-count').textContent = `${members.length} personnes`;
}

function connecterProfil(profileId) {
  currentProfile = profileId;
  const config = profiles[currentProfile];

  document.getElementById('profile-name').textContent = config.name;
  document.getElementById('profile-role').textContent = config.role;
  document.getElementById('profile-description').textContent = config.description;
  document.getElementById('new-transaction-btn').disabled = !config.canTransact;
  document.getElementById('proposal-btn').disabled = !config.canSuggest;
  document.getElementById('add-member-btn').disabled = !config.canManageMembers;

  document.querySelectorAll('.btn-pour, .btn-contre').forEach(button => {
    button.disabled = !config.canVote;
  });
}

async function chargerTransactions() {
  try {
    const response = await fetch('/api/transactions');
    const data = await response.json();
    transactions = data.transactions || [];
    renderTransactions();
  } catch (error) {
    document.getElementById('transactions-list').innerHTML = '<tr><td colspan="5">Impossible de charger les transactions.</td></tr>';
    console.error(error);
  }
}

async function chargerMembres() {
  try {
    const response = await fetch('/api/members');
    const data = await response.json();
    members = data.members || [];
    renderMembers();
  } catch (error) {
    document.getElementById('members-list').innerHTML = '<tr><td colspan="5">Impossible de charger les membres.</td></tr>';
    console.error(error);
  }
}

// Enregistrer une transaction sur Stellar
function lireMontant(value) {
  const normalized = String(value ?? '').replace(/\s/g, '').replace(',', '.');
  const montant = Number(normalized);

  if (!Number.isInteger(montant) || montant === 0) {
    return null;
  }

  return montant;
}

async function enregistrerTransaction() {
  if (!profiles[currentProfile].canTransact) {
    alert('Seule la tresoriere peut ajouter une transaction.');
    return;
  }

  const libelle = prompt('Libelle de la transaction :')?.trim();
  if (!libelle) return;

  const montantSaisi = prompt('Montant (FCFA) :');
  if (!montantSaisi) return;

  const montant = lireMontant(montantSaisi);
  if (montant === null) {
    alert('Le montant doit etre un nombre entier non nul. Exemple : 5000 ou -150000.');
    return;
  }

  const btn = document.querySelector('.btn-primary');
  btn.textContent = 'Enregistrement sur blockchain...';
  btn.disabled = true;

  try {
    const response = await fetch('/api/transaction', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ libelle, montant })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Transaction refusee');
    }

    transactions.unshift(data.transaction);
    renderTransactions();
    afficherRecu(data.transaction.id);
    alert(`Transaction enregistree sur Stellar.\nHash : ${data.transaction.hash}`);
  } catch (error) {
    alert(error.message || 'Erreur lors de l enregistrement');
    console.error(error);
  } finally {
    btn.textContent = '+ Nouvelle Transaction';
    btn.disabled = false;
  }
}

function afficherRecu(id) {
  const transaction = transactions.find(item => item.id === id);
  if (!transaction) return;

  document.getElementById('receipt-title').textContent = transaction.libelle;
  document.getElementById('receipt-date').textContent = formatDate(transaction.date);
  document.getElementById('receipt-amount').textContent = formatMontant(transaction.montant);
  document.getElementById('receipt-hash').textContent = transaction.hash;
  document.getElementById('receipt-link').href = transaction.explorer;
  document.getElementById('receipt-panel').classList.remove('hidden');
}

function fermerRecu() {
  document.getElementById('receipt-panel').classList.add('hidden');
}

function suggererOperation() {
  if (!profiles[currentProfile].canSuggest) {
    alert('Seul le president peut suggerer une operation.');
    return;
  }

  const titre = prompt('Operation a soumettre au vote :')?.trim();
  if (!titre) return;

  const budget = prompt('Budget estime (FCFA) :')?.trim();
  if (!budget) return;

  const montantBudget = lireMontant(budget);
  if (montantBudget === null || montantBudget < 0) {
    alert('Le budget doit etre un nombre entier positif.');
    return;
  }

  document.getElementById('proposal-title').textContent = titre;
  document.getElementById('proposal-budget').textContent = `Budget estime : ${montantBudget.toLocaleString('fr-FR')} FCFA`;
  document.getElementById('proposal-panel').classList.remove('hidden');
  alert('Operation suggeree. Passe en role Membre pour simuler la validation par vote.');
}

async function ajouterMembre() {
  if (!profiles[currentProfile].canManageMembers) {
    alert('Seuls le president et ses collaborateurs peuvent ajouter une personne.');
    return;
  }

  const nom = prompt('Nom complet de la personne :')?.trim();
  if (!nom) return;

  const role = prompt('Role dans la cooperative :', 'Membre')?.trim();
  if (!role) return;

  const cotisationsSaisies = prompt('Cotisations versees (FCFA) :', '0');
  if (cotisationsSaisies === null) return;

  const cotisations = Number(String(cotisationsSaisies).replace(/\s/g, '').replace(',', '.'));
  if (!Number.isInteger(cotisations) || cotisations < 0) {
    alert('Les cotisations doivent etre un entier positif ou nul.');
    return;
  }

  try {
    const response = await fetch('/api/members', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nom, role, cotisations, statut: 'Actif' })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Ajout refuse.');
    }

    members.push(data.member);
    renderMembers();
    alert(`${data.member.nom} a ete ajoute a la cooperative.`);
  } catch (error) {
    alert(error.message || 'Erreur lors de l ajout.');
    console.error(error);
  }
}

function lancerDemo() {
  demoIndex = 0;
  document.getElementById('demo-guide').classList.remove('hidden');
  afficherEtapeDemo();
}

function afficherEtapeDemo() {
  const step = demoSteps[demoIndex];
  document.getElementById('profile-select').value = step.profile;
  connecterProfil(step.profile);
  showPage(step.page);
  document.getElementById('demo-title').textContent = step.title;
  document.getElementById('demo-text').textContent = step.text;
}

function etapeDemoSuivante() {
  demoIndex += 1;

  if (demoIndex >= demoSteps.length) {
    arreterDemo();
    return;
  }

  afficherEtapeDemo();
}

function arreterDemo() {
  document.getElementById('demo-guide').classList.add('hidden');
}

// Voter
document.addEventListener('DOMContentLoaded', () => {
  chargerTransactions();
  chargerMembres();
  connecterProfil(currentProfile);

  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', function(event) {
      event.preventDefault();
      const match = this.getAttribute('onclick').match(/showPage\('(.+)'\)/);
      if (match) {
        showPage(match[1], this);
      }
    });
  });

  document.querySelectorAll('.btn-pour, .btn-contre').forEach(btn => {
    btn.addEventListener('click', function() {
      if (!profiles[currentProfile].canVote) {
        alert('Seuls les membres peuvent voter.');
        return;
      }

      const voteCard = this.closest('.vote-card') || this.closest('.proposal-panel');
      const titre = voteCard.querySelector('h3, h2').textContent;
      const choix = this.classList.contains('btn-pour') ? 'POUR' : 'CONTRE';

      alert(`Vote enregistre.\nProposition : ${titre}\nVotre choix : ${choix}\nEnregistre sur Stellar Testnet`);

      this.textContent = 'Vote';
      this.disabled = true;
      voteCard.querySelector(this.classList.contains('btn-pour') ? '.btn-contre' : '.btn-pour').disabled = true;
    });
  });
});
