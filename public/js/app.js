let transactions = [];
let members = [];
let demoIndex = 0;
let currentProfile = null;

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

function getPermissions(role) {
  const normalized = String(role || '').toLowerCase();

  return {
    canSuggest: normalized === 'president',
    canTransact: normalized === 'tresoriere',
    canVote: normalized === 'membre',
    canManageMembers: ['president', 'tresoriere', 'secretaire'].includes(normalized)
  };
}

function getProfileDescription(role) {
  const permissions = getPermissions(role);

  if (permissions.canSuggest) {
    return 'Peut proposer une operation soumise au vote et gerer la cooperative.';
  }

  if (permissions.canTransact) {
    return 'Peut ajouter une transaction financiere scellee et gerer les membres.';
  }

  if (permissions.canManageMembers) {
    return 'Peut gerer les personnes de la cooperative et consulter les preuves.';
  }

  if (permissions.canVote) {
    return 'Peut consulter les preuves et voter les operations.';
  }

  return 'Peut seulement consulter et verifier les preuves.';
}

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

function formatAbsoluteMontant(montant) {
  return `${Math.abs(montant).toLocaleString('fr-FR')} FCFA`;
}

function isCotisation(libelle) {
  return String(libelle || '').toLowerCase().includes('cotisation');
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
        <td>
          ${transaction.libelle}
          ${transaction.memberName ? `<small class="linked-member">Membre : ${transaction.memberName}</small>` : ''}
        </td>
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
  renderDashboard();
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
      <td>
        <div class="member-actions">
        <button class="status-button" onclick="changerStatutMembre('${member.id}')" ${currentProfile?.canManageMembers ? '' : 'disabled'}>
          ${member.statut === 'Actif' ? 'Suspendre' : 'Activer'}
        </button>
        <button class="delete-button" onclick="supprimerMembre('${member.id}')" ${currentProfile?.canManageMembers ? '' : 'disabled'}>
          Supprimer
        </button>
        </div>
      </td>
    </tr>
  `).join('');

  document.getElementById('members-count').textContent = members.length;
  document.getElementById('sidebar-members-count').textContent = `${members.length} personnes`;
  document.getElementById('active-members-count').textContent = members.filter(member => member.statut === 'Actif').length;
  renderExistingProfiles();
}

function renderDashboard() {
  const balance = transactions.reduce((total, transaction) => total + transaction.montant, 0);
  const contributions = transactions
    .filter(transaction => transaction.montant > 0 && isCotisation(transaction.libelle))
    .reduce((total, transaction) => total + transaction.montant, 0);
  const expenses = transactions
    .filter(transaction => transaction.montant < 0)
    .reduce((total, transaction) => total + transaction.montant, 0);

  document.getElementById('coop-balance').textContent = formatAbsoluteMontant(balance);
  document.getElementById('monthly-contributions').textContent = formatAbsoluteMontant(contributions);
  document.getElementById('monthly-expenses').textContent = formatAbsoluteMontant(expenses);
}

function renderExistingProfiles() {
  const container = document.getElementById('existing-profiles');
  if (!container) return;

  const memberButtons = members.map(member => `
    <button class="profile-login" onclick="loginExistingMember('${member.id}')">
      <strong>${member.nom}</strong>
      <span>${member.role} · ${member.cotisations.toLocaleString('fr-FR')} FCFA cotisés</span>
    </button>
  `).join('');

  container.innerHTML = `
    ${memberButtons}
    <button class="profile-login" onclick="loginDemoProfile('observateur')">
      <strong>Partenaire externe</strong>
      <span>Observateur</span>
    </button>
  `;
}

function openSession(profile) {
  const permissions = getPermissions(profile.role);
  currentProfile = {
    ...profile,
    description: profile.description || getProfileDescription(profile.role),
    ...permissions
  };

  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app-shell').classList.remove('hidden');
  document.getElementById('profile-name').textContent = currentProfile.name;
  document.getElementById('profile-role').textContent = currentProfile.role;
  document.getElementById('profile-description').textContent = currentProfile.description;
  applyPermissions();
}

function applyPermissions() {
  if (!currentProfile) return;

  document.getElementById('new-transaction-btn').disabled = !currentProfile.canTransact;
  document.getElementById('proposal-btn').disabled = !currentProfile.canSuggest;
  document.getElementById('add-member-btn').disabled = !currentProfile.canManageMembers;

  document.querySelectorAll('.btn-pour, .btn-contre').forEach(button => {
    button.disabled = !currentProfile.canVote;
  });
  renderMembers();
}

function loginDemoProfile(profileId) {
  openSession(profiles[profileId]);
}

function loginExistingMember(memberId) {
  const member = members.find(item => item.id === memberId);
  if (!member) return;

  openSession({
    id: member.id,
    name: member.nom,
    role: member.role,
    cotisations: member.cotisations,
    description: getProfileDescription(member.role)
  });
}

function deconnecter() {
  currentProfile = null;
  arreterDemo();
  document.getElementById('app-shell').classList.add('hidden');
  document.getElementById('auth-screen').classList.remove('hidden');
}

async function enregistrerProfil(event) {
  event.preventDefault();

  const name = document.getElementById('register-name').value.trim();
  const role = document.getElementById('register-role').value;
  const cotisations = Number(document.getElementById('register-cotisations').value || 0);

  if (!name) {
    alert('Le nom est obligatoire.');
    return;
  }

  if (!Number.isInteger(cotisations) || cotisations < 0) {
    alert('Les cotisations doivent etre un entier positif ou nul.');
    return;
  }

  if (role !== 'Observateur') {
    try {
      const response = await fetch('/api/members', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nom: name, role, cotisations, statut: 'Actif' })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Enregistrement refuse.');
      }

      members.push(data.member);
      renderMembers();
    } catch (error) {
      alert(error.message || 'Erreur lors de l enregistrement.');
      console.error(error);
      return;
    }
  }

  openSession({
    name,
    role,
    description: getProfileDescription(role)
  });

  event.target.reset();
  document.getElementById('register-cotisations').value = '0';
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
  if (!currentProfile?.canTransact) {
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

  let memberId = '';
  if (montant > 0 && libelle.toLowerCase().includes('cotisation')) {
    const choix = prompt(
      'ID du membre concerne par cette cotisation (laisser vide si non applicable) :\n' +
      members.map(member => `${member.id} - ${member.nom} (${member.cotisations.toLocaleString('fr-FR')} FCFA)`).join('\n')
    )?.trim();

    memberId = choix || '';
  } else if (montant < 0) {
    alert('Cette depense reduira le solde total de la cooperative, sans modifier les cotisations individuelles.');
  }

  const btn = document.querySelector('.btn-primary');
  btn.textContent = 'Enregistrement sur blockchain...';
  btn.disabled = true;

  try {
    const response = await fetch('/api/transaction', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ libelle, montant, memberId })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Transaction refusee');
    }

    transactions.unshift(data.transaction);
    if (data.member) {
      members = members.map(member => member.id === data.member.id ? data.member : member);
      renderMembers();
    }
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
  if (!currentProfile?.canSuggest) {
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
  if (!currentProfile?.canManageMembers) {
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

async function changerStatutMembre(memberId) {
  if (!currentProfile?.canManageMembers) {
    alert('Seuls le president et ses collaborateurs peuvent modifier le statut des comptes.');
    return;
  }

  const member = members.find(item => item.id === memberId);
  if (!member) return;

  const statut = member.statut === 'Actif' ? 'Inactif' : 'Actif';

  try {
    const response = await fetch(`/api/members/${encodeURIComponent(memberId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statut })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Modification refusee.');
    }

    members = members.map(item => item.id === data.member.id ? data.member : item);
    renderMembers();
  } catch (error) {
    alert(error.message || 'Erreur lors de la modification du statut.');
    console.error(error);
  }
}

async function supprimerMembre(memberId) {
  if (!currentProfile?.canManageMembers) {
    alert('Seuls le president et ses collaborateurs peuvent supprimer un compte.');
    return;
  }

  if (currentProfile.id === memberId) {
    alert('Vous ne pouvez pas supprimer le compte actuellement connecte.');
    return;
  }

  const member = members.find(item => item.id === memberId);
  if (!member) return;

  const confirmed = confirm(`Supprimer ${member.nom} de la cooperative ? Cette action retire son profil de connexion.`);
  if (!confirmed) return;

  try {
    const response = await fetch(`/api/members/${encodeURIComponent(memberId)}`, {
      method: 'DELETE'
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Suppression refusee.');
    }

    members = members.filter(item => item.id !== data.member.id);
    renderMembers();
  } catch (error) {
    alert(error.message || 'Erreur lors de la suppression.');
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
  openSession(profiles[step.profile]);
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
      if (!currentProfile?.canVote) {
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
