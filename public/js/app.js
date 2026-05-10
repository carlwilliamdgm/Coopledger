let transactions = [];
let members = [];
let votes = [];
let cotisations = [];
let notifications = [];
let candidatures = [];
let currentUser = null;
let financialHealth = null;
let coopConfig = null;
let sseAbortController = null;
let sseReconnectTimer = null;

const TOKEN_KEY = 'token';
const PENDING_TRANSACTIONS_KEY = 'pendingTransactions';

function getToken() {
  return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
}

function setToken(token, persist = false) {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  const storage = persist ? localStorage : sessionStorage;
  storage.setItem(TOKEN_KEY, token);
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  currentUser = null;
}

function decodeJwt(token) {
  try {
    const payload = token.split('.')[1];
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(normalized)
        .split('')
        .map(char => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`)
        .join('')
    );
    return JSON.parse(json);
  } catch (error) {
    return null;
  }
}

function normalizeRole(role) {
  return String(role || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function getPermissions(role) {
  const normalized = normalizeRole(role);

  return {
    canSuggest: normalized === 'president',
    canTransact: normalized === 'tresorier' || normalized === 'tresoriere',
    canVote: normalized === 'membre',
    canManageMembers: ['admin', 'secretaire'].includes(normalized),
    canVerify: normalized === 'verificateur',
    canViewReport: ['president', 'tresorier', 'tresoriere', 'verificateur'].includes(normalized),
    isAdmin: normalized === 'admin',
  };
}

function getProfileDescription(role) {
  const permissions = getPermissions(role);

  if (permissions.canSuggest) return 'Peut proposer des operations soumises au vote.';
  if (permissions.canTransact) return 'Peut enregistrer cotisations et transactions scellees.';
  if (permissions.canManageMembers) return 'Peut administrer les membres et les roles.';
  if (permissions.canVerify) return 'Peut signaler une transaction suspecte.';
  if (permissions.canVote) return 'Peut voter et consulter ses cotisations.';
  return 'Peut consulter les informations autorisees.';
}

function formatDate(dateValue) {
  if (!dateValue) return '-';
  return new Date(dateValue).toLocaleDateString('fr-FR');
}

function formatDateTime(dateValue) {
  if (!dateValue) return '-';
  return new Date(dateValue).toLocaleString('fr-FR');
}

function formatMontant(montant) {
  const value = Number(montant || 0);
  const prefix = value > 0 ? '+' : '';
  return `${prefix}${value.toLocaleString('fr-FR')} FCFA`;
}

function formatAbsoluteMontant(montant) {
  return `${Math.abs(Number(montant || 0)).toLocaleString('fr-FR')} FCFA`;
}

function lireMontant(value) {
  const normalized = String(value ?? '').replace(/\s/g, '').replace(',', '.');
  const montant = Number(normalized);
  return Number.isInteger(montant) && montant !== 0 ? montant : null;
}

function shortHash(hash) {
  return hash ? `${hash.substring(0, 16)}...` : '-';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function apiFetch(url, options = {}) {
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {}),
  };
  const token = getToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });
  const isJson = response.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await response.json() : null;

  if (response.status === 401) {
    handleAuthExpired();
    throw new Error(data?.error || 'Session expiree.');
  }

  if (!response.ok) {
    throw new Error(data?.error || `Erreur HTTP ${response.status}`);
  }

  return data;
}

function handleAuthExpired() {
  clearSession();
  stopNotificationsStream();
  document.getElementById('app-shell')?.classList.add('hidden');
  document.getElementById('auth-screen')?.classList.remove('hidden');
  renderAuthForms();
}

function openSessionFromToken(token) {
  const decoded = decodeJwt(token);

  if (!decoded || (decoded.exp && decoded.exp * 1000 <= Date.now())) {
    handleAuthExpired();
    return;
  }

  currentUser = {
    ...decoded,
    name: decoded.nom,
    permissions: getPermissions(decoded.role),
  };

  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app-shell').classList.remove('hidden');
  document.getElementById('profile-name').textContent = currentUser.nom;
  document.getElementById('profile-role').textContent = currentUser.role;
  document.getElementById('profile-description').textContent = getProfileDescription(currentUser.role);

  applyPermissions();
  startAfterLogin();
  startNotificationsStream();
}

async function startAfterLogin() {
  if (normalizeRole(currentUser?.role) === 'admin') {
    const config = await apiFetch('/api/config');
    if (!config.nom_coop) {
      showPage('setup-config');
      return;
    }
  }

  showPage('dashboard');
  loadProtectedData();
}

function showPage(pageId, navTarget) {
  document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

  const page = document.getElementById(`page-${pageId}`);
  if (page) page.classList.add('active');

  const activeNav = navTarget || document.querySelector(`.nav-item[data-page="${pageId}"]`) || document.querySelector(`.nav-item[onclick*="${pageId}"]`);
  if (activeNav) activeNav.classList.add('active');
}

function installDynamicInterface() {
  renderAuthForms();
  installExtraNavItems();
  installCotisationsPage();
  installNotificationsPage();
  installStartupPages();
  markDashboardNodes();
}

function renderAuthForms() {
  const container = document.getElementById('existing-profiles');
  const registerForm = document.querySelector('#auth-screen form');

  if (container) {
    container.innerHTML = `
      <form id="login-form" class="login-form">
        <label for="login-username">Identifiant</label>
        <input id="login-username" type="text" placeholder="komi_adjoka" autocomplete="username" required>
        <label for="login-password">Mot de passe</label>
        <input id="login-password" type="password" autocomplete="current-password" required>
        <label class="remember-row">
          <input id="remember-login" type="checkbox">
          <span>Rester connecte</span>
        </label>
        <button class="btn-primary" type="submit">Se connecter</button>
      </form>
    `;
    document.getElementById('login-form').addEventListener('submit', loginUser);
  }

  if (registerForm) {
    registerForm.innerHTML = `
      <p class="panel-label">Nouvel acces membre</p>
      <label for="register-name">Nom complet</label>
      <input id="register-name" type="text" placeholder="Ex. Komi ADJOKA" required>
      <label for="register-username">Identifiant</label>
      <input id="register-username" type="text" placeholder="komi_adjoka" pattern="[a-zA-Z0-9_]{3,20}" minlength="3" maxlength="20" autocomplete="username" required>
      <label for="register-email">Email</label>
      <input id="register-email" type="email" placeholder="komi@coop.test" required>
      <label for="register-password">Mot de passe</label>
      <input id="register-password" type="password" minlength="6" autocomplete="new-password" required>
      <label class="remember-row">
        <input id="register-observer" type="checkbox">
        <span>Je souhaite m'inscrire comme Observateur uniquement</span>
      </label>
      <button class="btn-primary" type="submit">Creer le compte et entrer</button>
    `;
    registerForm.onsubmit = enregistrerProfil;
  }
}

function installExtraNavItems() {
  const nav = document.querySelector('.sidebar nav');
  if (!nav || nav.querySelector('[data-page="cotisations"]')) return;

  nav.insertAdjacentHTML('beforeend', `
    <a href="#" class="nav-item" data-page="cotisations">💰 Cotisations</a>
    <a href="#" class="nav-item" data-page="notifications">🔔 Notifications</a>
  `);

  nav.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', event => {
      event.preventDefault();
      const page = item.dataset.page || item.getAttribute('onclick')?.match(/showPage\('(.+)'\)/)?.[1];
      if (page) showPage(page, item);
    });
  });
}

function installStartupPages() {
  const main = document.querySelector('.main-content');
  if (!main || document.getElementById('page-setup-config')) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="page-setup-config" class="page">
      <h1>Configuration initiale</h1>
      <form class="login-panel" onsubmit="configurerCoop(event)">
        <label for="setup-coop-name">Nom de la cooperative</label>
        <input id="setup-coop-name" type="text" required>
        <label for="setup-mandate-duration">Duree des mandats en mois</label>
        <input id="setup-mandate-duration" type="number" min="1" value="12" required>
        <button class="btn-primary" type="submit">Configurer</button>
      </form>
      <div id="setup-key-panel" class="receipt-panel hidden">
        <p class="panel-label">Cle unique generee une seule fois</p>
        <code id="setup-unique-key">-</code>
        <p>Conservez cette cle maintenant. Elle ne sera pas recuperable depuis l interface.</p>
        <button class="btn-secondary" onclick="copierCleUnique()">Copier</button>
        <button class="btn-primary" onclick="showPage('setup-members')">Constituer le bureau initial</button>
      </div>
    </div>
    <div id="page-setup-members" class="page">
      <h1>Constituer le bureau initial</h1>
      <form class="login-panel" onsubmit="creerMembreAdmin(event)">
        <label for="admin-member-name">Nom</label>
        <input id="admin-member-name" type="text" required>
        <label for="admin-member-username">Identifiant</label>
        <input id="admin-member-username" type="text" pattern="[a-zA-Z0-9_]{3,20}" required>
        <label for="admin-member-email">Email</label>
        <input id="admin-member-email" type="email" required>
        <label for="admin-member-password">Mot de passe</label>
        <input id="admin-member-password" type="password" minlength="6" required>
        <label for="admin-member-role">Role</label>
        <select id="admin-member-role" required>
          <option value="president">President</option>
          <option value="tresorier">Tresorier</option>
          <option value="secretaire">Secretaire</option>
          <option value="verificateur">Verificateur</option>
          <option value="membre">Membre</option>
          <option value="observateur">Observateur</option>
        </select>
        <button class="btn-primary" type="submit">Ajouter un membre</button>
      </form>
      <button class="btn-primary" onclick="terminerInitialisation()">Terminer et acceder au dashboard</button>
    </div>
  `);
}

function installCotisationsPage() {
  const main = document.querySelector('.main-content');
  if (!main || document.getElementById('page-cotisations')) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="page-cotisations" class="page">
      <div class="page-header">
        <h1>Cotisations</h1>
        <div class="cotisations-header-actions">
          <label for="fedapay-amount">Montant (FCFA)</label>
          <input id="fedapay-amount" type="number" min="1" placeholder="5000" />
          <button id="fedapay-btn" class="btn-primary" type="button" onclick="initierPaiementFedapay()">Payer</button>
        </div>
      </div>
      <form id="manual-cotisation-form" class="login-panel hidden" onsubmit="enregistrerCotisationManuelle(event)">
        <label for="cotisation-member-id">ID membre</label>
        <input id="cotisation-member-id" type="number" min="1" required>
        <label for="cotisation-montant">Montant</label>
        <input id="cotisation-montant" type="number" min="1" required>
        <label for="cotisation-mode">Mode</label>
        <input id="cotisation-mode" type="text" value="manuel" required>
        <button class="btn-primary" type="submit">Enregistrer</button>
      </form>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Date</th><th>Montant</th><th>Mode</th><th>Statut</th></tr>
          </thead>
          <tbody id="cotisations-list">
            <tr><td colspan="4">Chargement...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `);
}

function installNotificationsPage() {
  const main = document.querySelector('.main-content');
  if (!main || document.getElementById('page-notifications')) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="page-notifications" class="page">
      <h1>Notifications</h1>
      <div id="network-status" class="membres-stats"></div>
      <div id="notifications-list" class="table-container">
        <p>Aucune notification pour le moment.</p>
      </div>
    </div>
  `);
}

function markDashboardNodes() {
  const statValues = document.querySelectorAll('#page-dashboard .stats-grid .stat-card .stat-value');
  if (statValues[3]) statValues[3].id = 'open-votes-count';
  const proofSpans = document.querySelectorAll('.proof-grid span');
  if (proofSpans[1]) proofSpans[1].id = 'votes-proof-count';
  const score = document.querySelector('.panel-score');
  if (score) score.id = 'financial-health-score';
}

async function loginUser(event) {
  event.preventDefault();

  try {
    const data = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('login-username').value.trim(),
        password: document.getElementById('login-password').value,
      }),
    });
    setToken(data.token, document.getElementById('remember-login').checked);
    openSessionFromToken(data.token);
  } catch (error) {
    alert(error.message || 'Connexion impossible.');
  }
}

async function enregistrerProfil(event) {
  event.preventDefault();

  try {
    const data = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        nom: document.getElementById('register-name').value.trim(),
        username: document.getElementById('register-username').value.trim(),
        email: document.getElementById('register-email').value.trim(),
        password: document.getElementById('register-password').value,
        role: document.getElementById('register-observer').checked ? 'observateur' : 'membre',
      }),
    });
    setToken(data.token);
    alert(`Votre identifiant de connexion : @${data.member.username}`);
    event.target.reset();
    openSessionFromToken(data.token);
  } catch (error) {
    alert(error.message || 'Inscription impossible.');
  }
}

function deconnecter() {
  clearSession();
  stopNotificationsStream();
  document.getElementById('app-shell').classList.add('hidden');
  document.getElementById('auth-screen').classList.remove('hidden');
}

async function loadProtectedData() {
  await Promise.allSettled([
    chargerConfig(),
    chargerTransactions(),
    chargerMembres(),
    chargerVotes(),
    chargerCandidatures(),
    chargerCotisations(),
    chargerSante(),
  ]);
  renderDashboard();
  renderVotes();
  renderVotesInDashboard();
  flushPendingTransactions();
}

async function chargerConfig() {
  try {
    const data = await apiFetch('/api/config');
    coopConfig = data;
    document.getElementById('members-title').textContent = `Membres — ${data.nom_coop || 'Coop'}`;
  } catch (error) {
    coopConfig = { nom_coop: 'CoopLedger' };
    document.getElementById('members-title').textContent = 'Membres';
  }
}

async function chargerTransactions() {
  try {
    const data = await apiFetch('/api/transactions');
    transactions = data.transactions || [];
    renderTransactions();
  } catch (error) {
    renderTableError('transactions-list', 5, error.message);
  }
}

async function chargerMembres() {
  try {
    const data = await apiFetch('/api/members');
    members = data.members || [];
    renderMembers();
  } catch (error) {
    renderTableError('members-list', 6, error.message);
  }
}

async function chargerVotes() {
  try {
    const data = await apiFetch('/api/votes');
    votes = data.votes || [];
    renderVotes();
    renderVotesInDashboard();
  } catch (error) {
    const page = document.getElementById('page-vote');
    if (page) page.insertAdjacentHTML('beforeend', `<p>${escapeHtml(error.message)}</p>`);
  }
}

async function chargerCandidatures() {
  try {
    const data = await apiFetch('/api/candidatures');
    candidatures = data.candidatures || [];
    renderVotes();
    renderVotesInDashboard();
  } catch (error) {
    candidatures = [];
  }
}

async function chargerCotisations() {
  try {
    const data = await apiFetch('/api/cotisations/me');
    cotisations = data.cotisations || [];
    renderCotisations();
  } catch (error) {
    renderTableError('cotisations-list', 4, error.message);
  }
}

async function chargerSante() {
  try {
    financialHealth = await apiFetch('/api/sante');
    renderHealthScore();
  } catch (error) {
    financialHealth = null;
    renderHealthScore();
  }
}

function renderVotesInDashboard() {
  const container = document.getElementById('votes-container');
  if (!container) return;

  if (!votes.length) {
    container.innerHTML = '<p>Aucun vote en cours.</p>';
    return;
  }

  container.innerHTML = votes.map(renderVoteCard).join('');
}

function renderTableError(id, colspan, message) {
  const target = document.getElementById(id);
  if (target) target.innerHTML = `<tr><td colspan="${colspan}">${escapeHtml(message)}</td></tr>`;
}

function renderTransactions() {
  const tbody = document.getElementById('transactions-list');
  if (!tbody) return;

  if (!transactions.length) {
    tbody.innerHTML = '<tr><td colspan="5">Aucune transaction enregistree.</td></tr>';
  } else {
    tbody.innerHTML = transactions.map(transaction => {
      const amount = Number(transaction.montant || 0);
      return `
        <tr>
          <td>${formatDate(transaction.date)}</td>
          <td>${escapeHtml(transaction.libelle)}</td>
          <td class="${amount >= 0 ? 'montant-positif' : 'montant-negatif'}">${formatMontant(amount)}</td>
          <td class="hash">
            <button class="hash-button" onclick="afficherRecu('${escapeHtml(transaction.id)}')">${shortHash(transaction.hash)}</button>
          </td>
          <td><span class="badge-scelle">${escapeHtml(transaction.statut || 'scelle')}</span></td>
        </tr>
      `;
    }).join('');
  }

  document.getElementById('proof-count').textContent = transactions.length;
  document.getElementById('proof-last').textContent = transactions[0] ? formatDate(transactions[0].date) : '-';
  renderDashboard();
}

function renderMembers() {
  const tbody = document.getElementById('members-list');
  if (!tbody) return;

  if (!members.length) {
    tbody.innerHTML = '<tr><td colspan="6">Aucun membre enregistre.</td></tr>';
  } else {
    tbody.innerHTML = members.map(member => `
      <tr>
        <td>${member.id}</td>
        <td>${escapeHtml(member.nom)}</td>
        <td>${escapeHtml(member.role)}</td>
        <td>-</td>
        <td><span class="${member.statut === 'Actif' ? 'badge-actif' : 'badge-inactif'}">${escapeHtml(member.statut)}</span></td>
        <td>
          <button class="status-button" onclick="attribuerRole('${member.id}')" ${currentUser?.permissions.canManageMembers ? '' : 'disabled'}>
            Attribuer role
          </button>
        </td>
      </tr>
    `).join('');
  }

  document.getElementById('members-count').textContent = members.length;
  document.getElementById('sidebar-members-count').textContent = `${members.length} personnes`;
  document.getElementById('active-members-count').textContent = members.filter(member => member.statut === 'Actif').length;
}

function renderVotes() {
  const page = document.getElementById('page-vote');
  if (!page) return;

  page.querySelectorAll('.vote-card').forEach(card => card.remove());
  document.getElementById('proposal-panel')?.classList.add('hidden');

  const electionVotes = votes.filter(vote => vote.type === 'election');
  const decisionVotes = votes.filter(vote => vote.type !== 'election');
  const electionBlocks = candidatures.map(renderCandidatureCard).join('') + electionVotes.map(renderVoteCard).join('');
  const decisionBlocks = decisionVotes.map(renderVoteCard).join('');

  if (!electionBlocks && !decisionBlocks) {
    page.insertAdjacentHTML('beforeend', '<div class="vote-card"><h3>Aucune proposition</h3><p class="vote-info">Les nouvelles propositions apparaitront ici.</p></div>');
  } else {
    page.insertAdjacentHTML('beforeend', `
      <div class="vote-card"><h3>Élections en cours</h3></div>
      ${electionBlocks || '<div class="vote-card"><p class="vote-info">Aucune election ouverte.</p></div>'}
      <div class="vote-card"><h3>Propositions de décision</h3></div>
      ${decisionBlocks || '<div class="vote-card"><p class="vote-info">Aucune decision en cours.</p></div>'}
    `);
  }

  document.getElementById('open-votes-count').textContent = votes.filter(vote => vote.statut === 'ouvert').length;
  document.getElementById('votes-proof-count').textContent = votes.length;
  applyPermissions();
  renderDashboard();
}

function renderCandidatureCard(vacancy) {
  return `
    <div class="vote-card">
      <h3>Poste ${escapeHtml(vacancy.poste)}</h3>
      <p class="vote-info">${(vacancy.candidats || []).length} candidature(s) deposee(s)</p>
      <button class="btn-primary" onclick="mePorterCandidat('${escapeHtml(vacancy.poste)}')" ${currentUser && normalizeRole(currentUser.role) !== 'observateur' ? '' : 'disabled'}>
        Me porter candidat
      </button>
    </div>
  `;
}

function renderVoteCard(vote) {
  const total = Number(vote.pour || 0) + Number(vote.contre || 0);
  const pourPct = total ? Math.round((Number(vote.pour || 0) / total) * 100) : 0;
  const contrePct = total ? 100 - pourPct : 0;
  const closed = vote.statut !== 'ouvert';

  return `
    <div class="vote-card" data-vote-id="${vote.id}">
      <h3>${escapeHtml(vote.titre)}</h3>
      <p class="vote-budget">Budget estime : ${Number(vote.budget || 0).toLocaleString('fr-FR')} FCFA</p>
      ${closed ? `
        <div class="vote-barre">
          <div class="vote-pour" style="width: ${pourPct}%">${pourPct}% Pour</div>
          <div class="vote-contre" style="width: ${contrePct}%">${contrePct}%</div>
        </div>
        <p class="vote-info">${vote.pour || 0} votes pour · ${vote.contre || 0} votes contre · Statut : ${escapeHtml(vote.statut)}</p>
      ` : `
        <p class="vote-info">Ouvert jusqu'au ${formatDateTime(vote.expires_at)}. Resultat masque jusqu'a la cloture.</p>
      `}
      ${vote.statut === 'ouvert' ? `
        <div class="vote-actions">
          ${vote.type === 'election'
            ? renderElectionVoteButtons(vote)
            : `<button class="btn-pour" onclick="voter(${vote.id}, 'pour')">Voter Pour</button>
               <button class="btn-contre" onclick="voter(${vote.id}, 'contre')">Voter Contre</button>`}
        </div>
      ` : ''}
      <p class="vote-blockchain">Resultat ${closed ? 'publie' : 'en attente de cloture'}</p>
    </div>
  `;
}

function renderElectionVoteButtons(vote) {
  const vacancy = candidatures.find(item => item.id === vote.poste_vacant_id || item.poste === vote.poste);
  const candidates = vacancy?.candidats || [];

  if (!candidates.length) {
    return '<p class="vote-info">Aucun candidat disponible.</p>';
  }

  return candidates.map(candidate => `
    <button class="btn-pour" onclick="voter(${vote.id}, '${candidate.id}')">
      ${escapeHtml(candidate.nom || candidate.username)}
    </button>
  `).join('');
}

function renderCotisations() {
  const tbody = document.getElementById('cotisations-list');
  if (!tbody) return;

  if (!cotisations.length) {
    tbody.innerHTML = '<tr><td colspan="4">Aucune cotisation personnelle.</td></tr>';
  } else {
    tbody.innerHTML = cotisations.map(cotisation => `
      <tr>
        <td>${formatDate(cotisation.date)}</td>
        <td>${formatAbsoluteMontant(cotisation.montant)}</td>
        <td>${escapeHtml(cotisation.mode)}</td>
        <td>${escapeHtml(cotisation.statut)}</td>
      </tr>
    `).join('');
  }
}

function renderNotifications() {
  const list = document.getElementById('notifications-list');
  if (!list) return;

  if (!notifications.length) {
    list.innerHTML = '<p>Aucune notification pour le moment.</p>';
    return;
  }

  list.innerHTML = notifications.map(notification => `
    <div class="membres-stats">
      <strong>${escapeHtml(notification.type || 'notification')}</strong>
      <p>${escapeHtml(notification.message)}</p>
      <small>${formatDateTime(notification.created_at)}</small>
    </div>
  `).join('');
}

function renderDashboard() {
  const balance = transactions.reduce((total, transaction) => total + Number(transaction.montant || 0), 0);
  const currentMonth = new Date().toISOString().slice(0, 7);
  const monthlyTransactions = transactions.filter(transaction => String(transaction.date || '').slice(0, 7) === currentMonth);
  const monthlyCotisations = cotisations.filter(cotisation => String(cotisation.date || '').slice(0, 7) === currentMonth);
  const contributions = monthlyCotisations.reduce((total, cotisation) => total + Number(cotisation.montant || 0), 0);
  const expenses = monthlyTransactions
    .filter(transaction => Number(transaction.montant || 0) < 0)
    .reduce((total, transaction) => total + Number(transaction.montant || 0), 0);
  const openVotes = votes.filter(vote => vote.statut === 'ouvert').length;
  const closedVotes = votes.filter(vote => vote.statut !== 'ouvert').length;
  const activeMembers = members.filter(m => m.statut === 'Actif').length;

  document.getElementById('coop-balance').textContent = formatAbsoluteMontant(balance);
  document.getElementById('monthly-contributions').textContent = formatAbsoluteMontant(contributions);
  document.getElementById('monthly-expenses').textContent = formatAbsoluteMontant(Math.abs(expenses));
  document.getElementById('active-members-count').textContent = activeMembers;
  document.getElementById('open-votes-count').textContent = openVotes;
  document.getElementById('proof-count').textContent = transactions.length;
  document.getElementById('votes-proof-count').textContent = closedVotes;
  document.getElementById('proof-last').textContent = transactions.length > 0 ? formatDate(transactions[0].date) : '-';

  renderHealthScore();
}

function renderHealthScore() {
  const scoreNode = document.getElementById('financial-health-score');
  if (!scoreNode) return;

  if (!financialHealth) {
    scoreNode.textContent = '-';
    scoreNode.style.color = '#1B4F72';
    return;
  }

  const score = Number(financialHealth.score || 0);
  scoreNode.textContent = `${score}%`;

  if (score < 40) {
    scoreNode.style.color = '#C0392B';
  } else if (score <= 70) {
    scoreNode.style.color = '#D68910';
  } else {
    scoreNode.style.color = '#1E8449';
  }
}

function applyPermissions() {
  if (!currentUser) return;

  const permissions = currentUser.permissions;
  const setVisible = (id, visible) => {
    const element = document.getElementById(id);
    if (element) element.classList.toggle('hidden', !visible);
  };

  const newTransactionBtn = document.getElementById('new-transaction-btn');
  if (newTransactionBtn) newTransactionBtn.disabled = !permissions.canTransact;

  const proposalBtn = document.getElementById('proposal-btn');
  if (proposalBtn) proposalBtn.disabled = !permissions.canSuggest;

  const addMemberBtn = document.getElementById('add-member-btn');
  if (addMemberBtn) {
    addMemberBtn.disabled = !permissions.isAdmin;
    addMemberBtn.textContent = permissions.isAdmin ? 'Créer un membre' : '+ Ajouter une personne';
  }

  setVisible('manual-cotisation-form', permissions.canTransact);

  document.querySelectorAll('.btn-pour, .btn-contre').forEach(button => {
    button.disabled = !permissions.canVote;
  });
}

async function enregistrerTransaction() {
  if (!currentUser?.permissions.canTransact) {
    alert('Seul le Tresorier peut ajouter une transaction.');
    return;
  }

  const libelle = prompt('Libelle de la transaction :')?.trim();
  if (!libelle) return;

  const montant = lireMontant(prompt('Montant (FCFA) :'));
  if (montant === null) {
    alert('Le montant doit etre un entier non nul.');
    return;
  }

  const voteId = prompt('ID du vote valide associe :')?.trim();
  if (!voteId) return;

  const payload = { libelle, montant, vote_id: Number(voteId) };

  if (!navigator.onLine) {
    queuePendingTransaction(payload);
    alert('Connexion absente. Transaction ajoutee a la file d attente.');
    return;
  }

  await submitTransactionPayload(payload);
}

async function submitTransactionPayload(payload) {
  const data = await apiFetch('/api/transactions', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  transactions.unshift(data.transaction);
  renderTransactions();
  afficherRecu(data.transaction.id);
}

function queuePendingTransaction(payload) {
  const pending = getPendingTransactions();
  pending.push(payload);
  sessionStorage.setItem(PENDING_TRANSACTIONS_KEY, JSON.stringify(pending));
}

function getPendingTransactions() {
  try {
    return JSON.parse(sessionStorage.getItem(PENDING_TRANSACTIONS_KEY) || '[]');
  } catch (error) {
    return [];
  }
}

async function flushPendingTransactions() {
  if (!navigator.onLine || !getToken()) return;

  const pending = getPendingTransactions();
  if (!pending.length) return;

  const remaining = [];
  for (const payload of pending) {
    try {
      await submitTransactionPayload(payload);
    } catch (error) {
      remaining.push(payload);
    }
  }

  sessionStorage.setItem(PENDING_TRANSACTIONS_KEY, JSON.stringify(remaining));
  updateNetworkStatus();
}

function afficherRecu(id) {
  const transaction = transactions.find(item => String(item.id) === String(id));
  if (!transaction) return;

  document.getElementById('receipt-title').textContent = transaction.libelle;
  document.getElementById('receipt-date').textContent = formatDate(transaction.date);
  document.getElementById('receipt-amount').textContent = formatMontant(transaction.montant);
  document.getElementById('receipt-hash').textContent = transaction.hash || '-';
  document.getElementById('receipt-link').href = transaction.explorer || '#';
  document.getElementById('receipt-panel').classList.remove('hidden');
}

function fermerRecu() {
  document.getElementById('receipt-panel').classList.add('hidden');
}

async function suggererOperation() {
  if (!currentUser?.permissions.canSuggest) {
    alert('Seul le President peut suggerer une operation.');
    return;
  }

  const titre = prompt('Operation a soumettre au vote :')?.trim();
  if (!titre) return;

  const budget = lireMontant(prompt('Budget estime (FCFA) :'));
  if (budget === null || budget < 0) {
    alert('Le budget doit etre un entier positif.');
    return;
  }

  const duree = Number(prompt('Duree du vote en heures (minimum 72) :', '72') || 72);

  try {
    await apiFetch('/api/votes', {
      method: 'POST',
      body: JSON.stringify({ titre, budget, duree_heures: Math.max(duree, 72) }),
    });
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Creation du vote impossible.');
  }
}

async function voter(voteId, choix) {
  if (!currentUser?.permissions.canVote) {
    alert('Seuls les membres peuvent voter.');
    return;
  }

  try {
    await apiFetch(`/api/votes/${voteId}/vote`, {
      method: 'POST',
      body: JSON.stringify({ choix }),
    });
    alert('Vote enregistre.');
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Vote refuse.');
  }
}

async function attribuerRole(memberId) {
  if (!currentUser?.permissions.canManageMembers) return;

  const role = prompt('Nouveau role :')?.trim();
  if (!role) return;

  const voteId = prompt('ID du vote valide autorisant ce role :')?.trim();
  if (!voteId) return;

  try {
    await apiFetch(`/api/members/${memberId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role, vote_id: Number(voteId) }),
    });
    await chargerMembres();
  } catch (error) {
    alert(error.message || 'Attribution impossible.');
  }
}

async function ajouterMembre() {
  if (!currentUser?.permissions.isAdmin) {
    alert('Seul l admin peut creer directement un membre.');
    return;
  }

  showPage('setup-members');
}

async function configurerCoop(event) {
  event.preventDefault();

  try {
    const data = await apiFetch('/api/config/init', {
      method: 'POST',
      body: JSON.stringify({
        nom_coop: document.getElementById('setup-coop-name').value.trim(),
        duree_mandat: Number(document.getElementById('setup-mandate-duration').value),
      }),
    });
    document.getElementById('setup-unique-key').textContent = data.config.cle_unique;
    document.getElementById('setup-key-panel').classList.remove('hidden');
  } catch (error) {
    alert(error.message || 'Configuration impossible.');
  }
}

function copierCleUnique() {
  const key = document.getElementById('setup-unique-key').textContent;
  navigator.clipboard?.writeText(key);
}

async function creerMembreAdmin(event) {
  event.preventDefault();

  try {
    await apiFetch('/api/members/create', {
      method: 'POST',
      body: JSON.stringify({
        nom: document.getElementById('admin-member-name').value.trim(),
        username: document.getElementById('admin-member-username').value.trim(),
        email: document.getElementById('admin-member-email').value.trim(),
        password: document.getElementById('admin-member-password').value,
        role: document.getElementById('admin-member-role').value,
      }),
    });
    event.target.reset();
    await chargerMembres();
    alert('Membre ajoute.');
  } catch (error) {
    alert(error.message || 'Creation impossible.');
  }
}

function terminerInitialisation() {
  showPage('dashboard');
  loadProtectedData();
}

async function mePorterCandidat(poste) {
  try {
    await apiFetch('/api/candidatures', {
      method: 'POST',
      body: JSON.stringify({ poste }),
    });
    await chargerCandidatures();
    alert('Candidature enregistree.');
  } catch (error) {
    alert(error.message || 'Candidature refusee.');
  }
}

async function enregistrerCotisationManuelle(event) {
  event.preventDefault();

  if (!currentUser?.permissions.canTransact) {
    alert('Seul le Tresorier peut enregistrer une cotisation.');
    return;
  }

  try {
    await apiFetch('/api/cotisations', {
      method: 'POST',
      body: JSON.stringify({
        member_id: Number(document.getElementById('cotisation-member-id').value),
        montant: Number(document.getElementById('cotisation-montant').value),
        mode: document.getElementById('cotisation-mode').value.trim(),
      }),
    });
    event.target.reset();
    await chargerCotisations();
  } catch (error) {
    alert(error.message || 'Cotisation refusee.');
  }
}

async function initierPaiementFedapay(event) {
  if (event?.preventDefault) event.preventDefault();
  const amount = Number(document.getElementById('fedapay-amount')?.value || 0);

  if (!Number.isInteger(amount) || amount <= 0) {
    alert('Le montant doit être un entier positif.');
    return;
  }

  try {
    const data = await apiFetch('/api/fedapay/initier', {
      method: 'POST',
      body: JSON.stringify({ montant: amount }),
    });

    const widget = window.FedapayCheckout || window.FedaPayCheckout || window.FedaPay || window.fedapay;
    if (!widget) {
      throw new Error('Widget FedaPay indisponible.');
    }

    const openWidget = widget.open || widget.init;
    if (typeof openWidget !== 'function') {
      throw new Error('Widget FedaPay invalide.');
    }

    openWidget.call(widget, {
      token: data.token,
      public_key: 'pk_sandbox_4OdnCn5ourE2X53kWoJDlymC',
      onComplete: () => {
        alert('Paiement FedaPay terminé. Merci !');
        chargerCotisations();
      },
      onError: (error) => {
        console.error('FedaPay erreur', error);
        alert(error?.message || 'Erreur lors du paiement FedaPay.');
      },
    });
  } catch (error) {
    alert(error.message || 'Impossible de lancer le paiement FedaPay.');
  }
}

function startNotificationsStream() {
  stopNotificationsStream();

  if (!getToken()) return;

  sseAbortController = new AbortController();

  fetch('/api/notifications/stream', {
    headers: { Authorization: `Bearer ${getToken()}` },
    signal: sseAbortController.signal,
  })
    .then(async response => {
      if (response.status === 401) {
        handleAuthExpired();
        return;
      }

      if (!response.ok || !response.body) {
        throw new Error('Flux SSE indisponible.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split('\n\n');
        buffer = events.pop();

        events.forEach(parseSseEvent);
      }
    })
    .catch(error => {
      if (error.name !== 'AbortError') scheduleSseReconnect();
    });
}

function parseSseEvent(eventText) {
  const line = eventText.split('\n').find(item => item.startsWith('data: '));
  if (!line) return;

  try {
    const notification = JSON.parse(line.slice(6));
    notifications.unshift(notification);
    renderNotifications();
    refreshDataAfterNotification(notification);
  } catch (error) {
    console.error(error);
  }
}

function refreshDataAfterNotification(notification) {
  if (notification.type === 'transaction') chargerTransactions();
  if (notification.type === 'vote') chargerVotes();
  if (notification.type === 'membre') chargerMembres();
  if (notification.type === 'cotisation') chargerCotisations();
}

function scheduleSseReconnect() {
  clearTimeout(sseReconnectTimer);
  sseReconnectTimer = setTimeout(startNotificationsStream, 3000);
}

function stopNotificationsStream() {
  clearTimeout(sseReconnectTimer);
  if (sseAbortController) {
    sseAbortController.abort();
    sseAbortController = null;
  }
}

function updateNetworkStatus() {
  const status = document.getElementById('network-status');
  if (!status) return;

  const pending = getPendingTransactions().length;
  status.textContent = navigator.onLine
    ? `En ligne${pending ? ` · ${pending} transaction(s) en attente` : ''}`
    : `Hors ligne · ${pending} transaction(s) en attente`;
}

function lancerDemo() {
  alert('La demo locale a ete remplacee par les donnees reelles de l API.');
}

function etapeDemoSuivante() {}

function arreterDemo() {
  document.getElementById('demo-guide')?.classList.add('hidden');
}

window.showPage = showPage;
window.deconnecter = deconnecter;
window.enregistrerProfil = enregistrerProfil;
window.enregistrerTransaction = enregistrerTransaction;
window.afficherRecu = afficherRecu;
window.fermerRecu = fermerRecu;
window.suggererOperation = suggererOperation;
window.voter = voter;
window.attribuerRole = attribuerRole;
window.ajouterMembre = ajouterMembre;
window.configurerCoop = configurerCoop;
window.copierCleUnique = copierCleUnique;
window.creerMembreAdmin = creerMembreAdmin;
window.terminerInitialisation = terminerInitialisation;
window.mePorterCandidat = mePorterCandidat;
window.enregistrerCotisationManuelle = enregistrerCotisationManuelle;
window.initierPaiementFedapay = initierPaiementFedapay;
window.lancerDemo = lancerDemo;
window.etapeDemoSuivante = etapeDemoSuivante;
window.arreterDemo = arreterDemo;

document.addEventListener('DOMContentLoaded', () => {
  installDynamicInterface();
  updateNetworkStatus();

  window.addEventListener('online', () => {
    updateNetworkStatus();
    flushPendingTransactions();
    startNotificationsStream();
  });

  window.addEventListener('offline', updateNetworkStatus);

  const token = getToken();
  if (token) {
    openSessionFromToken(token);
  }
});
