let transactions = [];
let members = [];
let votes = [];
let cotisations = [];
let notifications = [];
let candidatures = [];
/** @type {Array<Record<string, unknown>>} */
let actionsVotees = [];
let currentUser = null;
let financialHealth = null;
let coopConfig = null;
let sseAbortController = null;
let sseReconnectTimer = null;
let initialSetupKey = null;
let paiementRetourAwaitingSse = false;
let paiementRetourRedirectTimer = null;
let demoSessionTimer = null;

const TOKEN_KEY = 'token';
const PENDING_TRANSACTIONS_KEY = 'pendingTransactions';
const THEME_STORAGE_KEY = 'cl_theme';
const LANG_STORAGE_KEY = 'cl_lang';
const PUSH_PREF_STORAGE_KEY = 'cl_push_enabled';

/** Page ids used in showPage() that sync with URL hash (sidebar + dashboard). */
const HASH_ROUTABLE_PAGES = new Set([
  'dashboard',
  'transactions',
  'vote',
  'membres',
  'cotisations',
  'notifications',
  'configuration',
]);

function parseShellRouteFromHash() {
  const raw = String(window.location.hash || '').replace(/^#/, '').trim();
  if (!raw) return null;
  return HASH_ROUTABLE_PAGES.has(raw) ? raw : null;
}

function getActiveShellPageId() {
  const active = document.querySelector('.page.active');
  if (!active?.id || !active.id.startsWith('page-')) return null;
  return active.id.slice('page-'.length);
}

function isPaiementRetourShellRoute() {
  if (window.location.hash === '#paiement-retour') return true;
  const path = String(window.location.pathname || '').replace(/\/$/, '') || '/';
  if (path !== '/paiement-retour') return false;
  const h = String(window.location.hash || '');
  if (h && h !== '#paiement-retour') return false;
  return true;
}

function resetPaiementRetourViewDom() {
  const progress = document.getElementById('paiement-retour-progress');
  const success = document.getElementById('paiement-retour-success');
  progress?.classList.remove('hidden');
  success?.classList.add('hidden');
}

function showPaiementRetourView() {
  const root = document.getElementById('paiement-retour-view');
  if (!root) return;
  clearTimeout(paiementRetourRedirectTimer);
  paiementRetourRedirectTimer = null;
  paiementRetourAwaitingSse = true;
  resetPaiementRetourViewDom();
  root.classList.remove('hidden');
}

function hidePaiementRetourView() {
  const root = document.getElementById('paiement-retour-view');
  if (!root) return;
  clearTimeout(paiementRetourRedirectTimer);
  paiementRetourRedirectTimer = null;
  paiementRetourAwaitingSse = false;
  root.classList.add('hidden');
  resetPaiementRetourViewDom();
}

function onPaiementRetourCotisationNotification(notification) {
  if (!paiementRetourAwaitingSse) return;
  if (notification.type !== 'cotisation' && notification.type !== 'paiement_confirme') return;

  paiementRetourAwaitingSse = false;
  document.getElementById('paiement-retour-progress')?.classList.add('hidden');
  document.getElementById('paiement-retour-success')?.classList.remove('hidden');

  paiementRetourRedirectTimer = setTimeout(() => {
    paiementRetourRedirectTimer = null;
    hidePaiementRetourView();
    window.location.href = `${window.location.origin}/#cotisations`;
  }, 3000);
}

/** @type {MediaQueryList|null} */
let systemLightMql = null;

const I18N = {
  fr: {
    'shell.sessionLabel': 'Session active',
    'shell.switchProfile': 'Changer de profil',
    'nav.dashboard': '📊 Dashboard',
    'nav.transactions': '📋 Transactions',
    'nav.vote': '🗳️ Vote',
    'nav.members': '👥 Membres',
    'nav.cotisations': '💰 Cotisations',
    'nav.notifications': '🔔 Notifications',
    'nav.configuration': '⚙️ Configuration',
    'auth.heroTitle': 'Connexion coopérative',
    'auth.heroSubtitle': 'Identifiez-vous ou enregistrez-vous pour ouvrir une interface adaptée à votre rôle.',
    'auth.loginPanel': 'Connexion',
    'auth.launchDemo': 'Lancer la démo',
    'auth.registerPanel': 'Nouvel accès membre',
    'page.dashboard.title': 'Dashboard',
    'page.dashboard.balanceLabel': 'Solde actuel de la coopérative',
    'page.dashboard.stellar': '🔗 Enregistré sur Stellar Testnet',
    'page.dashboard.statContrib': 'Cotisations ce mois',
    'page.dashboard.statExpenses': 'Dépenses ce mois',
    'page.dashboard.statMembers': 'Membres actifs',
    'page.dashboard.statVotes': 'Votes en cours',
    'page.dashboard.healthLabel': 'Score de santé',
    'page.dashboard.proofTx': 'transactions enregistrées',
    'page.dashboard.proofVotes': 'votes fermés',
    'page.dashboard.proofLast': 'dernière mise à jour',
    'page.transactions.title': 'Historique des Transactions',
    'page.transactions.new': '+ Nouvelle Transaction',
    'page.vote.title': 'Votes en cours',
    'page.vote.suggest': '+ Suggérer une opération',
    'page.members.add': '+ Ajouter une personne',
    'page.members.registeredSuffix': 'personnes enregistrées',
    'page.members.titleWithCoop': 'Membres — {{coop}}',
    'page.members.titleShort': 'Membres',
    'common.close': 'Fermer',
    'a11y.openMenu': 'Ouvrir le menu',
    'a11y.closeMenu': 'Fermer le menu',
    'settings.title': 'Paramètres',
    'settings.sectionTheme': 'Thème',
    'settings.themeLabel': 'Apparence',
    'settings.themeLight': 'Clair',
    'settings.themeDark': 'Sombre',
    'settings.themeSystem': 'Système',
    'settings.sectionLang': 'Langue',
    'settings.langLabel': 'Langue d’affichage',
    'settings.sectionPush': 'Notifications',
    'settings.pushLabel': 'Notifications Web Push',
    'settings.pushHint': 'Activez pour recevoir des alertes sur cet appareil.',
    'settings.sectionSystem': 'Informations système',
    'settings.sysInstance': 'Clé d’instance',
    'settings.sysCoopName': 'Nom de la coopérative',
    'settings.sysMandate': 'Durée du mandat',
    'settings.sysInactivity': 'Inactivité (mois)',
    'settings.na': '—',
    'settings.restricted': 'Réservé aux administrateurs',
    'settings.monthsSuffix': ' mois',
    'settings.openTitle': 'Paramètres',
    'auth.labelUsername': 'Identifiant',
    'auth.labelPassword': 'Mot de passe',
    'auth.rememberLogin': 'Rester connecté',
    'auth.submitLogin': 'Se connecter',
    'auth.labelFullName': 'Nom complet',
    'auth.labelEmail': 'Email',
    'auth.observerOnly': 'Je souhaite m’inscrire comme Observateur uniquement',
    'auth.submitRegister': 'Créer le compte et entrer',
  },
  en: {
    'shell.sessionLabel': 'Active session',
    'shell.switchProfile': 'Switch profile',
    'nav.dashboard': '📊 Dashboard',
    'nav.transactions': '📋 Transactions',
    'nav.vote': '🗳️ Vote',
    'nav.members': '👥 Members',
    'nav.cotisations': '💰 Contributions',
    'nav.notifications': '🔔 Notifications',
    'nav.configuration': '⚙️ Settings',
    'auth.heroTitle': 'Cooperative login',
    'auth.heroSubtitle': 'Sign in or register for an interface tailored to your role.',
    'auth.loginPanel': 'Sign in',
    'auth.launchDemo': 'Launch demo',
    'auth.registerPanel': 'New member access',
    'page.dashboard.title': 'Dashboard',
    'page.dashboard.balanceLabel': 'Current cooperative balance',
    'page.dashboard.stellar': '🔗 Recorded on Stellar Testnet',
    'page.dashboard.statContrib': 'Contributions this month',
    'page.dashboard.statExpenses': 'Expenses this month',
    'page.dashboard.statMembers': 'Active members',
    'page.dashboard.statVotes': 'Open votes',
    'page.dashboard.healthLabel': 'Health score',
    'page.dashboard.proofTx': 'recorded transactions',
    'page.dashboard.proofVotes': 'closed votes',
    'page.dashboard.proofLast': 'last update',
    'page.transactions.title': 'Transaction history',
    'page.transactions.new': '+ New transaction',
    'page.vote.title': 'Open votes',
    'page.vote.suggest': '+ Suggest an operation',
    'page.members.add': '+ Add a person',
    'page.members.registeredSuffix': 'people registered',
    'page.members.titleWithCoop': 'Members — {{coop}}',
    'page.members.titleShort': 'Members',
    'common.close': 'Close',
    'a11y.openMenu': 'Open menu',
    'a11y.closeMenu': 'Close menu',
    'settings.title': 'Settings',
    'settings.sectionTheme': 'Theme',
    'settings.themeLabel': 'Appearance',
    'settings.themeLight': 'Light',
    'settings.themeDark': 'Dark',
    'settings.themeSystem': 'System',
    'settings.sectionLang': 'Language',
    'settings.langLabel': 'Display language',
    'settings.sectionPush': 'Notifications',
    'settings.pushLabel': 'Web push notifications',
    'settings.pushHint': 'Turn on to receive alerts on this device.',
    'settings.sectionSystem': 'System information',
    'settings.sysInstance': 'Instance key',
    'settings.sysCoopName': 'Cooperative name',
    'settings.sysMandate': 'Mandate duration',
    'settings.sysInactivity': 'Inactivity (months)',
    'settings.na': '—',
    'settings.restricted': 'Administrators only',
    'settings.monthsSuffix': ' months',
    'settings.openTitle': 'Settings',
    'auth.labelUsername': 'Username',
    'auth.labelPassword': 'Password',
    'auth.rememberLogin': 'Stay signed in',
    'auth.submitLogin': 'Sign in',
    'auth.labelFullName': 'Full name',
    'auth.labelEmail': 'Email',
    'auth.observerOnly': 'I want to register as Observer only',
    'auth.submitRegister': 'Create account and enter',
  },
};

function getUiLang() {
  return localStorage.getItem(LANG_STORAGE_KEY) === 'en' ? 'en' : 'fr';
}

function t(key, vars) {
  const lang = getUiLang();
  let s = I18N[lang]?.[key] ?? I18N.fr[key] ?? key;
  if (vars && typeof s === 'string') {
    Object.entries(vars).forEach(([k, v]) => {
      s = s.split(`{{${k}}}`).join(String(v));
    });
  }
  return s;
}

function applyDocumentI18n() {
  document.documentElement.lang = getUiLang();
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const k = el.getAttribute('data-i18n');
    if (k) el.textContent = t(k);
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
    const k = el.getAttribute('data-i18n-aria-label');
    if (k) el.setAttribute('aria-label', t(k));
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const k = el.getAttribute('data-i18n-title');
    if (k) el.setAttribute('title', t(k));
  });
  const toggle = document.getElementById('sidebar-toggle');
  if (toggle && document.body.classList.contains('sidebar-open')) {
    const ck = toggle.getAttribute('data-i18n-aria-close');
    if (ck) toggle.setAttribute('aria-label', t(ck));
  } else if (toggle) {
    const ok = toggle.getAttribute('data-i18n-aria-open');
    if (ok) toggle.setAttribute('aria-label', t(ok));
  }
}

function resolveStoredTheme() {
  const raw = localStorage.getItem(THEME_STORAGE_KEY) || 'system';
  if (raw === 'light') return 'light';
  if (raw === 'dark') return 'dark';
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function applyResolvedTheme(resolved) {
  document.documentElement.setAttribute('data-theme', resolved);
}

function syncThemeFromStorage() {
  applyResolvedTheme(resolveStoredTheme());
}

function installThemeMediaListener() {
  if (!window.matchMedia) return;
  systemLightMql = window.matchMedia('(prefers-color-scheme: light)');
  const onChange = () => {
    if ((localStorage.getItem(THEME_STORAGE_KEY) || 'system') === 'system') {
      syncThemeFromStorage();
    }
  };
  if (typeof systemLightMql.addEventListener === 'function') {
    systemLightMql.addEventListener('change', onChange);
  } else if (typeof systemLightMql.addListener === 'function') {
    systemLightMql.addListener(onChange);
  }
}

function isAppAdmin() {
  return normalizeRole(currentUser?.role) === 'admin';
}

async function unsubscribeFromWebPush() {
  if (isDemoSession()) {
    return;
  }
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      return;
    }
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (!sub) {
      return;
    }
    const endpoint = sub.endpoint;
    await sub.unsubscribe();
    await apiFetch('/api/push/unsubscribe', {
      method: 'POST',
      body: JSON.stringify({ endpoint }),
    });
  } catch (_) {
    /* optional */
  }
}

function getPushPreferenceEnabled() {
  return localStorage.getItem(PUSH_PREF_STORAGE_KEY) !== 'false';
}

async function loadSettingsSystemInfo() {
  const na = t('settings.na');
  const restricted = t('settings.restricted');
  const keyEl = document.getElementById('settings-sys-key');
  const nomEl = document.getElementById('settings-sys-nom');
  const mandEl = document.getElementById('settings-sys-mandat');
  const inactEl = document.getElementById('settings-sys-inact');
  if (!keyEl || !nomEl || !mandEl || !inactEl) return;
  keyEl.textContent = na;
  nomEl.textContent = na;
  mandEl.textContent = na;
  inactEl.textContent = na;
  if (!currentUser) {
    return;
  }
  try {
    if (isAppAdmin()) {
      const full = await apiFetch('/api/config/all');
      const cfg = full.config || {};
      keyEl.textContent = cfg.cle_unique_masked || na;
      nomEl.textContent = cfg.nom_coop || na;
      mandEl.textContent = cfg.duree_mandat != null && String(cfg.duree_mandat) !== ''
        ? `${cfg.duree_mandat}${t('settings.monthsSuffix')}`
        : na;
      inactEl.textContent = cfg.duree_inactivite_mois != null && String(cfg.duree_inactivite_mois) !== ''
        ? String(cfg.duree_inactivite_mois)
        : na;
    } else {
      const data = await apiFetch('/api/config');
      keyEl.textContent = restricted;
      nomEl.textContent = data.nom_coop || na;
      mandEl.textContent = restricted;
      inactEl.textContent = restricted;
    }
  } catch (_) {
    keyEl.textContent = na;
    nomEl.textContent = na;
    mandEl.textContent = na;
    inactEl.textContent = na;
  }
}

function openSettingsPanel() {
  const panel = document.getElementById('settings-panel');
  const backdrop = document.getElementById('settings-backdrop');
  const btn = document.getElementById('settings-open-btn');
  if (!panel || !backdrop) return;
  const themeSel = document.getElementById('settings-theme');
  const langSel = document.getElementById('settings-lang');
  const pushEl = document.getElementById('settings-push-toggle');
  if (themeSel) themeSel.value = localStorage.getItem(THEME_STORAGE_KEY) || 'system';
  if (langSel) langSel.value = getUiLang();
  if (pushEl) pushEl.checked = getPushPreferenceEnabled();
  applyDocumentI18n();
  backdrop.classList.add('is-open');
  panel.classList.add('is-open');
  backdrop.setAttribute('aria-hidden', 'false');
  panel.setAttribute('aria-hidden', 'false');
  if (btn) btn.setAttribute('aria-expanded', 'true');
  loadSettingsSystemInfo();
}

function closeSettingsPanel() {
  const panel = document.getElementById('settings-panel');
  const backdrop = document.getElementById('settings-backdrop');
  const btn = document.getElementById('settings-open-btn');
  backdrop?.classList.remove('is-open');
  panel?.classList.remove('is-open');
  backdrop?.setAttribute('aria-hidden', 'true');
  panel?.setAttribute('aria-hidden', 'true');
  if (btn) btn.setAttribute('aria-expanded', 'false');
}

function installSettingsPanel() {
  const openBtn = document.getElementById('settings-open-btn');
  const closeBtn = document.getElementById('settings-close-btn');
  const backdrop = document.getElementById('settings-backdrop');
  const themeSel = document.getElementById('settings-theme');
  const langSel = document.getElementById('settings-lang');
  const pushToggle = document.getElementById('settings-push-toggle');
  if (!openBtn || openBtn.dataset.bound === '1') return;
  openBtn.dataset.bound = '1';
  openBtn.addEventListener('click', () => openSettingsPanel());
  closeBtn?.addEventListener('click', () => closeSettingsPanel());
  backdrop?.addEventListener('click', () => closeSettingsPanel());
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && document.getElementById('settings-panel')?.classList.contains('is-open')) {
      closeSettingsPanel();
    }
  });
  themeSel?.addEventListener('change', () => {
    const v = themeSel.value;
    localStorage.setItem(THEME_STORAGE_KEY, v);
    syncThemeFromStorage();
  });
  langSel?.addEventListener('change', () => {
    localStorage.setItem(LANG_STORAGE_KEY, langSel.value);
    applyDocumentI18n();
    renderAuthForms();
    if (document.getElementById('settings-panel')?.classList.contains('is-open')) {
      loadSettingsSystemInfo();
    }
  });
  pushToggle?.addEventListener('change', async () => {
    if (pushToggle.checked) {
      localStorage.setItem(PUSH_PREF_STORAGE_KEY, 'true');
      await subscribeToWebPush();
    } else {
      localStorage.setItem(PUSH_PREF_STORAGE_KEY, 'false');
      await unsubscribeFromWebPush();
    }
  });
}

const ROLE_PERMISSIONS = {
  createTransaction: ['tresorier'],
  createVote: ['president'],
  createMembre: ['admin', 'secretaire'],
  updateMembreStatut: ['admin', 'secretaire'],
  updateMembreRole: ['admin', 'secretaire'],
  signalerTransaction: ['verificateur'],
  enregistrerCotisation: ['tresorier'],
  genererRapport: ['admin', 'president', 'tresorier', 'verificateur'],
  adminActions: ['admin'],
};

/** @type {ReturnType<typeof setTimeout>|null} */
let appToastTimer = null;

function checkPermission(action, userRole) {
  const allowed = ROLE_PERMISSIONS[action];
  if (!allowed || !allowed.length) {
    return false;
  }
  const r = normalizeRole(userRole);
  return allowed.some((role) => {
    const a = normalizeRole(role);
    if (r === a) return true;
    if (a === 'tresorier' && r === 'tresoriere') return true;
    return false;
  });
}

function showPermissionError(action, userRole) {
  const allowed = ROLE_PERMISSIONS[action] || [];
  const rolesText = allowed.map((role) => String(role)).join(', ');
  const displayRole = userRole != null && String(userRole).trim() !== ''
    ? String(userRole)
    : String(currentUser?.role ?? '—');
  const msg = `Cette action est réservée au(x) rôle(s) : ${rolesText}. Votre rôle actuel est ${displayRole}.`;
  showAppToast(msg);
}

function showAppToast(message) {
  let el = document.getElementById('app-toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'app-toast';
    el.className = 'demo-mode-banner';
    el.setAttribute('role', 'alert');
    el.style.whiteSpace = 'normal';
    el.style.lineHeight = '1.4';
    el.style.fontWeight = '600';
    el.style.letterSpacing = '0.02em';
    el.style.cursor = 'pointer';
    el.title = 'Cliquer pour fermer';
    el.addEventListener('click', () => el.classList.add('hidden'));
    const main = document.querySelector('.main-content');
    const anchor = document.getElementById('demo-mode-banner');
    if (main) {
      if (anchor && anchor.parentNode === main) {
        anchor.insertAdjacentElement('afterend', el);
      } else {
        main.insertBefore(el, main.firstChild);
      }
    } else {
      document.body.appendChild(el);
    }
  }
  el.textContent = message;
  el.classList.remove('hidden');
  if (appToastTimer) clearTimeout(appToastTimer);
  appToastTimer = setTimeout(() => el.classList.add('hidden'), 9000);
}

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
  if (demoSessionTimer) {
    clearTimeout(demoSessionTimer);
    demoSessionTimer = null;
  }
  document.getElementById('demo-mode-banner')?.classList.add('hidden');
}

function isDemoSession() {
  return Boolean(currentUser && normalizeRole(currentUser.role) === 'demo');
}

function syncDemoBanner() {
  const banner = document.getElementById('demo-mode-banner');
  if (!banner) return;
  banner.classList.toggle('hidden', !isDemoSession());
}

function urlBase64ToUint8Array(base64String) {
  const raw = String(base64String || '').trim();
  const padding = '='.repeat((4 - (raw.length % 4)) % 4);
  const base64 = (raw + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i += 1) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

async function subscribeToWebPush() {
  if (isDemoSession()) {
    return;
  }
  try {
    if (!('Notification' in window) || !('serviceWorker' in navigator) || !('PushManager' in window)) {
      return;
    }
    const res = await fetch('/api/push/public-key');
    const data = await res.json().catch(() => ({}));
    const key = String(data.public_key || '').trim();
    if (!key) {
      return;
    }
    let perm = Notification.permission;
    if (perm === 'default') {
      perm = await Notification.requestPermission();
    }
    if (perm !== 'granted') {
      return;
    }
    const reg = await navigator.serviceWorker.ready;
    const subscription = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(key),
    });
    const payload = subscription.toJSON ? subscription.toJSON() : subscription;
    await apiFetch('/api/push/subscribe', {
      method: 'POST',
      body: JSON.stringify({ subscription: payload }),
    });
  } catch (_) {
    /* Notifications push facultatives */
  }
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

function filterNotificationsForCurrentUser(notifs) {
  if (!currentUser) return [];
  const userNorm = normalizeRole(currentUser.role);
  if (userNorm === 'admin') return [...(notifs || [])];

  return (notifs || []).filter((n) => {
    const raw = String(n.destinataires ?? 'tous')
      .trim()
      .toLowerCase();
    if (raw === 'tous' || raw === '') return true;
    const parts = raw
      .split(',')
      .map((s) => normalizeRole(s.trim()))
      .filter(Boolean);
    return parts.includes(userNorm);
  });
}

function getPermissions(role) {
  const normalized = normalizeRole(role);

  if (normalized === 'demo') {
    return {
      canSuggest: false,
      canTransact: false,
      canVote: false,
      canManageMembers: false,
      canSecretaryFlows: false,
      canAssignRoleDropdown: false,
      canResetPassword: false,
      canProlongVotes: false,
      canProposeConfigVote: false,
      canEditCoopConfig: false,
      isPresident: false,
      canVerify: false,
      canViewReport: true,
      isAdmin: false,
      isDemo: true,
    };
  }

  const isAdmin = normalized === 'admin';
  const isSecretary = normalized === 'secretaire';

  return {
    canSuggest: normalized === 'president',
    canTransact: normalized === 'tresorier' || normalized === 'tresoriere',
    canVote: normalized === 'membre',
    canManageMembers: ['admin', 'secretaire'].includes(normalized),
    canSecretaryFlows: isSecretary,
    canAssignRoleDropdown: isAdmin,
    canResetPassword: isAdmin,
    canProlongVotes: isAdmin,
    canProposeConfigVote: normalized === 'president',
    canEditCoopConfig: isAdmin,
    isPresident: normalized === 'president',
    canVerify: normalized === 'verificateur',
    canViewReport: ['president', 'tresorier', 'tresoriere', 'verificateur'].includes(normalized),
    isAdmin,
    isDemo: false,
  };
}

function getProfileDescription(role) {
  const permissions = getPermissions(role);

  if (permissions.isDemo) return 'Session de démonstration : données fictives, sans effet sur la coopérative réelle.';

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
  hidePaiementRetourView();
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

  if (demoSessionTimer) {
    clearTimeout(demoSessionTimer);
    demoSessionTimer = null;
  }

  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app-shell').classList.remove('hidden');
  closeMobileSidebar();
  document.getElementById('profile-name').textContent = currentUser.nom;
  document.getElementById('profile-role').textContent = currentUser.role;
  document.getElementById('profile-description').textContent = getProfileDescription(currentUser.role);

  syncDemoBanner();

  if (normalizeRole(decoded.role) === 'demo' && decoded.exp) {
    const ms = decoded.exp * 1000 - Date.now();
    if (ms > 0) {
      demoSessionTimer = setTimeout(() => {
        alert('La session de démonstration a expiré.');
        handleAuthExpired();
      }, ms);
    } else {
      handleAuthExpired();
      return;
    }
  }

  applyPermissions();
  startAfterLogin();
  startNotificationsStream();
  if (getPushPreferenceEnabled()) {
    subscribeToWebPush();
  }
}

async function startAfterLogin() {
  if (normalizeRole(currentUser?.role) === 'admin') {
    const config = await apiFetch('/api/config');
    if (!config.nom_coop) {
      showPage('setup-config');
      return;
    }
  }

  if (isPaiementRetourShellRoute()) {
    showPaiementRetourView();
    loadProtectedData();
    return;
  }

  const initialPage = parseShellRouteFromHash() || 'dashboard';
  showPage(initialPage);
  loadProtectedData();
}

/**
 * @param {string} pageId
 * @param {Element|null} [navTarget]
 * @param {{ updateHash?: boolean }} [options]
 */
function showPage(pageId, navTarget, options = {}) {
  document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

  const page = document.getElementById(`page-${pageId}`);
  if (page) page.classList.add('active');

  const activeNav = navTarget || document.querySelector(`.nav-item[data-page="${pageId}"]`) || document.querySelector(`.nav-item[onclick*="${pageId}"]`);
  if (activeNav) activeNav.classList.add('active');

  onPageShown(pageId);
  closeMobileSidebar();

  const updateHash = options.updateHash !== false;
  if (updateHash && HASH_ROUTABLE_PAGES.has(pageId)) {
    const target = `#${pageId}`;
    if (window.location.hash !== target) {
      window.location.hash = pageId;
    }
  }
}

function onPageShown(pageId) {
  if (pageId === 'setup-members') {
    chargerMembres().then(renderSetupMembersList).catch(() => {});
    const inlinePanel = document.getElementById('setup-key-inline');
    const inlineKey = document.getElementById('setup-unique-key-inline');
    if (inlineKey && initialSetupKey) inlineKey.textContent = initialSetupKey;
    if (inlinePanel) inlinePanel.classList.toggle('hidden', !initialSetupKey);
  }
  if (pageId === 'notifications') {
    chargerNotificationsHistorique();
  }
  if (pageId === 'configuration') {
    chargerConfigAdmin();
  }
  if (pageId === 'transactions') {
    document.getElementById('tx-filters')?.classList.toggle('hidden', isDemoSession());
  }
}

const MOBILE_SIDEBAR_MQ = window.matchMedia('(max-width: 768px)');

function closeMobileSidebar() {
  document.body.classList.remove('sidebar-open');
  document.getElementById('app-shell')?.classList.remove('sidebar-open');
  const toggle = document.getElementById('sidebar-toggle');
  if (toggle) {
    toggle.setAttribute('aria-expanded', 'false');
    const ok = toggle.getAttribute('data-i18n-aria-open');
    toggle.setAttribute('aria-label', ok ? t(ok) : 'Ouvrir le menu');
  }
}

function openMobileSidebar() {
  if (!MOBILE_SIDEBAR_MQ.matches) return;
  document.body.classList.add('sidebar-open');
  document.getElementById('app-shell')?.classList.add('sidebar-open');
  const toggle = document.getElementById('sidebar-toggle');
  if (toggle) {
    toggle.setAttribute('aria-expanded', 'true');
    const ck = toggle.getAttribute('data-i18n-aria-close');
    toggle.setAttribute('aria-label', ck ? t(ck) : 'Fermer le menu');
  }
}

function toggleMobileSidebar() {
  if (!MOBILE_SIDEBAR_MQ.matches) return;
  if (document.body.classList.contains('sidebar-open')) closeMobileSidebar();
  else openMobileSidebar();
}

function onMobileSidebarMqChange() {
  if (!MOBILE_SIDEBAR_MQ.matches) closeMobileSidebar();
}

function installShellHashRouting() {
  const syncFromHash = () => {
    if (document.getElementById('auth-screen') && !document.getElementById('auth-screen').classList.contains('hidden')) {
      return;
    }
    if (isPaiementRetourShellRoute()) {
      showPaiementRetourView();
      return;
    }
    hidePaiementRetourView();
    const id = parseShellRouteFromHash() || 'dashboard';
    if (getActiveShellPageId() === id) return;
    showPage(id, null, { updateHash: false });
  };
  window.addEventListener('hashchange', syncFromHash);
  window.addEventListener('popstate', syncFromHash);
}

function installMobileShellNav() {
  const toggle = document.getElementById('sidebar-toggle');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (!toggle || toggle.dataset.bound === '1') return;
  toggle.dataset.bound = '1';
  toggle.addEventListener('click', () => toggleMobileSidebar());
  backdrop?.addEventListener('click', () => closeMobileSidebar());
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && document.body.classList.contains('sidebar-open')) {
      closeMobileSidebar();
    }
  });
  if (typeof MOBILE_SIDEBAR_MQ.addEventListener === 'function') {
    MOBILE_SIDEBAR_MQ.addEventListener('change', onMobileSidebarMqChange);
  } else if (typeof MOBILE_SIDEBAR_MQ.addListener === 'function') {
    MOBILE_SIDEBAR_MQ.addListener(onMobileSidebarMqChange);
  }
}

function installDynamicInterface() {
  renderAuthForms();
  installExtraNavItems();
  installCotisationsPage();
  installNotificationsPage();
  installStartupPages();
  installConfigurationPage();
  installVotePageSections();
  installTransactionForm();
  markDashboardNodes();
}

function installTransactionForm() {
  const page = document.getElementById('page-transactions');
  if (!page || document.getElementById('transaction-form')) return;

  const header = page.querySelector('.page-header');
  if (!header) return;

  header.insertAdjacentHTML('afterend', `
    <form id="transaction-form" class="login-panel hidden" onsubmit="soumettreFluxFinancier(event)">
      <p class="panel-label">Mouvement financier</p>
      <label for="txn-flow-type">Type d'opération</label>
      <select id="txn-flow-type" required onchange="majChampsFluxFinancier()">
        <option value="">— Choisir —</option>
        <option value="recette">Recette</option>
        <option value="depense">Dépense</option>
        <option value="cotisation_manuelle">Cotisation manuelle</option>
      </select>
      <div id="txn-recette-depense-block" class="hidden">
        <label for="transaction-libelle">Libellé</label>
        <input id="transaction-libelle" type="text">
        <label for="transaction-montant">Montant (FCFA, entier positif)</label>
        <input id="transaction-montant" type="number" min="1" step="1">
        <label for="transaction-vote-select">Vote validé associé</label>
        <select id="transaction-vote-select"></select>
      </div>
      <div id="txn-cotisation-block" class="hidden">
        <label for="txn-cot-member">Membre</label>
        <select id="txn-cot-member"></select>
        <label for="txn-cot-montant">Montant</label>
        <input id="txn-cot-montant" type="number" min="1" step="1">
        <label for="txn-cot-mode">Mode</label>
        <select id="txn-cot-mode">
          <option value="Cash">Cash</option>
          <option value="Mobile Money">Mobile Money</option>
        </select>
      </div>
      <button class="btn-primary" type="submit">Enregistrer et sceller</button>
    </form>
  `);
}

function renderAuthForms() {
  const container = document.getElementById('existing-profiles');
  const registerForm = document.querySelector('#auth-screen form');

  if (container) {
    container.innerHTML = `
      <form id="login-form" class="login-form">
        <label for="login-username">${t('auth.labelUsername')}</label>
        <input id="login-username" type="text" placeholder="komi_adjoka" autocomplete="username" required>
        <label for="login-password">${t('auth.labelPassword')}</label>
        <input id="login-password" type="password" autocomplete="current-password" required>
        <label class="remember-row">
          <input id="remember-login" type="checkbox">
          <span>${t('auth.rememberLogin')}</span>
        </label>
        <button class="btn-primary" type="submit">${t('auth.submitLogin')}</button>
      </form>
    `;
    document.getElementById('login-form').addEventListener('submit', loginUser);
  }

  if (registerForm) {
    registerForm.innerHTML = `
      <p class="panel-label">${t('auth.registerPanel')}</p>
      <label for="register-name">${t('auth.labelFullName')}</label>
      <input id="register-name" type="text" placeholder="Ex. Komi ADJOKA" required>
      <label for="register-username">${t('auth.labelUsername')}</label>
      <input id="register-username" type="text" placeholder="komi_adjoka" pattern="[a-zA-Z0-9_]{3,20}" minlength="3" maxlength="20" autocomplete="username" required>
      <label for="register-email">${t('auth.labelEmail')}</label>
      <input id="register-email" type="email" placeholder="komi@coop.test" required>
      <label for="register-password">${t('auth.labelPassword')}</label>
      <input id="register-password" type="password" minlength="6" autocomplete="new-password" required>
      <label class="remember-row">
        <input id="register-observer" type="checkbox">
        <span>${t('auth.observerOnly')}</span>
      </label>
      <button class="btn-primary" type="submit">${t('auth.submitRegister')}</button>
    `;
    registerForm.onsubmit = enregistrerProfil;
  }
}

function installExtraNavItems() {
  const nav = document.querySelector('.sidebar nav');
  if (!nav || nav.querySelector('[data-page="cotisations"]')) return;

  nav.insertAdjacentHTML('beforeend', `
    <a href="#cotisations" class="nav-item" data-page="cotisations"><span data-i18n="nav.cotisations">💰 Cotisations</span></a>
    <a href="#notifications" class="nav-item" data-page="notifications"><span data-i18n="nav.notifications">🔔 Notifications</span></a>
    <a href="#configuration" class="nav-item hidden" data-page="configuration" id="nav-configuration"><span data-i18n="nav.configuration">⚙️ Configuration</span></a>
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
      <div id="setup-key-inline" class="receipt-panel hidden">
        <p class="panel-label">Clé unique (une seule fois)</p>
        <code id="setup-unique-key-inline">-</code>
        <button class="btn-secondary" type="button" onclick="copierCleUnique()">Copier</button>
      </div>
      <div id="setup-members-existing" class="login-panel">
        <p class="panel-label">Membres déjà inscrits</p>
        <div id="setup-members-list">
          <p>Chargement...</p>
        </div>
      </div>
      <form id="setup-create-member-form" class="login-panel" onsubmit="creerMembreAdmin(event)">
        <p class="panel-label">Créer un nouveau profil (si nécessaire)</p>
        <label for="admin-member-name">Nom</label>
        <input id="admin-member-name" type="text" required>
        <label for="admin-member-username">Identifiant</label>
        <input id="admin-member-username" type="text" pattern="[a-zA-Z0-9_]{3,20}" required>
        <label for="admin-member-email">Email</label>
        <input id="admin-member-email" type="email" required>
        <label for="admin-member-password">Mot de passe</label>
        <input id="admin-member-password" type="password" minlength="6" required>
        <button class="btn-primary" type="submit">Créer le profil</button>
      </form>
      <button class="btn-primary" onclick="terminerInitialisation()">Terminer</button>
    </div>
  `);
}

function installConfigurationPage() {
  const main = document.querySelector('.main-content');
  if (!main || document.getElementById('page-configuration')) return;

  main.insertAdjacentHTML('beforeend', `
    <div id="page-configuration" class="page">
      <div class="page-header">
        <h1>Configuration</h1>
        <p class="vote-info">Modifications réservées à l’administrateur. Chaque champ est enregistré séparément.</p>
      </div>
      <div class="login-panel">
        <label for="cfg-nom-coop">Nom de la coopérative</label>
        <input id="cfg-nom-coop" type="text" autocomplete="organization">
        <button type="button" class="btn-primary" onclick="enregistrerConfigCle('nom_coop')">Enregistrer</button>
      </div>
      <div class="login-panel">
        <label for="cfg-duree-mandat">Durée des mandats (mois)</label>
        <input id="cfg-duree-mandat" type="number" min="1" step="1">
        <button type="button" class="btn-primary" onclick="enregistrerConfigCle('duree_mandat')">Enregistrer</button>
      </div>
      <div class="login-panel">
        <label for="cfg-inactivite">Durée d’inactivité avant désactivation (mois)</label>
        <input id="cfg-inactivite" type="number" min="1" step="1">
        <button type="button" class="btn-primary" onclick="enregistrerConfigCle('duree_inactivite_mois')">Enregistrer</button>
      </div>
    </div>
  `);
}

function installVotePageSections() {
  const page = document.getElementById('page-vote');
  if (!page || document.getElementById('config-vote-panel')) return;

  const proposalBtn = document.getElementById('proposal-btn');
  if (proposalBtn) {
    proposalBtn.insertAdjacentHTML('afterend', `
      <button type="button" id="proposer-config-btn" class="btn-secondary hidden" onclick="basculerPanelConfigVote()">
        Proposer une modification de configuration
      </button>
    `);
  }

  const container = document.getElementById('votes-container');
  if (container) {
    container.insertAdjacentHTML('beforebegin', `
      <div id="config-vote-panel" class="login-panel hidden">
        <p class="panel-label">Vote sur la configuration</p>
        <label for="config-vote-cle">Paramètre</label>
        <select id="config-vote-cle">
          <option value="nom_coop">Nom de la coopérative</option>
          <option value="duree_mandat">Durée des mandats (mois)</option>
          <option value="duree_inactivite_mois">Durée d’inactivité (mois)</option>
        </select>
        <label for="config-vote-valeur">Nouvelle valeur</label>
        <input id="config-vote-valeur" type="text">
        <label for="config-vote-duree">Durée du vote (heures, minimum 72)</label>
        <input id="config-vote-duree" type="number" min="72" step="1" value="72">
        <button type="button" class="btn-primary" onclick="soumettrePropositionConfig()">Soumettre au vote</button>
        <button type="button" class="btn-secondary" onclick="basculerPanelConfigVote(true)">Annuler</button>
      </div>
    `);
    container.insertAdjacentHTML('afterend', `
      <section id="actions-votees-section" class="login-panel">
        <h2>Actions votées</h2>
        <div id="actions-votees-list"><p>Chargement…</p></div>
      </section>
    `);
  }
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
          <p id="fedapay-pay-error" class="fedapay-pay-error hidden" role="alert"></p>
        </div>
      </div>
      <form id="manual-cotisation-form" class="login-panel hidden" onsubmit="enregistrerCotisationManuelle(event)">
        <label for="cotisation-member-select">Membre</label>
        <select id="cotisation-member-select" required></select>
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
  closeMobileSidebar();
  hidePaiementRetourView();
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
    chargerNotificationsHistorique(),
    chargerSante(),
  ]);
  renderDashboard();
  renderVotes();
  renderVotesInDashboard();
  flushPendingTransactions();
}

async function chargerNotificationsHistorique() {
  try {
    const data = await apiFetch('/api/notifications');
    const incoming = data.notifications || [];
    notifications = filterNotificationsForCurrentUser(incoming);
    renderNotifications();
  } catch (error) {
    // ignore
  }
}

function renderSetupMembersList() {
  const container = document.getElementById('setup-members-list');
  if (!container) return;

  if (!members.length) {
    container.innerHTML = '<p>Aucun membre inscrit pour le moment. Créez un premier profil ci-dessous.</p>';
    return;
  }

  const roleOptions = ['president', 'tresorier', 'secretaire', 'verificateur', 'membre', 'observateur'];
  container.innerHTML = `
    <table style="width:100%; border-collapse:collapse;">
      <thead>
        <tr><th style="text-align:left; padding:6px 0;">Nom</th><th style="text-align:left; padding:6px 0;">Rôle</th><th style="text-align:left; padding:6px 0;">Action</th></tr>
      </thead>
      <tbody>
        ${members.map(member => `
          <tr>
            <td style="padding:6px 0;">${escapeHtml(member.nom)}</td>
            <td style="padding:6px 0;">
              <select id="setup-role-${member.id}">
                ${roleOptions.map(role => `<option value="${role}" ${normalizeRole(member.role)===role?'selected':''}>${role}</option>`).join('')}
              </select>
            </td>
            <td style="padding:6px 0;">
              <button class="status-button" onclick="attribuerRoleDepuisSetup('${member.id}')">Attribuer</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function attribuerRoleDepuisSetup(memberId) {
  const userRole = currentUser?.role;
  if (!checkPermission('updateMembreRole', userRole)) {
    showPermissionError('updateMembreRole', userRole);
    return;
  }
  try {
    const role = document.getElementById(`setup-role-${memberId}`)?.value;
    await apiFetch(`/api/members/${memberId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role, duree_mandat_mois: Number(document.getElementById('setup-mandate-duration')?.value || 12) }),
    });
    await chargerMembres();
    renderSetupMembersList();
  } catch (error) {
    alert(error.message || 'Attribution impossible.');
  }
}

async function chargerConfig() {
  try {
    const data = await apiFetch('/api/config');
    coopConfig = data;
    document.getElementById('members-title').textContent = t('page.members.titleWithCoop', { coop: data.nom_coop || 'Coop' });
    const sidebarName = document.getElementById('sidebar-coop-name');
    if (sidebarName) sidebarName.textContent = data.nom_coop || 'CoopLedger';
  } catch (error) {
    coopConfig = { nom_coop: null };
    document.getElementById('members-title').textContent = t('page.members.titleShort');
    const sidebarName = document.getElementById('sidebar-coop-name');
    if (sidebarName) sidebarName.textContent = 'CoopLedger';
  }
}

async function chargerConfigAdmin() {
  if (!currentUser?.permissions?.canEditCoopConfig || isDemoSession()) {
    return;
  }
  try {
    const data = await apiFetch('/api/config/all');
    const cfg = data.config || {};
    const nom = document.getElementById('cfg-nom-coop');
    const mand = document.getElementById('cfg-duree-mandat');
    const inact = document.getElementById('cfg-inactivite');
    if (nom) nom.value = String(cfg.nom_coop ?? '');
    if (mand) mand.value = String(cfg.duree_mandat ?? '');
    if (inact) inact.value = String(cfg.duree_inactivite_mois ?? '');
  } catch (_) {
    /* ignore */
  }
}

async function enregistrerConfigCle(cle) {
  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }
  const inputId = cle === 'nom_coop'
    ? 'cfg-nom-coop'
    : cle === 'duree_mandat'
      ? 'cfg-duree-mandat'
      : 'cfg-inactivite';
  const el = document.getElementById(inputId);
  const valeur = el?.value;
  try {
    await apiFetch(`/api/config/${encodeURIComponent(cle)}`, {
      method: 'PUT',
      body: JSON.stringify({ valeur }),
    });
    alert('Configuration enregistrée.');
    await chargerConfig();
  } catch (error) {
    alert(error.message || 'Erreur lors de l’enregistrement.');
  }
}

async function chargerActionsVotees() {
  try {
    const data = await apiFetch('/api/actions-votees');
    actionsVotees = data.actions_votees || [];
    renderActionsVotees();
  } catch (_) {
    actionsVotees = [];
    renderActionsVotees();
  }
}

function renderActionsVotees() {
  const list = document.getElementById('actions-votees-list');
  if (!list) return;

  if (!actionsVotees.length) {
    list.innerHTML = '<p class="vote-info">Aucune action votée enregistrée.</p>';
    return;
  }

  list.innerHTML = `
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Vote</th>
            <th>Budget</th>
            <th>Statut</th>
            <th>Preuve</th>
          </tr>
        </thead>
        <tbody>
          ${actionsVotees.map((row) => {
            const statut = String(row.statut || '');
            const enAttente = statut === 'en_attente';
            const hash = row.transaction_hash;
            const explorer = row.transaction_explorer;
            const badge = enAttente
              ? '<span class="badge-inactif">En attente</span>'
              : '<span class="badge-actif">Concrétisé</span>';
            const link = hash && explorer
              ? `<a href="${escapeHtml(explorer)}" target="_blank" rel="noreferrer" class="hash-link">${escapeHtml(shortHash(hash))}</a>`
              : '—';
            return `
              <tr>
                <td>${escapeHtml(row.titre)}</td>
                <td>${Number(row.budget || 0).toLocaleString('fr-FR')} FCFA</td>
                <td>${badge}</td>
                <td class="hash">${link}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function basculerPanelConfigVote(forceClose = false) {
  const panel = document.getElementById('config-vote-panel');
  if (!panel) return;
  if (forceClose) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.toggle('hidden');
}

async function soumettrePropositionConfig() {
  const userRole = currentUser?.role;
  if (!checkPermission('createVote', userRole)) {
    showPermissionError('createVote', userRole);
    return;
  }
  const cle = document.getElementById('config-vote-cle')?.value || '';
  const nouvelleValeur = document.getElementById('config-vote-valeur')?.value ?? '';
  const duree = Math.max(72, Number(document.getElementById('config-vote-duree')?.value || 72));
  try {
    await apiFetch('/api/votes', {
      method: 'POST',
      body: JSON.stringify({
        type: 'config',
        cle_config: cle,
        nouvelle_valeur: nouvelleValeur,
        duree_heures: duree,
      }),
    });
    basculerPanelConfigVote(true);
    document.getElementById('config-vote-valeur') && (document.getElementById('config-vote-valeur').value = '');
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Impossible de créer le vote.');
  }
}

function buildTransactionQueryString() {
  const params = new URLSearchParams();
  const typeEl = document.getElementById('tx-filter-type');
  const statutEl = document.getElementById('tx-filter-statut');
  const fromEl = document.getElementById('tx-filter-date-from');
  const toEl = document.getElementById('tx-filter-date-to');
  const type = String(typeEl?.value || '').trim();
  const statut = String(statutEl?.value || '').trim();
  const dateFrom = String(fromEl?.value || '').trim();
  const dateTo = String(toEl?.value || '').trim();
  if (type && type !== 'tous') params.set('type', type);
  if (statut) params.set('statut', statut);
  if (dateFrom) params.set('date_from', dateFrom);
  if (dateTo) params.set('date_to', dateTo);
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

async function chargerTransactions() {
  try {
    const data = await apiFetch(`/api/transactions${buildTransactionQueryString()}`);
    transactions = data.transactions || [];
    renderTransactions();
  } catch (error) {
    renderTableError('transactions-list', 6, error.message);
  }
}

function appliquerFiltresTransactions() {
  chargerTransactions();
}

async function chargerMembres() {
  try {
    const data = await apiFetch('/api/members');
    members = data.members || [];
    renderMembers();
    renderCotisationMemberOptions();
    renderFluxCotisationMemberOptions();
  } catch (error) {
    renderTableError('members-list', error.message === 'Acces non autorise.' ? 3 : 6, error.message);
  }
}

function renderCotisationMemberOptions() {
  const select = document.getElementById('cotisation-member-select');
  if (!select) return;
  const sorted = [...members].sort((a, b) => String(a.nom).localeCompare(String(b.nom), 'fr'));
  select.innerHTML = sorted.length
    ? sorted.map(member => `<option value="${member.id}">${escapeHtml(member.nom)} (${escapeHtml(member.username || member.id)})</option>`).join('')
    : '<option value="">Aucun membre</option>';
}

function renderFluxCotisationMemberOptions() {
  const select = document.getElementById('txn-cot-member');
  if (!select) return;
  const sorted = [...members].sort((a, b) => String(a.nom).localeCompare(String(b.nom), 'fr'));
  select.innerHTML = sorted.length
    ? sorted.map(member => `<option value="${member.id}">${escapeHtml(member.nom)} (${escapeHtml(member.username || member.id)})</option>`).join('')
    : '<option value="">Aucun membre</option>';
}

async function chargerVotes() {
  try {
    const data = await apiFetch('/api/votes');
    votes = data.votes || [];
    renderVotes();
    renderVotesInDashboard();
    renderTransactionVoteOptions();
    await chargerActionsVotees();
  } catch (error) {
    const page = document.getElementById('page-vote');
    if (page) page.insertAdjacentHTML('beforeend', `<p>${escapeHtml(error.message)}</p>`);
  }
}

function renderTransactionVoteOptions() {
  const select = document.getElementById('transaction-vote-select');
  if (!select) return;

  const validated = votes.filter((vote) => {
    if (vote.statut !== 'validé') return false;
    const t = String(vote.type || 'decision').toLowerCase();
    return t === 'decision';
  });
  select.innerHTML = validated.length
    ? validated.map(vote => `
        <option value="${vote.id}">
          ${escapeHtml(vote.titre)} — budget ${Number(vote.budget || 0).toLocaleString('fr-FR')} FCFA
        </option>`.trim())
      .join('')
    : '<option value="">Aucun vote validé</option>';
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
    tbody.innerHTML = '<tr><td colspan="6">Aucune transaction enregistree.</td></tr>';
  } else {
    tbody.innerHTML = transactions.map(transaction => {
      const amount = Number(transaction.montant || 0);
      const txType = transaction.type || (amount < 0 ? 'depense' : 'recette');
      const hash = transaction.hash;
      const explorer = transaction.explorer || '';
      const detailArg = JSON.stringify(String(transaction.id));
      const linkPart = hash && explorer
        ? `<a href="${escapeHtml(explorer)}" target="_blank" rel="noreferrer" class="hash-link">${escapeHtml(shortHash(hash))}</a>`
        : (hash ? escapeHtml(shortHash(hash)) : '—');
      const detailBtn = `<button type="button" class="hash-button" onclick="afficherRecu(${detailArg})">Détail</button>`;

      return `
        <tr>
          <td>${formatDate(transaction.date)}</td>
          <td>${escapeHtml(transaction.libelle)}</td>
          <td>${escapeHtml(txType)}</td>
          <td class="${amount >= 0 ? 'montant-positif' : 'montant-negatif'}">${formatMontant(amount)}</td>
          <td class="hash">${linkPart} ${hash ? detailBtn : ''}</td>
          <td><span class="badge-scelle">${escapeHtml(transaction.statut || 'scellé')}</span></td>
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

  const theadRow = tbody.closest('table')?.querySelector('thead tr');
  const canManage = Boolean(currentUser?.permissions.canManageMembers);
  const detailView = Boolean(
    currentUser?.permissions.canAssignRoleDropdown || currentUser?.permissions.canSecretaryFlows,
  );
  const isAdmin = Boolean(currentUser?.permissions.isAdmin);
  const isSecretary = Boolean(currentUser?.permissions.canSecretaryFlows);

  if (theadRow) {
    theadRow.innerHTML = detailView
      ? '<th>Nom</th><th>Email</th><th>Rôle</th><th>Cotisations</th><th>Statut</th><th>Action</th>'
      : '<th>Nom</th><th>Rôle</th><th>Statut</th>';
  }

  if (!members.length) {
    const cols = detailView ? 6 : 3;
    tbody.innerHTML = `<tr><td colspan="${cols}">Aucun membre enregistre.</td></tr>`;
  } else {
    tbody.innerHTML = members.map(member => {
      const roleValue = normalizeRole(member.role || 'membre');
      const mandateValue = isAdmin ? 12 : '';
      const cotCount = typeof member.cotisations_count === 'number' ? String(member.cotisations_count) : '—';

      if (!detailView) {
        return `
          <tr>
            <td>${escapeHtml(member.nom)}</td>
            <td>${escapeHtml(member.role)}</td>
            <td><span class="${member.statut === 'Actif' ? 'badge-actif' : 'badge-inactif'}">${escapeHtml(member.statut)}</span></td>
          </tr>
        `;
      }

      return `
        <tr>
          <td>${escapeHtml(member.nom)}</td>
          <td>${escapeHtml(member.email || '—')}</td>
          <td>${escapeHtml(member.role)}</td>
          <td>${escapeHtml(cotCount)}</td>
          <td><span class="${member.statut === 'Actif' ? 'badge-actif' : 'badge-inactif'}">${escapeHtml(member.statut)}</span></td>
          <td>
            ${canManage && isAdmin ? `
              <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                <select id="member-role-${member.id}">
                  ${['president','tresorier','secretaire','verificateur','membre','observateur'].map(r => `<option value="${r}" ${roleValue===r?'selected':''}>${r}</option>`).join('')}
                </select>
                <input id="member-mandate-${member.id}" type="number" min="1" value="${mandateValue}" style="width:90px" title="Durée du mandat (mois)">
                <button type="button" class="status-button" onclick="attribuerRole('${member.id}')">Enregistrer rôle</button>
              </div>
              <div style="display:flex; gap:8px; margin-top:8px; flex-wrap:wrap; align-items:center;">
                <button type="button" class="status-button" onclick="basculerStatutMembre('${member.id}', 'Actif')"
                  ${member.statut === 'Actif' ? 'disabled' : ''}>Activer</button>
                <button type="button" class="status-button" onclick="basculerStatutMembre('${member.id}', 'Inactif')"
                  ${member.statut === 'Inactif' ? 'disabled' : ''}>Désactiver</button>
                <input id="member-resetpwd-${member.id}" type="password" minlength="6" placeholder="Nouveau mot de passe" style="width:220px">
                <button type="button" class="status-button" onclick="resetPassword('${member.id}')">Réinitialiser mot de passe</button>
              </div>
            ` : ''}
            ${canManage && isSecretary && !isAdmin ? `
              <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                <span>Rôle : ${escapeHtml(member.role)}</span>
              </div>
              <div style="display:flex; gap:8px; margin-top:8px;">
                <button type="button" class="status-button" onclick="basculerStatutMembre('${member.id}', 'Actif')"
                  ${member.statut === 'Actif' ? 'disabled' : ''}>Activer</button>
                <button type="button" class="status-button" onclick="basculerStatutMembre('${member.id}', 'Inactif')"
                  ${member.statut === 'Inactif' ? 'disabled' : ''}>Désactiver</button>
              </div>
            ` : ''}
            ${!canManage ? '<button class="status-button" disabled>—</button>' : ''}
          </td>
        </tr>
      `;
    }).join('');
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
  const configVotes = votes.filter(vote => String(vote.type || '').toLowerCase() === 'config');
  const decisionVotes = votes.filter((vote) => {
    const t = String(vote.type || 'decision').toLowerCase();
    return t === 'decision';
  });
  const electionBlocks = candidatures.map(renderCandidatureCard).join('') + electionVotes.map(renderVoteCard).join('');
  const configBlocks = configVotes.map(renderVoteCard).join('');
  const decisionBlocks = decisionVotes.map(renderVoteCard).join('');
  const anyContent = electionBlocks || decisionBlocks || configBlocks;

  if (!anyContent) {
    page.insertAdjacentHTML('beforeend', '<div class="vote-card"><h3>Aucune proposition</h3><p class="vote-info">Les nouvelles propositions apparaitront ici.</p></div>');
  } else {
    page.insertAdjacentHTML('beforeend', `
      <div class="vote-card"><h3>Élections en cours</h3></div>
      ${electionBlocks || '<div class="vote-card"><p class="vote-info">Aucune election ouverte.</p></div>'}
      <div class="vote-card"><h3>Modifications de configuration (vote)</h3></div>
      ${configBlocks || '<div class="vote-card"><p class="vote-info">Aucune proposition de configuration.</p></div>'}
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
  const titre = escapeHtml(vacancy.poste || '');
  const dateLimite = vacancy.date_limite_candidature
    ? formatDateTime(vacancy.date_limite_candidature)
    : '-';
  const candidats = vacancy.candidats || [];
  const nombre = typeof vacancy.nombre_candidatures === 'number'
    ? vacancy.nombre_candidatures
    : candidats.length;
  const estCandidat = Boolean(vacancy.est_candidat);
  const aVote = Boolean(vacancy.a_vote);
  const electionVote = vacancy.election_vote;
  const scrutinCloture = electionVote && electionVote.statut !== 'ouvert';
  const showDecompte = scrutinCloture && Array.isArray(vacancy.decompte_voix) && vacancy.decompte_voix.length > 0;
  const isObs = currentUser && normalizeRole(currentUser.role) === 'observateur';
  const isAdmin = Boolean(currentUser?.permissions?.isAdmin);
  const statutPv = cleanString(vacancy.statut);
  const peutSePresenter = !isObs && !estCandidat && statutPv !== 'annulé' && statutPv !== 'pourvu'
    && ['vacant', 'candidature'].includes(statutPv);
  const listeCandidats = candidats.length
    ? `<ul class="candidats-liste">${candidats.map((c) => `<li>${escapeHtml(c.nom_complet || c.nom || c.username || '')}</li>`).join('')}</ul>`
    : '<p class="vote-info">Aucun candidat inscrit pour le moment.</p>';
  const adminClose = isAdmin && (statutPv === 'vacant' || statutPv === 'candidature');
  const adminAnnuler = isAdmin && statutPv !== 'pourvu' && statutPv !== 'annulé';

  const decompteBloc = showDecompte
    ? `<div class="vote-decompte">
        <p class="vote-info">Décompte des voix</p>
        <ul>${vacancy.decompte_voix.map((d) => `<li>${escapeHtml(d.nom_complet)} — ${d.voix} voix</li>`).join('')}</ul>
      </div>`
    : '';

  return `
    <div class="vote-card" data-vacancy-id="${vacancy.id}">
      <h3>${titre}</h3>
      <p class="vote-info">Date limite de candidature : ${dateLimite}</p>
      <p class="vote-info">${nombre} candidature(s) · Statut : ${escapeHtml(statutPv || '-')}</p>
      ${estCandidat ? '<span class="badge-election">Déjà candidat</span>' : ''}
      ${aVote ? '<span class="badge-election">Déjà voté</span>' : ''}
      <p class="vote-info">Candidats</p>
      ${listeCandidats}
      ${decompteBloc}
      <div class="vote-actions">
        <button class="btn-primary" onclick="mePorterCandidat(${JSON.stringify(vacancy.poste)})" ${peutSePresenter ? '' : 'disabled'}>
          Me porter candidat
        </button>
        ${adminClose ? `<button class="btn-secondary" type="button" onclick="cloturerCandidaturePeriode(${vacancy.id})">Clôturer la candidature</button>` : ''}
        ${adminAnnuler ? `<button class="btn-secondary" type="button" onclick="annulerElectionPoste(${vacancy.id})">Annuler l'élection</button>` : ''}
      </div>
    </div>
  `;
}

function cleanString(value) {
  return String(value ?? '').trim().toLowerCase();
}

function renderVoteCard(vote) {
  const total = Number(vote.pour || 0) + Number(vote.contre || 0);
  const pourPct = total ? Math.round((Number(vote.pour || 0) / total) * 100) : 0;
  const contrePct = total ? 100 - pourPct : 0;
  const closed = vote.statut !== 'ouvert';
  const isAdmin = Boolean(currentUser?.permissions?.isAdmin);
  const isElection = vote.type === 'election';
  const isConfig = String(vote.type || '').toLowerCase() === 'config';
  const decompte = vote.decompte_voix;
  const showDecompteElection = isElection && closed && Array.isArray(decompte) && decompte.length > 0;

  const decompteBloc = showDecompteElection
    ? `<div class="vote-decompte">
        <p class="vote-info">Décompte des voix</p>
        <ul>${decompte.map((d) => `<li>${escapeHtml(d.nom_complet)} — ${d.voix} voix</li>`).join('')}</ul>
      </div>`
    : '';

  const budgetLine = isConfig
    ? `<p class="vote-info">Clé : <strong>${escapeHtml(vote.cle_config || '')}</strong></p>
       <p class="vote-info">Valeur proposée : <strong>${escapeHtml(vote.nouvelle_valeur || '')}</strong></p>`
    : `<p class="vote-budget">Budget estime : ${Number(vote.budget || 0).toLocaleString('fr-FR')} FCFA</p>`;

  return `
    <div class="vote-card" data-vote-id="${vote.id}">
      <h3>${escapeHtml(vote.titre)}</h3>
      ${budgetLine}
      ${!isElection && closed ? `
        <div class="vote-barre">
          <div class="vote-pour" style="width: ${pourPct}%">${pourPct}% Pour</div>
          <div class="vote-contre" style="width: ${contrePct}%">${contrePct}%</div>
        </div>
        <p class="vote-info">${vote.pour || 0} votes pour · ${vote.contre || 0} votes contre · Statut : ${escapeHtml(vote.statut)}</p>
      ` : ''}
      ${isElection && closed ? `
        <p class="vote-info">Statut du scrutin : ${escapeHtml(vote.statut)}</p>
        ${decompteBloc}
      ` : ''}
      ${!isElection && !closed ? `
        <p class="vote-info">Ouvert jusqu'au ${formatDateTime(vote.expires_at)}. ${isConfig ? 'Les membres votent pour ou contre cette modification.' : `Resultat masque jusqu'a la cloture.`}</p>
      ` : ''}
      ${isElection && !closed ? `
        <p class="vote-info">Scrutin ouvert jusqu'au ${formatDateTime(vote.expires_at)}.</p>
      ` : ''}
      ${vote.statut === 'ouvert' ? `
        <div class="vote-actions">
          ${vote.type === 'election'
            ? renderElectionVoteButtons(vote)
            : `<button class="btn-pour" onclick="voter(${vote.id}, 'pour')">Voter Pour</button>
               <button class="btn-contre" onclick="voter(${vote.id}, 'contre')">Voter Contre</button>`}
          ${currentUser?.permissions.canProlongVotes ? `
            <div class="vote-prolong-inline">
              <label for="prolong-hours-${vote.id}">Prolonger (heures)</label>
              <input id="prolong-hours-${vote.id}" type="number" min="1" step="1" value="24" style="width:72px;">
              <button class="btn-secondary" type="button" onclick="prolongerVoteDepuisCarte(${vote.id})">Prolonger</button>
            </div>
          ` : ''}
          ${(() => {
            const expireOk = vote.expires_at && new Date(vote.expires_at).getTime() <= Date.now();
            const bureau = ['president', 'tresorier'].includes(normalizeRole(currentUser?.role));
            const peutCloturerBureau = Boolean(bureau && expireOk);
            const afficheCloture = Boolean(isAdmin || peutCloturerBureau);
            const propId = vote.propose_par != null ? Number(vote.propose_par) : null;
            const uid = Number(currentUser?.id);
            const presidentAnnul = Boolean(
              normalizeRole(currentUser?.role) === 'president'
              && vote.type !== 'election'
              && vote.statut === 'ouvert'
              && propId === uid
              && Number(vote.pour || 0) === 0
              && Number(vote.contre || 0) === 0
            );
            const afficheAnnulerAdmin = Boolean(isAdmin);
            const afficheAnnulerPresident = Boolean(presidentAnnul);
            return `
              ${afficheCloture ? `
                <button class="btn-secondary" type="button" onclick="cloturerVote(${vote.id})">Clôturer</button>
              ` : ''}
              ${afficheAnnulerAdmin ? `
                <button class="btn-secondary" type="button" onclick="annulerVote(${vote.id})">Annuler</button>
              ` : ''}
              ${afficheAnnulerPresident && !afficheAnnulerAdmin ? `
                <button class="btn-secondary" type="button" onclick="annulerVote(${vote.id})">Annuler ma proposition</button>
              ` : ''}
            `;
          })()}
        </div>
      ` : ''}
      <p class="vote-blockchain">Resultat ${closed ? 'publie' : 'en attente de cloture'}</p>
    </div>
  `;
}

function renderElectionVoteButtons(vote) {
  if (vote.a_vote) {
    return '<p><span class="badge-election">Déjà voté</span> · vous avez participé à ce scrutin.</p>';
  }

  const vacancy = candidatures.find(item => item.id === vote.poste_vacant_id || item.poste === vote.poste);
  const candidates = vacancy?.candidats || [];

  if (!candidates.length) {
    return '<p class="vote-info">Aucun candidat disponible.</p>';
  }

  return candidates.map(candidate => `
    <button class="btn-pour" onclick="voter(${vote.id}, '${candidate.id}')">
      ${escapeHtml(candidate.nom || candidate.nom_complet || candidate.username)}
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

  const visible = filterNotificationsForCurrentUser(notifications);

  if (!visible.length) {
    list.innerHTML = '<p>Aucune notification pour le moment.</p>';
    return;
  }

  list.innerHTML = visible.map(notification => `
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

  const proposerConfigBtn = document.getElementById('proposer-config-btn');
  if (proposerConfigBtn) {
    proposerConfigBtn.classList.toggle('hidden', !permissions.canProposeConfigVote);
    proposerConfigBtn.disabled = !permissions.canProposeConfigVote;
  }

  document.getElementById('nav-configuration')?.classList.toggle('hidden', !permissions.canEditCoopConfig);

  const addMemberBtn = document.getElementById('add-member-btn');
  if (addMemberBtn) {
    const canAdd = permissions.isAdmin || permissions.canSecretaryFlows;
    addMemberBtn.disabled = !canAdd;
    addMemberBtn.textContent = permissions.isAdmin ? 'Créer un membre' : 'Ajouter un membre';
  }

  setVisible('manual-cotisation-form', false);

  document.querySelectorAll('.btn-pour, .btn-contre').forEach(button => {
    button.disabled = !permissions.canVote;
  });
}

function majChampsFluxFinancier() {
  const flow = document.getElementById('txn-flow-type')?.value || '';
  const rd = document.getElementById('txn-recette-depense-block');
  const cot = document.getElementById('txn-cotisation-block');
  if (rd) rd.classList.toggle('hidden', flow !== 'recette' && flow !== 'depense');
  if (cot) cot.classList.toggle('hidden', flow !== 'cotisation_manuelle');

  const lib = document.getElementById('transaction-libelle');
  const m = document.getElementById('transaction-montant');
  const vs = document.getElementById('transaction-vote-select');
  if (flow === 'recette' || flow === 'depense') {
    if (lib) lib.required = true;
    if (m) m.required = true;
    if (vs) vs.required = true;
  } else {
    if (lib) lib.required = false;
    if (m) m.required = false;
    if (vs) vs.required = false;
  }
}

async function enregistrerTransaction() {
  const userRole = currentUser?.role;
  if (!checkPermission('createTransaction', userRole) && !checkPermission('enregistrerCotisation', userRole)) {
    showPermissionError('createTransaction', userRole);
    return;
  }
  const form = document.getElementById('transaction-form');
  if (!form) return;
  form.classList.toggle('hidden');
  if (!form.classList.contains('hidden')) {
    const sel = document.getElementById('txn-flow-type');
    if (sel) sel.value = '';
    majChampsFluxFinancier();
  }
}

async function soumettreFluxFinancier(event) {
  event.preventDefault();

  const flow = document.getElementById('txn-flow-type')?.value || '';

  if (flow === 'cotisation_manuelle') {
    const userRole = currentUser?.role;
    if (!checkPermission('enregistrerCotisation', userRole)) {
      showPermissionError('enregistrerCotisation', userRole);
      return;
    }
    const memberId = Number(document.getElementById('txn-cot-member')?.value || 0);
    const montant = Number(document.getElementById('txn-cot-montant')?.value || 0);
    const mode = String(document.getElementById('txn-cot-mode')?.value || '').trim();
    if (!Number.isInteger(memberId) || memberId <= 0) {
      alert('Choisissez un membre.');
      return;
    }
    if (!Number.isInteger(montant) || montant <= 0) {
      alert('Montant cotisation invalide.');
      return;
    }
    try {
      const data = await apiFetch('/api/cotisations', {
        method: 'POST',
        body: JSON.stringify({ member_id: memberId, montant, mode }),
      });
      event.target.reset();
      majChampsFluxFinancier();
      document.getElementById('transaction-form')?.classList.add('hidden');
      await Promise.all([chargerCotisations(), chargerTransactions()]);
      const c = data.cotisation;
      if (c?.explorer) {
        alert(`Cotisation scellée. Preuve : ${c.explorer}`);
      } else {
        alert('Cotisation enregistrée.');
      }
    } catch (error) {
      alert(error.message || 'Enregistrement impossible.');
    }
    return;
  }

  const libelle = document.getElementById('transaction-libelle')?.value?.trim();
  const montantInput = document.getElementById('transaction-montant')?.value;
  const montantPositif = Number(montantInput);
  const voteId = Number(document.getElementById('transaction-vote-select')?.value || 0);

  if (!libelle) {
    alert('Libellé obligatoire.');
    return;
  }
  if (!Number.isInteger(montantPositif) || montantPositif <= 0) {
    alert('Le montant doit être un entier positif.');
    return;
  }
  if (!Number.isInteger(voteId) || voteId <= 0) {
    alert('Sélectionnez un vote validé.');
    return;
  }

  const type = flow === 'depense' ? 'depense' : 'recette';
  const payload = { libelle, montant: montantPositif, vote_id: voteId, type };

  const userRole = currentUser?.role;
  if (!checkPermission('createTransaction', userRole)) {
    showPermissionError('createTransaction', userRole);
    return;
  }

  if (!navigator.onLine) {
    queuePendingTransaction(payload);
    alert('Connexion absente. Mouvement ajouté à la file d\'attente.');
    return;
  }

  try {
    await submitTransactionPayload(payload);
    event.target.reset();
    document.getElementById('txn-flow-type').value = '';
    majChampsFluxFinancier();
    document.getElementById('transaction-form')?.classList.add('hidden');
  } catch (error) {
    alert(error.message || 'Enregistrement impossible.');
  }
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
  if (!checkPermission('createTransaction', currentUser?.role)) {
    showPermissionError('createTransaction', currentUser?.role);
    return;
  }

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
  const userRole = currentUser?.role;
  if (!checkPermission('createVote', userRole)) {
    showPermissionError('createVote', userRole);
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

async function cloturerVote(voteId) {
  const bureau = ['president', 'tresorier'].includes(normalizeRole(currentUser?.role));
  if (!currentUser?.permissions.isAdmin && !bureau) {
    return;
  }
  try {
    await apiFetch(`/api/votes/${voteId}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Clôture impossible.');
  }
}

async function prolongerVoteDepuisCarte(voteId) {
  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }
  const input = document.getElementById(`prolong-hours-${voteId}`);
  const hours = Number(input?.value || 0);
  if (!Number.isInteger(hours) || hours <= 0) {
    alert('Nombre d\'heures invalide.');
    return;
  }
  try {
    await apiFetch(`/api/votes/${voteId}/prolong`, {
      method: 'POST',
      body: JSON.stringify({ nouvelle_duree_heures: hours }),
    });
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Prolongation impossible.');
  }
}

async function annulerVote(voteId) {
  if (!confirm('Annuler cette consultation ?')) {
    return;
  }
  try {
    await apiFetch(`/api/votes/${voteId}/annuler`, { method: 'POST' });
    await chargerVotes();
  } catch (error) {
    alert(error.message || 'Annulation impossible.');
  }
}

async function attribuerRole(memberId) {
  const userRole = currentUser?.role;
  if (!checkPermission('updateMembreRole', userRole)) {
    showPermissionError('updateMembreRole', userRole);
    return;
  }

  try {
    const role = document.getElementById(`member-role-${memberId}`)?.value;
    if (!role) throw new Error('Role manquant.');

    const payload = { role };
    if (currentUser?.permissions.isAdmin) {
      const months = Number(document.getElementById(`member-mandate-${memberId}`)?.value || 0);
      if (months > 0) payload.duree_mandat_mois = months;
    } else {
      const voteId = Number(document.getElementById(`member-vote-${memberId}`)?.value || 0);
      payload.vote_id = voteId;
    }

    await apiFetch(`/api/members/${memberId}/role`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    await chargerMembres();
  } catch (error) {
    alert(error.message || 'Attribution impossible.');
  }
}

async function resetPassword(memberId) {
  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }

  try {
    const input = document.getElementById(`member-resetpwd-${memberId}`);
    const nouveau_password = input?.value || '';
    if (String(nouveau_password).length < 6) {
      alert('Minimum 6 caractères.');
      return;
    }

    await apiFetch(`/api/members/${memberId}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ nouveau_password }),
    });

    if (input) input.value = '';
    await chargerMembres();
    alert('Mot de passe réinitialisé.');
  } catch (error) {
    alert(error.message || 'Réinitialisation impossible.');
  }
}

async function basculerStatutMembre(memberId, statut) {
  const userRole = currentUser?.role;
  if (!checkPermission('updateMembreStatut', userRole)) {
    showPermissionError('updateMembreStatut', userRole);
    return;
  }
  try {
    await apiFetch(`/api/members/${memberId}/statut`, {
      method: 'POST',
      body: JSON.stringify({ statut }),
    });
    await chargerMembres();
  } catch (error) {
    alert(error.message || 'Mise à jour impossible.');
  }
}

async function ajouterMembre() {
  const userRole = currentUser?.role;
  if (!checkPermission('createMembre', userRole)) {
    showPermissionError('createMembre', userRole);
    return;
  }

  showPage('setup-members');
}

async function configurerCoop(event) {
  event.preventDefault();

  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }

  try {
    const data = await apiFetch('/api/config/init', {
      method: 'POST',
      body: JSON.stringify({
        nom_coop: document.getElementById('setup-coop-name').value.trim(),
        duree_mandat: Number(document.getElementById('setup-mandate-duration').value),
      }),
    });
    document.getElementById('setup-unique-key').textContent = data.config.cle_unique;
    initialSetupKey = data.config.cle_unique;
    document.getElementById('setup-key-panel').classList.remove('hidden');
    await chargerConfig();
    await chargerMembres();
    renderSetupMembersList();
    showPage('setup-members');
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

  const userRole = currentUser?.role;
  if (!checkPermission('createMembre', userRole)) {
    showPermissionError('createMembre', userRole);
    return;
  }

  try {
    await apiFetch('/api/members/create', {
      method: 'POST',
      body: JSON.stringify({
        nom: document.getElementById('admin-member-name').value.trim(),
        username: document.getElementById('admin-member-username').value.trim(),
        email: document.getElementById('admin-member-email').value.trim(),
        password: document.getElementById('admin-member-password').value,
        role: 'membre',
      }),
    });
    event.target.reset();
    await chargerMembres();
    renderSetupMembersList();
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

async function cloturerCandidaturePeriode(vacancyId) {
  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }
  try {
    await apiFetch(`/api/candidatures/${vacancyId}/close`, { method: 'POST' });
    await Promise.all([chargerCandidatures(), chargerVotes()]);
    renderVotes();
    renderVotesInDashboard();
    alert('Période de candidature clôturée. Le vote est maintenant ouvert.');
  } catch (error) {
    alert(error.message || 'Action impossible.');
  }
}

async function annulerElectionPoste(vacancyId) {
  const userRole = currentUser?.role;
  if (!checkPermission('adminActions', userRole)) {
    showPermissionError('adminActions', userRole);
    return;
  }
  if (!window.confirm('Annuler cette élection ?')) return;
  try {
    await apiFetch(`/api/candidatures/${vacancyId}/annuler`, { method: 'POST' });
    await Promise.all([chargerCandidatures(), chargerVotes()]);
    renderVotes();
    renderVotesInDashboard();
    alert('Élection annulée.');
  } catch (error) {
    alert(error.message || 'Action impossible.');
  }
}

async function enregistrerCotisationManuelle(event) {
  event.preventDefault();

  const userRole = currentUser?.role;
  if (!checkPermission('enregistrerCotisation', userRole)) {
    showPermissionError('enregistrerCotisation', userRole);
    return;
  }

  try {
    await apiFetch('/api/cotisations', {
      method: 'POST',
      body: JSON.stringify({
        member_id: Number(document.getElementById('cotisation-member-select').value),
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
  const btn = document.getElementById('fedapay-btn');
  const errEl = document.getElementById('fedapay-pay-error');

  const setError = (msg) => {
    if (errEl) {
      errEl.textContent = msg;
      errEl.classList.remove('hidden');
    } else {
      alert(msg);
    }
  };

  if (!Number.isInteger(amount) || amount <= 0) {
    setError('Le montant doit être un entier positif.');
    return;
  }

  if (btn) {
    if (!btn.dataset.defaultLabel) btn.dataset.defaultLabel = btn.textContent.trim();
    btn.disabled = true;
    btn.textContent = 'Redirection vers FedaPay...';
  }
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }

  try {
    const data = await apiFetch('/api/fedapay/initier', {
      method: 'POST',
      body: JSON.stringify({ montant: amount }),
    });
    const url = data?.url;
    if (!url || typeof url !== 'string') {
      throw new Error('Réponse de paiement incomplète.');
    }
    window.location.href = url;
  } catch (error) {
    if (btn) {
      btn.disabled = false;
      btn.textContent = btn.dataset.defaultLabel || 'Payer';
    }
    setError(error.message || 'Paiement temporairement indisponible. Réessayez.');
  }
}

function startNotificationsStream() {
  stopNotificationsStream();

  if (!getToken() || isDemoSession()) return;

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
    onPaiementRetourCotisationNotification(notification);
    if (filterNotificationsForCurrentUser([notification]).length) {
      notifications.unshift(notification);
    }
    renderNotifications();
    refreshDataAfterNotification(notification);
  } catch (error) {
    console.error(error);
  }
}

function refreshDataAfterNotification(notification) {
  if (notification.type === 'transaction') {
    chargerTransactions();
    chargerActionsVotees();
  }
  if (notification.type === 'vote') {
    chargerVotes();
    chargerActionsVotees();
  }
  if (notification.type === 'config') {
    chargerConfig();
    chargerVotes();
  }
  if (notification.type === 'membre') chargerMembres();
  if (notification.type === 'cotisation' || notification.type === 'paiement_confirme') {
    chargerCotisations();
  }
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

async function lancerDemo() {
  try {
    const data = await fetch('/api/demo/start', { method: 'POST' }).then(async (response) => {
      const json = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(json.error || 'Démo indisponible.');
      }
      return json;
    });
    if (!data.token) {
      throw new Error('Démo indisponible.');
    }
    setToken(data.token, false);
    openSessionFromToken(data.token);
  } catch (error) {
    alert(error.message || 'Impossible de lancer la démonstration.');
  }
}

function etapeDemoSuivante() {}

function arreterDemo() {
  document.getElementById('demo-guide')?.classList.add('hidden');
}

window.showPage = showPage;
window.deconnecter = deconnecter;
window.enregistrerProfil = enregistrerProfil;
window.enregistrerTransaction = enregistrerTransaction;
window.soumettreFluxFinancier = soumettreFluxFinancier;
window.majChampsFluxFinancier = majChampsFluxFinancier;
window.appliquerFiltresTransactions = appliquerFiltresTransactions;
window.basculerStatutMembre = basculerStatutMembre;
window.prolongerVoteDepuisCarte = prolongerVoteDepuisCarte;
window.afficherRecu = afficherRecu;
window.fermerRecu = fermerRecu;
window.suggererOperation = suggererOperation;
window.enregistrerConfigCle = enregistrerConfigCle;
window.basculerPanelConfigVote = basculerPanelConfigVote;
window.soumettrePropositionConfig = soumettrePropositionConfig;
window.voter = voter;
window.cloturerVote = cloturerVote;
window.annulerVote = annulerVote;
window.attribuerRole = attribuerRole;
window.resetPassword = resetPassword;
window.ajouterMembre = ajouterMembre;
window.configurerCoop = configurerCoop;
window.copierCleUnique = copierCleUnique;
window.creerMembreAdmin = creerMembreAdmin;
window.terminerInitialisation = terminerInitialisation;
window.attribuerRoleDepuisSetup = attribuerRoleDepuisSetup;
window.mePorterCandidat = mePorterCandidat;
window.cloturerCandidaturePeriode = cloturerCandidaturePeriode;
window.annulerElectionPoste = annulerElectionPoste;
window.enregistrerCotisationManuelle = enregistrerCotisationManuelle;
window.initierPaiementFedapay = initierPaiementFedapay;
window.lancerDemo = lancerDemo;
window.etapeDemoSuivante = etapeDemoSuivante;
window.arreterDemo = arreterDemo;

document.addEventListener('DOMContentLoaded', () => {
  parseShellRouteFromHash();
  installDynamicInterface();
  installMobileShellNav();
  installShellHashRouting();
  installSettingsPanel();
  installThemeMediaListener();
  applyDocumentI18n();
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
