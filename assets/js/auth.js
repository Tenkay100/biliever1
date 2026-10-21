// ── FEDERAL RESERVE BANK — AUTH MODULE ──
import { initSupabase, getSupabase, signOut, getSession, dbSelect, dbInsert } from './firebase.js';
import { showToast, Storage, generateUUID } from './utils.js';

// ── INIT ──
// Safe init: wait for Firebase SDK to be ready
function waitForFirebase(cb, retries = 20) {
  if (typeof window !== 'undefined' && window.firebase && window.firebase.apps) {
    initSupabase();
    cb();
  } else if (retries > 0) {
    setTimeout(() => waitForFirebase(cb, retries - 1), 200);
  } else {
    console.warn('[Auth] Firebase SDK not loaded after waiting. Running without Firestore sync.');
    cb();
  }
}

waitForFirebase(() => {
  // Support widget init (client pages only)
  if (!window.location.pathname.includes('/admin/')) {
    import('./support-widget.js').then(m => {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', m.initSupportWidget);
      } else {
        m.initSupportWidget();
      }
    }).catch(() => {});
  }
});

// ── LOCAL USER STORE (primary, always works) ──
const LOCAL_USERS_KEY = 'frb_users_store';

function getLocalUsers() {
  try {
    return JSON.parse(localStorage.getItem(LOCAL_USERS_KEY) || '[]');
  } catch (e) { return []; }
}

function saveLocalUsers(users) {
  try {
    localStorage.setItem(LOCAL_USERS_KEY, JSON.stringify(users));
  } catch (e) {}
}

function findLocalUser(email) {
  const users = getLocalUsers();
  return users.find(u => u.email === (email || '').trim().toLowerCase()) || null;
}

function saveLocalUser(user) {
  const users = getLocalUsers();
  const idx = users.findIndex(u => u.id === user.id);
  if (idx >= 0) users[idx] = user;
  else users.push(user);
  saveLocalUsers(users);
}

// ── ROUTE GUARD (call on protected pages) ──
export async function requireAuth(allowedRoles = ['client', 'admin', 'super_admin', 'support', 'auditor']) {
  // Check mock session in localStorage first (primary)
  const mockSession = getMockSession_client();
  const cachedProfile = Storage.get('user_profile');

  if (!mockSession && !cachedProfile) {
    redirectToLogin();
    return null;
  }

  // Use cached profile as primary source of truth
  let profile = cachedProfile;

  // If profile missing, try to find in local user store
  if (!profile && mockSession) {
    const localUser = findLocalUser(mockSession.user?.email);
    if (localUser) {
      profile = localUser;
      Storage.set('user_profile', profile);
    }
  }

  if (!profile) {
    redirectToLogin();
    return null;
  }

  // Check status
  if (profile.status === 'suspended') {
    Storage.clear();
    localStorage.removeItem('mock_session');
    showToast("Your account has been suspended.", "danger");
    setTimeout(() => redirectToLogin(), 2000);
    return null;
  }

  const role = profile.role || 'client';
  if (!allowedRoles.includes(role)) {
    if (!window.location.pathname.endsWith('dashboard.html')) {
      window.location.href = 'dashboard.html';
    }
    return null;
  }

  // Idle timer check
  const lastActivity = parseInt(localStorage.getItem('aff_last_activity') || Date.now());
  const diff = (Date.now() - lastActivity) / 1000;
  if (diff >= 900) {
    console.log("Session expired on load. Logging out...");
    await logout(false);
    return null;
  }
  localStorage.setItem('aff_last_activity', Date.now());
  startIdleTimer();

  // Background Firestore sync (non-blocking)
  tryFirestoreProfileSync(profile);

  return profile;
}

// Non-blocking Firestore sync
async function tryFirestoreProfileSync(profile) {
  try {
    if (window.firebase && window.firebase.apps && window.firebase.apps.length > 0) {
      const { data } = await dbSelect('users', { eq: { email: profile.email }, limit: 1 });
      if (data && data[0]) {
        const merged = { ...profile, ...data[0] };
        Storage.set('user_profile', merged);
        saveLocalUser(merged);
      }
    }
  } catch (e) {}
}

export async function requireAdminAuth(allowedRoles = ['super_admin', 'admin', 'support', 'auditor']) {
  // Hardcoded bypass for demo admin
  const storedAdmin = Storage.get('admin_profile');
  if (storedAdmin && storedAdmin.email === 'admin') {
    startIdleTimer();
    return storedAdmin;
  }

  if (!storedAdmin) {
    window.location.href = 'login.html';
    return null;
  }

  if (!allowedRoles.includes(storedAdmin.role)) {
    showToast('Access denied for your role', 'danger');
    if (!window.location.pathname.endsWith('dashboard.html')) {
      window.location.href = 'dashboard.html';
    }
    return null;
  }

  startIdleTimer();
  return storedAdmin;
}

// ── LOAD USER PROFILE ──
export async function loadProfile(authId) {
  // Try local store first
  const users = getLocalUsers();
  const localUser = users.find(u => u.auth_id === authId || u.id === authId);
  if (localUser) {
    Storage.set('user_profile', localUser);
    return localUser;
  }

  // Try Firestore
  try {
    let { data } = await dbSelect('users', { eq: { auth_id: authId }, limit: 1 });
    if (!data || data.length === 0) {
      const res = await dbSelect('users', { eq: { id: authId }, limit: 1 });
      data = res.data;
    }
    if (data && data[0]) {
      Storage.set('user_profile', data[0]);
      saveLocalUser(data[0]);
      return data[0];
    }
  } catch (e) {
    console.warn('[Auth] Firestore loadProfile failed:', e);
  }

  return null;
}

// ── CLIENT LOGIN ──
export async function clientLogin(email, password) {
  const cleanEmail = (email || '').trim().toLowerCase();

  // 1. Check local user store first (always works offline)
  const localUser = findLocalUser(cleanEmail);
  if (localUser) {
    // Verify password
    if (localUser.password && localUser.password !== password) {
      return { success: false, message: 'Invalid email or password.' };
    }
    // Fallback: check mock storage password
    const storedPwd = Storage.get('mock_pwd_' + cleanEmail);
    if (!localUser.password && storedPwd && storedPwd !== password) {
      return { success: false, message: 'Invalid email or password.' };
    }

    if (localUser.status === 'suspended') {
      return { success: false, message: 'Your account has been suspended by administration.' };
    }

    // Success
    const authId = localUser.auth_id || localUser.id;
    localStorage.setItem('mock_session', JSON.stringify({ user: { id: authId, email: localUser.email } }));
    Storage.set('user_profile', localUser);
    Storage.set('mock_pwd_' + cleanEmail, password);
    localStorage.setItem('aff_last_activity', Date.now());

    // Background Firestore sync
    tryFirestoreLogin(cleanEmail, localUser);

    return { success: true, profile: localUser };
  }

  // 2. Fallback: try Firestore
  try {
    const { data: resUser } = await dbSelect('users', { eq: { email: cleanEmail }, limit: 1 });
    let user = resUser;

    if (!user || user.length === 0) {
      const { data: rawUser } = await dbSelect('users', { eq: { email: (email || '').trim() }, limit: 1 });
      if (rawUser && rawUser.length > 0) user = rawUser;
    }

    if (!user || user.length === 0) {
      return { success: false, message: 'Invalid email or password.' };
    }

    const profile = user[0];

    const storedPwd = Storage.get('mock_pwd_' + cleanEmail);
    if (profile.password && profile.password !== password) {
      return { success: false, message: 'Invalid email or password.' };
    }
    if (!profile.password && storedPwd && storedPwd !== password) {
      return { success: false, message: 'Invalid email or password.' };
    }

    if (profile.status === 'suspended') {
      return { success: false, message: 'Your account has been suspended by administration.' };
    }

    const authId = profile.auth_id || profile.id;
    localStorage.setItem('mock_session', JSON.stringify({ user: { id: authId, email: profile.email } }));
    Storage.set('user_profile', profile);
    Storage.set('mock_pwd_' + cleanEmail, password);
    localStorage.setItem('aff_last_activity', Date.now());
    saveLocalUser(profile);

    return { success: true, profile };
  } catch (e) {
    console.error('[Auth] Firestore login error:', e);
    return { success: false, message: 'Login failed. Please check your connection and try again.' };
  }
}

async function tryFirestoreLogin(email, profile) {
  try {
    await logLoginAttempt(email, true);
  } catch (e) {}
}

// ── ADMIN LOGIN ──
export async function adminLogin(email, password) {
  // Hardcoded bypass for demo purposes
  if (email === 'admin' && password === 'admin4321') {
    const mockAdmin = {
      id: 'mock-admin-id',
      email: 'admin',
      full_name: 'System Administrator',
      role: 'super_admin',
      is_active: true
    };
    Storage.set('admin_profile', mockAdmin);
    localStorage.setItem('aff_last_activity', Date.now());
    return { success: true, admin: mockAdmin };
  }

  return { success: false, message: 'Invalid admin credentials.' };
}

// ── LOGOUT ──
export async function logout(isAdmin = false) {
  try { await signOut(); } catch (e) {}
  Storage.clear();
  localStorage.removeItem('mock_session');
  localStorage.removeItem('aff_last_activity');
  const isSubDir = window.location.pathname.includes('/admin/');
  window.location.href = isSubDir ? '../index.html' : 'index.html';
}

// ── REGISTER ──
export async function register(formData) {
  try {
    const cleanEmail = (formData.email || '').trim().toLowerCase();

    if (!cleanEmail || !formData.password || formData.password.length < 8) {
      return { success: false, message: 'Please fill in all required fields (email and password min 8 chars).' };
    }

    // Check local store for duplicate email
    if (findLocalUser(cleanEmail)) {
      return { success: false, message: 'An account with this email already exists.' };
    }

    const fakeAuthId = generateUUID();
    const userId = generateUUID();

    const userRecord = {
      id: userId,
      auth_id: fakeAuthId,
      email: cleanEmail,
      password: formData.password,
      full_name: (formData.fullName || '').trim(),
      phone: formData.phone || null,
      address: formData.address || null,
      ssn: formData.ssn || null,
      kyc_status: 'approved',
      status: 'active',
      role: 'client',
      created_at: new Date().toISOString()
    };

    // Save to local store FIRST (always works)
    saveLocalUser(userRecord);
    Storage.set('mock_pwd_' + cleanEmail, formData.password);

    // Setup session immediately
    localStorage.setItem('mock_session', JSON.stringify({ user: { id: fakeAuthId, email: cleanEmail } }));
    Storage.set('user_profile', userRecord);
    localStorage.setItem('aff_last_activity', Date.now());

    // Generate account number for local store
    const { generateAccountNumber, generateIBAN, generateSWIFT } = await import('./utils.js');
    const accountNumber = generateAccountNumber();
    const accountId = generateUUID();

    const accountRecord = {
      id: accountId,
      user_id: userId,
      account_number: accountNumber,
      iban: generateIBAN(accountNumber),
      swift: generateSWIFT(),
      account_type: 'checking',
      currency: 'USD',
      status: 'active',
      nickname: 'Primary Checking',
      created_at: new Date().toISOString()
    };

    // Store account locally
    try {
      const localAccounts = JSON.parse(localStorage.getItem('frb_accounts_store') || '[]');
      localAccounts.push(accountRecord);
      localStorage.setItem('frb_accounts_store', JSON.stringify(localAccounts));

      const localBalances = JSON.parse(localStorage.getItem('frb_balances_store') || '[]');
      localBalances.push({ id: generateUUID(), account_id: accountId, available: 0.00, pending: 0.00 });
      localStorage.setItem('frb_balances_store', JSON.stringify(localBalances));
    } catch (e) {}

    // Background Firestore sync (non-blocking — don't await)
    syncRegistrationToFirestore(userRecord, accountRecord, accountId, userId);

    return { success: true, message: 'Account created successfully! Welcome to Federal Reserve Bank.' };
  } catch (e) {
    console.error("Registration error:", e);
    return { success: false, message: e.message || 'Registration failed. Please try again.' };
  }
}

async function syncRegistrationToFirestore(userRecord, accountRecord, accountId, userId) {
  try {
    if (!window.firebase || !window.firebase.apps || !window.firebase.apps.length) return;

    // Check duplicate email in Firestore
    const { data: existing } = await dbSelect('users', { eq: { email: userRecord.email }, limit: 1 });
    if (existing && existing.length > 0) return; // Already exists

    await dbInsert('users', userRecord);
    await dbInsert('accounts', accountRecord);
    await dbInsert('balances', { account_id: accountId, available: 0.00, pending: 0.00 });
    await dbInsert('kyc_documents', { user_id: userId, doc_type: 'national_id', file_name: 'id_front.jpg', status: 'approved' });
    await dbInsert('kyc_documents', { user_id: userId, doc_type: 'national_id', file_name: 'id_back.jpg', status: 'approved' });
    await dbInsert('kyc_documents', { user_id: userId, doc_type: 'selfie', file_name: 'selfie.jpg', status: 'approved' });
    await dbInsert('notifications', {
      user_id: userId,
      title: 'Welcome to Federal Reserve Bank!',
      message: 'Your account has been created and your identity is fully verified.',
      type: 'success'
    });
    console.log('[Auth] Registration synced to Firestore successfully.');
  } catch (e) {
    console.warn('[Auth] Firestore registration sync failed (user still registered locally):', e.message);
  }
}

// ── SESSION CHECK (redirect if already logged in) ──
export async function redirectIfLoggedIn(adminPage = false) {
  if (adminPage) {
    const storedAdmin = Storage.get('admin_profile');
    if (storedAdmin) {
      const lastActivity = parseInt(localStorage.getItem('aff_last_activity') || '0');
      if (Date.now() - lastActivity < 900 * 1000) {
        window.location.href = 'dashboard.html';
      }
    }
    return;
  }

  // Client: check mock_session
  const mock = localStorage.getItem('mock_session');
  if (mock) {
    try {
      const session = JSON.parse(mock);
      if (session && session.user) {
        const lastActivity = parseInt(localStorage.getItem('aff_last_activity') || '0');
        if (Date.now() - lastActivity < 900 * 1000) {
          const profile = Storage.get('user_profile');
          if (profile && profile.status !== 'suspended') {
            window.location.href = 'dashboard.html';
            return;
          }
        }
      }
    } catch (e) {}
    // Invalid or expired session
    localStorage.removeItem('mock_session');
  }
}

// ── HELPERS ──
function redirectToLogin() {
  const isSubDir = window.location.pathname.includes('/admin/');
  window.location.href = isSubDir ? 'login.html' : 'login.html';
}

function getMockSession_client() {
  try {
    const raw = localStorage.getItem('mock_session');
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (e) { return null; }
}

async function logLoginAttempt(email, success, reason = null) {
  try {
    const res = await fetch('https://api.ipify.org?format=json');
    const { ip } = await res.json();
    await dbInsert('login_logs', {
      email, ip_address: ip, user_agent: navigator.userAgent,
      success, failure_reason: reason, timestamp: new Date().toISOString()
    });
  } catch (e) {}
}

function parseAuthError(msg) {
  if (!msg) return 'An error occurred.';
  if (msg.includes('Invalid login')) return 'Invalid email or password.';
  if (msg.includes('Email not confirmed')) return 'Please verify your email first.';
  if (msg.includes('Too many requests')) return 'Too many attempts. Please wait a moment.';
  if (msg.includes('User already registered')) return 'Email already registered.';
  return msg;
}

// ── RATE LIMITING (client-side) ──
export function checkRateLimit(key, maxAttempts = 5, windowMs = 300000) {
  const stored = Storage.get('rate_' + key) || { count: 0, resetAt: Date.now() + windowMs };
  if (Date.now() > stored.resetAt) { stored.count = 0; stored.resetAt = Date.now() + windowMs; }
  stored.count++;
  Storage.set('rate_' + key, stored);
  if (stored.count > maxAttempts) {
    const remaining = Math.ceil((stored.resetAt - Date.now()) / 60000);
    return { blocked: true, message: `Too many attempts. Try again in ${remaining} minute(s).` };
  }
  return { blocked: false };
}

export function resetRateLimit(key) { Storage.remove('rate_' + key); }

// ── GET STORED PROFILE ──
export function getStoredProfile() { return Storage.get('user_profile'); }
export function getStoredAdmin() { return Storage.get('admin_profile'); }

// ── SESSION MANAGEMENT ──
let idleInterval = null;
let timerElement = null;

export function startIdleTimer() {
  if (idleInterval) return;

  if (!timerElement) {
    timerElement = document.createElement('div');
    timerElement.id = 'session-timer';
    timerElement.style = `
      position: fixed; bottom: 20px; left: 20px; 
      background: rgba(0,0,0,0.8); color: #fff; 
      padding: 6px 12px; border-radius: 20px; 
      font-size: 0.75rem; font-weight: bold; font-family: monospace;
      z-index: 10000; border: 1px solid var(--border);
      pointer-events: none; backdrop-filter: blur(4px);
      display: flex; align-items: center; gap: 6px;
    `;
    timerElement.innerHTML = `<i class="ph-bold ph-clock"></i> <span id="session-time">15:00</span>`;
    document.body.appendChild(timerElement);
  }

  const resetTimer = () => localStorage.setItem('aff_last_activity', Date.now());
  resetTimer();

  const events = ['mousedown', 'keypress', 'scroll', 'touchstart', 'click'];
  events.forEach(evt => document.addEventListener(evt, resetTimer));

  idleInterval = setInterval(() => {
    const lastActivity = parseInt(localStorage.getItem('aff_last_activity') || Date.now());
    const diff = Math.floor((Date.now() - lastActivity) / 1000);
    const remaining = Math.max(0, 900 - diff);

    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    const display = document.getElementById('session-time');
    if (display) display.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;

    if (timerElement) {
      if (remaining < 60) {
        timerElement.style.color = '#ef4444';
        timerElement.style.borderColor = '#ef4444';
      } else {
        timerElement.style.color = '#fff';
        timerElement.style.borderColor = 'var(--border)';
      }
    }

    if (remaining <= 0) {
      clearInterval(idleInterval);
      showToast("Session expired due to inactivity.", "warning");
      setTimeout(() => logout(false), 1500);
    }
  }, 1000);
}

export function getMockSession() { return Storage.get('admin_profile'); }
