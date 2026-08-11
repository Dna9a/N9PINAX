// N9pinax - Main JavaScript

// Theme Management
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
  // Keep the toggle's pressed state in sync for screen readers (F-105).
  const toggleBtn = document.getElementById('themeToggle');
  if (toggleBtn) toggleBtn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  const sunIcon = document.querySelector('.icon-sun');
  const moonIcon = document.querySelector('.icon-moon');
  if (sunIcon && moonIcon) {
    if (theme === 'dark') {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    } else {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
  }
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', initTheme);

// Theme toggle button
document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);

// Sidebar Toggle (for mobile)
function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  sidebar?.classList.toggle('open');
}

// Dropdown handling
document.addEventListener('click', function(e) {
  const dropdown = e.target.closest('.dropdown');
  
  // Close all dropdowns
  document.querySelectorAll('.dropdown.active').forEach(d => {
    if (d !== dropdown) d.classList.remove('active');
  });
  
  // Toggle clicked dropdown
  if (dropdown) {
    dropdown.classList.toggle('active');
  }
});

// Modal handling
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  modal?.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  modal?.classList.remove('active');
  document.body.style.overflow = '';
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) {
      overlay.classList.remove('active');
      document.body.style.overflow = '';
    }
  });
});

// Tab handling — WAI-ARIA tablist pattern with keyboard support (F-106):
// click OR Enter/Space activates; Arrow/Home/End move focus between tabs.
function initTabs() {
  document.querySelectorAll('.tabs').forEach(tabContainer => {
    const tabs = Array.from(tabContainer.querySelectorAll('.tab'));

    function activate(tab, focus) {
      tabs.forEach(t => {
        const on = t === tab;
        t.classList.toggle('active', on);
        if (t.hasAttribute('role')) {   // ARIA-managed tabs (e.g. admin)
          t.setAttribute('aria-selected', String(on));
          t.setAttribute('tabindex', on ? '0' : '-1');
        }
      });
      const tabId = tab.getAttribute('data-tab');
      if (tabId) {
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        document.getElementById(tabId)?.classList.remove('hidden');
      }
      if (focus) tab.focus();
    }

    tabs.forEach((tab, i) => {
      tab.addEventListener('click', () => activate(tab));
      tab.addEventListener('keydown', (e) => {
        let target = null;
        switch (e.key) {
          case 'ArrowRight': case 'ArrowDown': target = tabs[(i + 1) % tabs.length]; break;
          case 'ArrowLeft':  case 'ArrowUp':   target = tabs[(i - 1 + tabs.length) % tabs.length]; break;
          case 'Home': target = tabs[0]; break;
          case 'End':  target = tabs[tabs.length - 1]; break;
          case 'Enter': case ' ': case 'Spacebar': e.preventDefault(); activate(tab); return;
          default: return;
        }
        if (target) { e.preventDefault(); activate(target, true); }
      });
    });
  });
}

document.addEventListener('DOMContentLoaded', initTabs);

// Notification handling
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `alert alert-${type}`;
  notification.style.cssText = `
    position: fixed;
    top: 1rem;
    right: 1rem;
    z-index: 1000;
    max-width: 400px;
    animation: slideIn 0.3s ease;
  `;
  notification.innerHTML = `
    <div class="alert-icon">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        ${type === 'success' ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>' : 
          type === 'danger' ? '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>' :
          type === 'warning' ? '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>' :
          '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line>'}
      </svg>
    </div>
    <span>${message}</span>
  `;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Format helpers
function formatDate(date) {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(date));
}

function formatNumber(num) {
  return new Intl.NumberFormat('en-US').format(num);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ── API base (Network Binding) ──────────────────────────────────────────
// '' means "same host as the page" (relative). The admin Network Binding card
// can set localStorage.apiBaseUrl to target a specific LAN IP.
function getApiBase() {
  return localStorage.getItem('apiBaseUrl') || '';
}

// API helper — authenticated fetch wrapper.
async function api(endpoint, options = {}) {
  const token = localStorage.getItem('authToken');

  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers
    },
    ...options
  };

  let response;
  try {
    response = await fetch(`${getApiBase()}/api${endpoint}`, config);
  } catch (error) {
    console.error('API network error:', error);
    throw new Error('Network error — is the backend reachable?');
  }

  if (response.status === 401) {
    // Token missing/expired — clear and bounce to login.
    logout();
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = body.detail;
    } catch (_) { /* non-JSON error body */ }
    throw new Error(detail);
  }

  if (response.status === 204) return null;
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

// Logout — clear session and return to the login page.
function logout() {
  localStorage.removeItem('authToken');
  localStorage.removeItem('userRole');
  localStorage.removeItem('role');
  localStorage.removeItem('userEmail');
  const path = window.location.pathname;
  // Pages live under /pages/; the login page is at the site root.
  window.location.href = path.includes('/pages/') ? '../index.html' : 'index.html';
}

// ── Auth guard ────────────────────────────────────────────────────────────
// Call at the top of every protected page. Returns false (and redirects) when
// there is no token.
// Decode a JWT payload without verifying the signature (that's the server's
// job) — used only to check client-side expiry so we bounce to login proactively.
function _jwtExpired(token) {
  try {
    let b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    b64 += '='.repeat((4 - (b64.length % 4)) % 4);
    const payload = JSON.parse(atob(b64));
    return typeof payload.exp === 'number' && payload.exp * 1000 <= Date.now();
  } catch (_) {
    return false;  // unparseable → let the server reject it with a 401
  }
}

function requireAuth() {
  const token = localStorage.getItem('authToken');
  if (!token || _jwtExpired(token)) {
    // No token, or it has already expired (F-092) — don't render a protected
    // page that will only 401 on its first API call; go straight to login.
    logout();
    return false;
  }
  return true;
}

function getRole() {
  return localStorage.getItem('userRole') || localStorage.getItem('role') || '';
}

// Fill sidebar user chrome + hide admin-only nav for non-admins.
function applyUserChrome() {
  const email = localStorage.getItem('userEmail') || 'admin';
  const role = getRole() || 'analyst';
  const initials = (email[0] || 'U').toUpperCase();
  document.querySelectorAll('[data-user-email]').forEach(el => { el.textContent = email; });
  document.querySelectorAll('[data-user-role]').forEach(el => { el.textContent = role; });
  document.querySelectorAll('[data-user-initials]').forEach(el => { el.textContent = initials; });
  if (role !== 'admin') {
    document.querySelectorAll('[data-admin-only]').forEach(el => { el.style.display = 'none'; });
  }
}

// ── Server-Sent Events ──────────────────────────────────────────────────
// The backend emits NAMED events (event: <type>) whose data is JSON. onEvent
// is called as onEvent(type, payload). opts.onStatus(connected:bool) reflects
// the live connection state.
const SSE_EVENT_TYPES = [
  'hello', 'scan_queued', 'scan_started', 'scan_progress', 'scan_log',
  'scan_completed', 'scan_failed', 'device_discovered', 'device_updated',
  'alert', 'alert_resolved'
];

// Opens an authenticated SSE stream. Because EventSource cannot set an
// Authorization header, we first POST for a short-lived, single-use ticket
// (sending the JWT in the header, never the URL), then open the stream with
// ?ticket=. Tickets are single-use and expire in seconds, so we transparently
// re-mint on reconnect. Returns a handle with .close().
function connectSSE(onEvent, opts = {}) {
  const base = getApiBase();
  let es = null;
  let closed = false;
  let backoff = 1000;

  const makeHandler = (type) => (e) => {
    let payload = null;
    try {
      const raw = JSON.parse(e.data);
      payload = (raw && typeof raw === 'object' && 'data' in raw) ? raw.data : raw;
    } catch (_) {
      payload = e.data;
    }
    try { onEvent(type, payload); }
    catch (err) { console.error(`SSE handler error (${type})`, err); }
  };

  async function mintTicket() {
    const token = localStorage.getItem('authToken');
    const resp = await fetch(`${base}/api/stream/ticket`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token || ''}` }
    });
    if (!resp.ok) throw new Error(`ticket HTTP ${resp.status}`);
    return (await resp.json()).ticket;
  }

  function scheduleReconnect() {
    if (closed) return;
    setTimeout(open, backoff);
    backoff = Math.min(backoff * 2, 15000);
  }

  async function open() {
    if (closed) return;
    let ticket;
    try {
      ticket = await mintTicket();
    } catch (err) {
      if (opts.onStatus) opts.onStatus(false);
      scheduleReconnect();
      return;
    }
    es = new EventSource(`${base}/api/stream?ticket=${encodeURIComponent(ticket)}`);
    es.addEventListener('open', () => {
      backoff = 1000;
      if (opts.onStatus) opts.onStatus(true);
    });
    es.onerror = () => {
      if (opts.onStatus) opts.onStatus(false);
      // The single-use ticket is already spent; tear down and reconnect with a
      // fresh one instead of letting EventSource retry the dead URL forever.
      try { es.close(); } catch (_) { /* noop */ }
      scheduleReconnect();
    };
    SSE_EVENT_TYPES.forEach(t => es.addEventListener(t, makeHandler(t)));
    es.onmessage = makeHandler('message');
  }

  open();
  return {
    close() {
      closed = true;
      if (es) { try { es.close(); } catch (_) { /* noop */ } }
    }
  };
}

// ── Authenticated file download (PDF / CSV) ──────────────────────────────
// `endpoint` includes the /api prefix, e.g. '/api/reports/<id>/pdf'.
async function downloadFile(endpoint, filename) {
  const token = localStorage.getItem('authToken');
  try {
    const resp = await fetch(`${getApiBase()}${endpoint}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  } catch (e) {
    showNotification('Download failed: ' + e.message, 'danger');
  }
}

// ── Dynamic alert badge (sidebar) ─────────────────────────────────────────
async function refreshAlertBadge() {
  try {
    const alerts = await api('/alerts?only_unresolved=true&limit=500');
    const count = Array.isArray(alerts) ? alerts.length : 0;
    document.querySelectorAll('.nav-alert-badge').forEach(b => {
      if (count > 0) { b.textContent = count; b.style.display = ''; }
      else { b.style.display = 'none'; }
    });
  } catch (_) { /* badge is best-effort */ }
}

// Escape user-supplied text before injecting into innerHTML.
function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value == null ? '' : String(value);
  return div.innerHTML;
}

// Search functionality
function initSearch() {
  const searchInput = document.querySelector('.search-box input');
  if (!searchInput) return;
  
  let debounceTimer;
  searchInput.addEventListener('input', function(e) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      // Dispatch on every change (incl. empty) so listeners can filter AND
      // reset when the box is cleared (F-090).
      performSearch(e.target.value.trim());
    }, 300);
  });
}

function performSearch(query) {
  // No global search endpoint — broadcast so a page can filter locally.
  document.dispatchEvent(new CustomEvent('globalsearch', { detail: query }));
}

document.addEventListener('DOMContentLoaded', initSearch);

// Table sorting
function sortTable(table, column, direction = 'asc') {
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  
  rows.sort((a, b) => {
    const aVal = a.cells[column].textContent.trim();
    const bVal = b.cells[column].textContent.trim();
    
    // Try numeric comparison first
    const aNum = parseFloat(aVal);
    const bNum = parseFloat(bVal);
    
    if (!isNaN(aNum) && !isNaN(bNum)) {
      return direction === 'asc' ? aNum - bNum : bNum - aNum;
    }
    
    // Fall back to string comparison
    return direction === 'asc' 
      ? aVal.localeCompare(bVal)
      : bVal.localeCompare(aVal);
  });
  
  rows.forEach(row => tbody.appendChild(row));
}

// Copy to clipboard
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showNotification('Copied to clipboard', 'success');
  } catch (error) {
    console.error('Copy failed:', error);
    showNotification('Failed to copy', 'danger');
  }
}

// Confirmation dialog.
// SECURITY: `message` is escaped before being injected — callers routinely
// build it from user-controlled data (e.g. a user's email), so raw
// interpolation here was a stored-XSS sink. The modal is also fully removed
// from the DOM on every exit path (confirm / cancel / overlay) so repeated
// use never leaves orphaned duplicate #confirmModal nodes behind.
function confirm(message, onConfirm, onCancel) {
  // Drop any stale modal so ids stay unique.
  document.getElementById('confirmModal')?.remove();

  const modalHtml = `
    <div class="modal-overlay active" id="confirmModal">
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title">Confirm Action</h3>
          <button class="btn btn-icon btn-ghost" data-confirm-cancel>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <p>${escapeHtml(message)}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" data-confirm-cancel>Cancel</button>
          <button class="btn btn-danger" id="confirmBtn">Confirm</button>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modalHtml);
  const modal = document.getElementById('confirmModal');
  const cleanup = () => modal.remove();

  modal.querySelectorAll('[data-confirm-cancel]').forEach(btn =>
    btn.addEventListener('click', () => { cleanup(); onCancel?.(); }));
  modal.addEventListener('click', (e) => {
    if (e.target === modal) { cleanup(); onCancel?.(); }
  });
  document.getElementById('confirmBtn').addEventListener('click', () => {
    cleanup();
    onConfirm?.();
  });
}

// CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
  .spinner {
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
`;
document.head.appendChild(style);
