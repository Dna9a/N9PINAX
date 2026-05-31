// admin.js — user management, activity log, and Network Binding (admin only).
(function () {
  if (!requireAuth()) return;

  // Hard guard: non-admins never see this page.
  if (getRole() !== 'admin') {
    window.location.href = 'dashboard.html';
    return;
  }

  let activityTimer = null;

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('admin');
    loadUsers();
    loadActivity();
    loadCurrentBinding();

    document.getElementById('createUserForm').addEventListener('submit', createUser);
    document.getElementById('saveBindingBtn').addEventListener('click', saveNetworkBinding);
    document.getElementById('clearBindingBtn').addEventListener('click', clearNetworkBinding);

    // Auto-refresh the activity log every 30s.
    activityTimer = setInterval(loadActivity, 30000);
    window.addEventListener('beforeunload', () => activityTimer && clearInterval(activityTimer));
  });

  // ── Users ────────────────────────────────────────────────────────────
  async function loadUsers() {
    const body = document.getElementById('usersBody');
    try {
      const users = await api('/admin/users') || [];
      if (!users.length) {
        body.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">No users.</td></tr>';
        return;
      }
      const self = localStorage.getItem('userEmail');
      body.innerHTML = users.map(u => {
        const roleBadge = u.role === 'admin' ? 'badge-danger' : 'badge-primary';
        const isSelf = u.email === self;
        const del = isSelf
          ? '<span class="text-xs text-muted">(you)</span>'
          : `<button class="btn btn-sm btn-danger" data-del="${escapeHtml(u.user_id)}" data-email="${escapeHtml(u.email)}">Delete</button>`;
        return `
          <tr>
            <td class="text-mono text-xs">${escapeHtml(u.user_id)}</td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="badge ${roleBadge}">${escapeHtml(u.role)}</span></td>
            <td>${del}</td>
          </tr>`;
      }).join('');
      body.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', () =>
        confirmDelete(b.getAttribute('data-del'), b.getAttribute('data-email'))));
    } catch (e) {
      body.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">Could not load users.</td></tr>';
    }
  }

  async function createUser(e) {
    e.preventDefault();
    const btn = document.getElementById('createUserBtn');
    const email = document.getElementById('newEmail').value.trim();
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newRole').value;
    btn.disabled = true;
    try {
      await api('/admin/users', { method: 'POST', body: JSON.stringify({ email, password, role }) });
      showNotification(`User ${email} created`, 'success');
      document.getElementById('createUserForm').reset();
      loadUsers();
    } catch (err) {
      showNotification('Create failed: ' + err.message, 'danger');
    } finally {
      btn.disabled = false;
    }
  }

  function confirmDelete(userId, email) {
    confirm(`Delete user "${email}"? This cannot be undone.`, async () => {
      try {
        await api(`/admin/users/${userId}`, { method: 'DELETE' });
        showNotification('User deleted', 'success');
        loadUsers();
      } catch (err) {
        showNotification('Delete failed: ' + err.message, 'danger');
      }
    });
  }

  // ── Activity log ─────────────────────────────────────────────────────
  async function loadActivity() {
    const body = document.getElementById('activityBody');
    try {
      const rows = await api('/admin/activity?limit=200') || [];
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No activity yet.</td></tr>';
        return;
      }
      body.innerHTML = rows.map(r => `
        <tr>
          <td class="text-sm text-muted whitespace-nowrap">${escapeHtml(formatDate(r.timestamp))}</td>
          <td>${escapeHtml(r.user_email || '')}</td>
          <td><span class="badge badge-secondary">${escapeHtml(r.action || '')}</span></td>
          <td class="text-sm">${escapeHtml(r.detail || '')}</td>
          <td class="text-mono text-xs">${escapeHtml(r.ip || '')}</td>
        </tr>`).join('');
    } catch (e) {
      body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Could not load activity.</td></tr>';
    }
  }

  // ── Network Binding ──────────────────────────────────────────────────
  function loadCurrentBinding() {
    const saved = localStorage.getItem('apiBaseUrl');
    const el = document.getElementById('currentBinding');
    if (saved) {
      el.innerHTML = `<span class="badge badge-success">Bound to: ${escapeHtml(saved)}</span>`;
      document.getElementById('platformIp').value = saved.replace('http://', '').replace(':8000', '');
    } else {
      el.innerHTML = '<span class="badge badge-secondary">Auto (current host)</span>';
    }
  }

  function saveNetworkBinding() {
    const input = document.getElementById('platformIp').value.trim();
    if (!input) { clearNetworkBinding(); return; }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
    if (!ipRegex.test(input)) {
      showNotification('Enter a valid IP address (e.g. 192.168.1.50)', 'danger');
      return;
    }
    const port = input.includes(':') ? '' : ':8000';
    const baseUrl = `http://${input}${port}`;
    localStorage.setItem('apiBaseUrl', baseUrl);
    showNotification(`Platform IP set to ${baseUrl} — reconnecting…`, 'success');
    loadCurrentBinding();

    setTimeout(async () => {
      try {
        await fetch(`${baseUrl}/api/health`);
        showNotification('Connection to new IP confirmed ✓', 'success');
      } catch (_) {
        showNotification('Warning: could not reach the platform at that IP. Check the address.', 'warning');
      }
    }, 500);
  }

  function clearNetworkBinding() {
    localStorage.removeItem('apiBaseUrl');
    document.getElementById('platformIp').value = '';
    loadCurrentBinding();
    showNotification('Reset to default (auto)', 'info');
  }
})();
