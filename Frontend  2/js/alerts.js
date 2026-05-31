// alerts.js — alert table with severity/resolved filters, resolve action, and
// live SSE updates.
(function () {
  if (!requireAuth()) return;

  const SEV_BADGE = {
    critical: 'badge-danger',
    high: 'badge-warning',
    medium: 'badge-primary',
    low: 'badge-secondary'
  };
  let alerts = [];

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('alerts');
    load();
    document.getElementById('severityFilter').addEventListener('change', load);
    document.getElementById('unresolvedOnly').addEventListener('change', load);
    document.getElementById('alertSearch').addEventListener('input', render);
    startSSE();
  });

  async function load() {
    const body = document.getElementById('alertsBody');
    body.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">Loading…</td></tr>';
    const sev = document.getElementById('severityFilter').value;
    const unresolved = document.getElementById('unresolvedOnly').checked;
    let qs = '/alerts?limit=100';
    if (sev) qs += `&severity=${encodeURIComponent(sev)}`;
    if (unresolved) qs += '&only_unresolved=true';
    try {
      alerts = await api(qs) || [];
    } catch (e) {
      alerts = [];
      body.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">Could not load alerts.</td></tr>';
      return;
    }
    render();
  }

  function render() {
    const q = document.getElementById('alertSearch').value.trim().toLowerCase();
    const body = document.getElementById('alertsBody');
    const rows = alerts.filter(a => !q ||
      [a.title, a.description, a.ip].some(v => (v || '').toLowerCase().includes(q)));

    document.getElementById('alertCount').textContent = `${rows.length} alert(s)`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No alerts.</td></tr>';
      return;
    }
    body.innerHTML = rows.map(a => {
      const resolved = a.resolved;
      const status = resolved
        ? '<span class="badge badge-success">Resolved</span>'
        : '<span class="badge badge-secondary">Open</span>';
      const action = resolved
        ? ''
        : `<button class="btn btn-sm btn-secondary" data-resolve="${escapeHtml(a.alert_id)}">Resolve</button>`;
      return `
        <tr data-alert="${escapeHtml(a.alert_id)}" style="${resolved ? 'opacity:.6' : ''}">
          <td><span class="badge ${SEV_BADGE[a.severity] || 'badge-secondary'}">${escapeHtml(a.severity)}</span></td>
          <td>${escapeHtml(a.title)}</td>
          <td class="text-sm text-secondary">${escapeHtml(a.description || '')}</td>
          <td class="text-mono text-sm">${escapeHtml(a.ip || '—')}</td>
          <td class="text-sm text-muted">${escapeHtml(formatDate(a.timestamp))}</td>
          <td>${status}</td>
          <td>${action}</td>
        </tr>`;
    }).join('');

    body.querySelectorAll('[data-resolve]').forEach(btn => {
      btn.addEventListener('click', () => resolve(btn.getAttribute('data-resolve'), btn));
    });
  }

  async function resolve(alertId, btn) {
    btn.disabled = true;
    try {
      await api(`/alerts/${alertId}/resolve`, { method: 'POST' });
      const a = alerts.find(x => x.alert_id === alertId);
      if (a) a.resolved = true;
      showNotification('Alert resolved', 'success');
      render();
      refreshAlertBadge();
    } catch (e) {
      showNotification('Failed to resolve: ' + e.message, 'danger');
      btn.disabled = false;
    }
  }

  function startSSE() {
    connectSSE((type, payload) => {
      if (type === 'alert') {
        // Prepend new alert if not already present.
        if (payload && payload.alert_id && !alerts.some(a => a.alert_id === payload.alert_id)) {
          alerts.unshift(payload);
          render();
          refreshAlertBadge();
        }
      } else if (type === 'alert_resolved') {
        const id = payload && payload.alert_id;
        const a = alerts.find(x => x.alert_id === id);
        if (a) { a.resolved = true; render(); refreshAlertBadge(); }
      }
    }, {
      onStatus: (up) => {
        const dot = document.getElementById('sseDot');
        const label = document.getElementById('sseLabel');
        if (dot) dot.className = 'status-dot ' + (up ? 'online' : 'offline');
        if (label) label.textContent = up ? 'live' : 'disconnected';
      }
    });
  }
})();
