// devices.js — device inventory from the most recent scan, with filtering and
// expandable per-device port details.
(function () {
  if (!requireAuth()) return;

  let allDevices = [];
  const RISK_BADGE = { low: 'badge-success', medium: 'badge-warning', high: 'badge-danger' };

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('devices');
    loadDevices();
    document.getElementById('deviceSearch').addEventListener('input', render);
    document.getElementById('riskFilter').addEventListener('change', render);
    document.getElementById('refreshScanBtn').addEventListener('click', rescan);
    connectSSE((type) => { if (type === 'scan_completed') loadDevices(); });
  });

  async function loadDevices() {
    const body = document.getElementById('devicesBody');
    body.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">Loading…</td></tr>';
    try {
      const scan = await api('/scans/last');
      allDevices = scan.devices || [];
    } catch (e) {
      allDevices = [];
      const noData = (e.message || '').toLowerCase().includes('no scans');
      body.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">${
        noData ? 'No scans yet — click Rescan to discover devices.'
               : 'Could not load devices: ' + escapeHtml(e.message || 'unknown error')}</td></tr>`;
      setStats();
      return;
    }
    setStats();
    render();
  }

  function setStats() {
    const online = allDevices.filter(d => d.is_online).length;
    const high = allDevices.filter(d => d.risk === 'high').length;
    document.getElementById('statTotal').textContent = allDevices.length;
    document.getElementById('statOnline').textContent = online;
    document.getElementById('statOffline').textContent = allDevices.length - online;
    document.getElementById('statHigh').textContent = high;
  }

  function render() {
    const q = document.getElementById('deviceSearch').value.trim().toLowerCase();
    const risk = document.getElementById('riskFilter').value;
    const body = document.getElementById('devicesBody');

    const filtered = allDevices.filter(d => {
      if (risk !== 'all' && d.risk !== risk) return false;
      if (!q) return true;
      return [d.ip, d.hostname, d.vendor, d.mac].some(v => (v || '').toLowerCase().includes(q));
    });

    document.getElementById('deviceCount').textContent =
      `Showing ${filtered.length} of ${allDevices.length} devices`;

    if (!filtered.length) {
      body.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No matching devices.</td></tr>';
      return;
    }

    body.innerHTML = filtered.map((d, i) => {
      const ports = d.open_ports || [];
      const portDetail = ports.length
        ? `<div class="table-container"><table class="table"><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Banner</th></tr></thead><tbody>${
            ports.map(p => `<tr><td class="text-mono">${p.number}</td><td>${escapeHtml(p.protocol)}</td><td>${escapeHtml(p.service || '')}</td><td class="text-xs text-muted">${escapeHtml(p.banner || '')}</td></tr>`).join('')
          }</tbody></table></div>`
        : '<div class="text-muted text-sm">No open ports.</div>';
      return `
        <tr class="device-row" data-idx="${i}" style="cursor:pointer" role="button" tabindex="0" aria-expanded="false" aria-label="Toggle port details for ${escapeHtml(d.ip)}">
          <td class="text-mono">${escapeHtml(d.ip)}</td>
          <td class="text-mono text-xs">${escapeHtml(d.mac)}</td>
          <td>${escapeHtml(d.vendor || 'Unknown')}</td>
          <td>${escapeHtml(d.hostname || 'unknown')}</td>
          <td>${escapeHtml(d.os_family || 'Unknown')}${d.os_version ? ' ' + escapeHtml(d.os_version) : ''}</td>
          <td>${escapeHtml(d.device_type || 'Unknown')}</td>
          <td><span class="badge ${RISK_BADGE[d.risk] || 'badge-secondary'}">${escapeHtml(d.risk || 'low')}</span></td>
          <td>${ports.length}</td>
        </tr>
        <tr class="device-detail hidden" data-detail="${i}"><td colspan="8">${portDetail}</td></tr>`;
    }).join('');

    const toggleRow = (row) => {
      const idx = row.getAttribute('data-idx');
      const detail = body.querySelector(`[data-detail="${idx}"]`);
      if (!detail) return;
      const nowOpen = detail.classList.toggle('hidden') === false;
      row.setAttribute('aria-expanded', String(nowOpen));
    };
    body.querySelectorAll('.device-row').forEach(row => {
      row.addEventListener('click', () => toggleRow(row));
      // Keyboard support (F-098): Enter / Space activate like a button.
      row.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          e.preventDefault();
          toggleRow(row);
        }
      });
    });
  }

  async function rescan() {
    const btn = document.getElementById('refreshScanBtn');
    btn.disabled = true;
    try {
      const job = await api('/scan', { method: 'POST', body: JSON.stringify({}) });
      showNotification('Rescan started…', 'info');
      const tick = async () => {
        try {
          const j = await api(`/jobs/${job.job_id}`);
          if (j.status === 'completed') { showNotification('Rescan complete', 'success'); btn.disabled = false; loadDevices(); return; }
          if (j.status === 'failed') { showNotification('Scan failed: ' + (j.error || ''), 'danger'); btn.disabled = false; return; }
          setTimeout(tick, 2000);
        } catch (e) { btn.disabled = false; }
      };
      setTimeout(tick, 2000);
    } catch (e) {
      showNotification('Could not start scan: ' + e.message, 'danger');
      btn.disabled = false;
    }
  }
})();
