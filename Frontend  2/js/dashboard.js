// dashboard.js — wires the dashboard to the live API + SSE.
(function () {
  if (!requireAuth()) return;

  let vendorChart = null;
  let portChart = null;
  let lastDevices = [];   // most recent scan's devices, for the top search box

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('dashboard');
    loadDashboard();
    startSSE();
    document.getElementById('quickScanBtn').addEventListener('click', quickScan);
    // Wire the top search box (F-090): filter the recent-devices table live.
    document.addEventListener('globalsearch', (e) => {
      const q = (e.detail || '').toLowerCase();
      const filtered = !q ? lastDevices : lastDevices.filter(d =>
        [d.ip, d.hostname, d.vendor, d.mac].some(v => (v || '').toLowerCase().includes(q)));
      renderRecentDevices(filtered);
    });
  });

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function relativeTime(iso) {
    if (!iso) return '—';
    const then = new Date(iso).getTime();
    const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  async function loadDashboard() {
    // Unresolved alerts (also drives the sidebar badge).
    try {
      // Fetch the full unresolved set so the stat tile matches the sidebar
      // badge (QA-011); only the newest few are rendered in the feed.
      const alerts = await api('/alerts?only_unresolved=true&limit=500');
      const list = Array.isArray(alerts) ? alerts : [];
      setText('statAlerts', list.length);
      renderRecentAlerts(list.slice(0, 5));
    } catch (e) {
      setText('statAlerts', '—');
      renderRecentAlerts([]);
    }

    // Last scan → stats, charts, devices.
    let scan = null;
    try {
      scan = await api('/scans/last');
    } catch (e) {
      // Distinguish "no data yet" (404) from a real failure (F-097).
      if ((e.message || '').toLowerCase().includes('no scans')) {
        emptyState();
      } else {
        errorState(e.message);
      }
      return;
    }
    renderScan(scan);
  }

  function errorState(msg) {
    ['statTotalDevices', 'statOnline', 'statOpenPorts', 'statHighRisk',
     'riskLow', 'riskMedium', 'riskHigh'].forEach(id => setText(id, '—'));
    setText('statLastScan', 'error');
    document.getElementById('recentDevices').innerHTML =
      `<tr><td colspan="4" class="text-center text-muted py-4">Could not load dashboard data: ${escapeHtml(msg || 'unknown error')}</td></tr>`;
  }

  function emptyState() {
    setText('statTotalDevices', 0);
    setText('statOnline', 0);
    setText('statOpenPorts', 0);
    setText('statLastScan', 'never');
    setText('statHighRisk', 0);
    setText('riskLow', 0); setText('riskMedium', 0); setText('riskHigh', 0);
    document.getElementById('recentDevices').innerHTML =
      '<tr><td colspan="4" class="text-center text-muted py-4">No scans yet — run a Quick Scan to begin.</td></tr>';
  }

  function renderScan(scan) {
    const devices = scan.devices || [];
    const online = devices.filter(d => d.is_online).length;
    const openPorts = devices.reduce((n, d) => n + (d.open_ports ? d.open_ports.length : 0), 0);
    const risk = { low: 0, medium: 0, high: 0 };
    devices.forEach(d => { risk[d.risk] = (risk[d.risk] || 0) + 1; });

    setText('statTotalDevices', scan.total_hosts != null ? scan.total_hosts : devices.length);
    setText('statOnline', online);
    setText('statOpenPorts', openPorts);
    setText('statLastScan', relativeTime(scan.timestamp));
    setText('statHighRisk', risk.high);
    setText('riskLow', risk.low);
    setText('riskMedium', risk.medium);
    setText('riskHigh', risk.high);

    lastDevices = devices;
    renderRecentDevices(devices);
    renderCharts(devices);
  }

  function renderRecentDevices(devices) {
    const tbody = document.getElementById('recentDevices');
    if (!devices.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">No devices.</td></tr>';
      return;
    }
    const badge = { low: 'badge-success', medium: 'badge-warning', high: 'badge-danger' };
    tbody.innerHTML = devices.slice(0, 6).map(d => `
      <tr>
        <td class="text-mono">${escapeHtml(d.ip)}</td>
        <td>${escapeHtml(d.hostname || 'unknown')}</td>
        <td><span class="badge ${badge[d.risk] || 'badge-secondary'}">${escapeHtml(d.risk || 'low')}</span></td>
        <td>${d.open_ports ? d.open_ports.length : 0}</td>
      </tr>`).join('');
  }

  function renderRecentAlerts(alerts) {
    const box = document.getElementById('recentAlerts');
    if (!alerts.length) {
      box.innerHTML = '<div class="text-muted text-sm">No unresolved alerts 🎉</div>';
      return;
    }
    const dot = { critical: 'danger', high: 'danger', medium: 'warning', low: 'primary' };
    box.innerHTML = alerts.map(a => `
      <div class="timeline-item">
        <div class="timeline-dot ${dot[a.severity] || 'primary'}"></div>
        <div class="timeline-content">
          <div class="timeline-title">${escapeHtml(a.title)}</div>
          <div class="timeline-time">${escapeHtml(a.severity)} · ${escapeHtml(a.ip || '')} · ${relativeTime(a.timestamp)}</div>
        </div>
      </div>`).join('');
  }

  function renderCharts(devices) {
    const themed = (v) => getComputedStyle(document.documentElement).getPropertyValue(v);
    // Vendor distribution.
    const vendors = {};
    devices.forEach(d => { const v = d.vendor || 'Unknown'; vendors[v] = (vendors[v] || 0) + 1; });
    const vLabels = Object.keys(vendors).slice(0, 6);
    const vData = vLabels.map(l => vendors[l]);

    // Top open ports.
    const ports = {};
    devices.forEach(d => (d.open_ports || []).forEach(p => { ports[p.number] = (ports[p.number] || 0) + 1; }));
    const pSorted = Object.entries(ports).sort((a, b) => b[1] - a[1]).slice(0, 6);

    if (vendorChart) vendorChart.destroy();
    if (portChart) portChart.destroy();

    vendorChart = new Chart(document.getElementById('vendorChart'), {
      type: 'doughnut',
      data: { labels: vLabels.length ? vLabels : ['No data'], datasets: [{
        data: vData.length ? vData : [1],
        backgroundColor: ['rgba(14,165,233,.8)','rgba(34,197,94,.8)','rgba(245,158,11,.8)','rgba(168,85,247,.8)','rgba(239,68,68,.8)','rgba(107,114,128,.8)'],
        borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: themed('--text-secondary'), padding: 16, usePointStyle: true } } } }
    });

    portChart = new Chart(document.getElementById('portChart'), {
      type: 'bar',
      data: { labels: pSorted.length ? pSorted.map(p => p[0]) : ['No data'], datasets: [{
        label: 'Hosts', data: pSorted.length ? pSorted.map(p => p[1]) : [0],
        backgroundColor: 'rgba(14,165,233,.8)', borderRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
        scales: { x: { grid: { display: false }, ticks: { color: themed('--text-muted') } },
                  y: { grid: { color: themed('--border-primary') }, ticks: { color: themed('--text-muted') } } } }
    });
  }

  function startSSE() {
    connectSSE((type, payload) => {
      if (type === 'scan_completed') {
        showNotification('Scan completed — refreshing dashboard', 'success');
        loadDashboard();
      } else if (type === 'alert' || type === 'alert_resolved') {
        refreshAlertBadge();
        loadDashboard();
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

  async function quickScan() {
    const btn = document.getElementById('quickScanBtn');
    btn.disabled = true;
    try {
      const job = await api('/scan', { method: 'POST', body: JSON.stringify({}) });
      showNotification('Scan queued — watch the live feed on the Scan page', 'info');
      pollJob(job.job_id, btn);
    } catch (e) {
      showNotification('Could not start scan: ' + e.message, 'danger');
      btn.disabled = false;
    }
  }

  async function pollJob(jobId, btn) {
    // Cap polling so a hung/never-completing job can't poll forever (F-096):
    // 150 × 2s ≈ 5 minutes, then give up and re-enable the button.
    const MAX_ATTEMPTS = 150;
    let attempts = 0;
    const tick = async () => {
      try {
        const job = await api(`/jobs/${jobId}`);
        if (job.status === 'completed') {
          showNotification('Scan finished', 'success');
          btn.disabled = false;
          loadDashboard();
          return;
        }
        if (job.status === 'failed') {
          showNotification('Scan failed: ' + (job.error || 'unknown'), 'danger');
          btn.disabled = false;
          return;
        }
        if (++attempts >= MAX_ATTEMPTS) {
          showNotification('Scan is taking longer than expected — check the Scan page.', 'warning');
          btn.disabled = false;
          return;
        }
        setTimeout(tick, 2000);
      } catch (e) {
        btn.disabled = false;
      }
    };
    setTimeout(tick, 2000);
  }
})();
