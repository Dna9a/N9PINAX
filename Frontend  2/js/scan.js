// scan.js — scan control with live SSE log, progress, and device feed.
(function () {
  if (!requireAuth()) return;

  const RISK_BADGE = { low: 'badge-success', medium: 'badge-warning', high: 'badge-danger' };
  let activeJobId = null;
  let startedAt = null;
  let elapsedTimer = null;
  let completedScanId = null;    // scan_id from the most-recent scan_completed event
  const liveDevices = new Map(); // mac -> device

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('scan');
    loadHistory();
    startSSE();
    document.getElementById('scanForm').addEventListener('submit', onSubmit);
    document.getElementById('stopScanBtn').addEventListener('click', resetView);
    document.getElementById('clearLogBtn').addEventListener('click', clearLog);
    document.getElementById('exportJsonBtn').addEventListener('click', () => {
      if (completedScanId)
        downloadFile(`/api/scan/${completedScanId}/export/json`, `scan_${completedScanId.slice(0, 8)}.json`);
    });
    document.getElementById('exportCsvBtn').addEventListener('click', () => {
      if (completedScanId)
        downloadFile(`/api/scan/${completedScanId}/export/csv`, `scan_${completedScanId.slice(0, 8)}.csv`);
    });
    document.getElementById('exportPdfBtn').addEventListener('click', () => {
      if (completedScanId)
        downloadFile(`/api/scan/${completedScanId}/export/pdf`, `scan_${completedScanId.slice(0, 8)}.pdf`);
    });
  });

  // Strip ANSI colour escape codes the CLI emits (QA-022) so the live log
  // shows clean text instead of raw "\x1b[44m…" sequences.
  function stripAnsi(s) {
    return String(s == null ? '' : s).replace(/\x1b\[[0-9;]*m/g, '');
  }

  function logLine(message, type) {
    const log = document.getElementById('scanLog');
    const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
    const div = document.createElement('div');
    div.className = 'console-line';
    div.innerHTML = `<span class="console-time">[${time}]</span><span class="console-message ${type || ''}">${escapeHtml(stripAnsi(message))}</span>`;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function clearLog() {
    document.getElementById('scanLog').innerHTML =
      '<div class="console-line"><span class="console-time">[--:--:--]</span><span class="console-message">Log cleared</span></div>';
  }

  function setRunning(running) {
    document.getElementById('startScanBtn').disabled = running;
    document.getElementById('startScanBtn').classList.toggle('hidden', running);
    document.getElementById('stopScanBtn').classList.toggle('hidden', !running);
    document.getElementById('scanProgress').classList.toggle('hidden', !running);
    // Disable export buttons while a scan is in progress.
    ['exportJsonBtn', 'exportCsvBtn', 'exportPdfBtn'].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = running || !completedScanId;
    });
    if (running) {
      document.getElementById('summaryCard').classList.add('hidden');
      startedAt = Date.now();
      elapsedTimer = setInterval(updateElapsed, 1000);
    } else if (elapsedTimer) {
      clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
  }

  function updateElapsed() {
    if (!startedAt) return;
    const s = Math.floor((Date.now() - startedAt) / 1000);
    const m = String(Math.floor(s / 60)).padStart(2, '0');
    document.getElementById('elapsedTime').textContent = `${m}:${String(s % 60).padStart(2, '0')}`;
  }

  async function onSubmit(e) {
    e.preventDefault();
    if (activeJobId) { showNotification('A scan is already running', 'warning'); return; }

    const body = {
      network: document.getElementById('targetRange').value.trim() || null,
      resolve_hostnames: document.getElementById('optResolve').checked,
      udp: document.getElementById('optUdp').checked,
      dhcp: document.getElementById('optDhcp').checked
    };

    // Reset live state.
    liveDevices.clear();
    renderLiveDevices();
    document.getElementById('progressBar').style.width = '5%';
    document.getElementById('devicesFound').textContent = '0';
    document.getElementById('stepLabel').textContent = 'queued';

    try {
      const job = await api('/scan', { method: 'POST', body: JSON.stringify(body) });
      activeJobId = job.job_id;
      document.getElementById('jobInfo').textContent = `Job ${job.job_id} — ${job.status}`;
      document.getElementById('scanStatusText').textContent = 'Scanning…';
      setRunning(true);
      logLine(`Scan queued (job ${job.job_id})`, 'info');
    } catch (err) {
      const msg = err.message || 'failed';
      logLine('Failed to start scan: ' + msg, 'danger');
      showNotification('Could not start scan: ' + msg, 'danger');
    }
  }

  function resetView() {
    // Server-side scans cannot be cancelled; this just clears the local view.
    activeJobId = null;
    setRunning(false);
    document.getElementById('jobInfo').textContent = '';
    showNotification('View reset (a running server scan continues in the background)', 'info');
  }

  function upsertDevice(d) {
    if (!d || !d.mac) return;
    liveDevices.set(d.mac, d);
    document.getElementById('devicesFound').textContent = liveDevices.size;
    document.getElementById('deviceCount').textContent = `${liveDevices.size} devices`;
    renderLiveDevices();
  }

  function renderLiveDevices() {
    const tbody = document.getElementById('liveDevices');
    if (!liveDevices.size) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">No devices yet</td></tr>';
      return;
    }
    tbody.innerHTML = [...liveDevices.values()].map(d => `
      <tr>
        <td class="text-mono">${escapeHtml(d.ip)}</td>
        <td class="text-mono text-xs">${escapeHtml(d.mac)}</td>
        <td>${escapeHtml(d.vendor || 'Unknown')}</td>
        <td><span class="badge ${RISK_BADGE[d.risk] || 'badge-secondary'}">${escapeHtml(d.risk || 'low')}</span></td>
      </tr>`).join('');
  }

  function startSSE() {
    connectSSE((type, payload) => {
      // Only react to events for the scan THIS page started. A job-scoped event
      // for any other job (e.g. another operator's scan) must not drive this
      // page's progress/status — that left it stuck on "Scanning…" (QA-021).
      if (payload && payload.job_id && payload.job_id !== activeJobId) return;
      switch (type) {
        case 'scan_log':
          if (payload && payload.line) logLine(payload.line);
          break;
        case 'scan_progress':
          if (payload) {
            document.getElementById('stepLabel').textContent = `${payload.step || ''} (${payload.state || ''})`;
            bumpProgress();
          }
          break;
        case 'scan_started':
          document.getElementById('scanStatusText').textContent = 'Scanning…';
          document.getElementById('progressBar').style.width = '10%';
          break;
        case 'device_discovered':
        case 'device_updated':
          upsertDevice(payload);
          break;
        case 'scan_completed':
          onCompleted(payload);
          break;
        case 'scan_failed':
          logLine('Scan failed: ' + (payload && payload.error ? payload.error : 'unknown'), 'danger');
          showNotification('Scan failed', 'danger');
          activeJobId = null;
          setRunning(false);
          break;
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

  let progress = 10;
  function bumpProgress() {
    progress = Math.min(95, progress + 6);
    document.getElementById('progressBar').style.width = progress + '%';
  }

  function onCompleted(payload) {
    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('scanStatusText').textContent = 'Scan complete';
    logLine('Scan completed.', 'success');
    activeJobId = null;
    setRunning(false);
    progress = 10;
    if (payload) {
      completedScanId = payload.scan_id || null;
      const dur = payload.duration_seconds != null ? payload.duration_seconds.toFixed(1) + 's' : '—';
      document.getElementById('summaryText').textContent =
        `Found ${payload.total_hosts} host(s) in ${dur} · ${payload.alerts} alert(s) raised.`;
      document.getElementById('summaryCard').classList.remove('hidden');
      // Enable export buttons now that we have a scan_id.
      if (completedScanId) {
        ['exportJsonBtn', 'exportCsvBtn', 'exportPdfBtn'].forEach(id => {
          const btn = document.getElementById(id);
          if (btn) btn.disabled = false;
        });
      }
    }
    loadHistory();
    refreshAlertBadge();
  }

  async function loadHistory() {
    const tbody = document.getElementById('scanHistory');
    try {
      const scans = await api('/scans?limit=10');
      if (!scans || !scans.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">No scans yet.</td></tr>';
        return;
      }
      tbody.innerHTML = scans.map(s => `
        <tr>
          <td class="text-sm">${escapeHtml(formatDate(s.timestamp))}</td>
          <td class="text-mono text-sm">${escapeHtml(s.network)}</td>
          <td>${s.total_hosts}</td>
          <td>${s.duration_seconds != null ? Number(s.duration_seconds).toFixed(1) + 's' : '—'}</td>
        </tr>`).join('');
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">Could not load history.</td></tr>';
    }
  }
})();
