// reports.js — list scans and offer authenticated PDF / CSV downloads.
(function () {
  if (!requireAuth()) return;

  let reports = [];

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('reports');
    load();
    document.getElementById('reportSearch').addEventListener('input', render);
  });

  async function load() {
    const body = document.getElementById('reportsBody');
    try {
      const data = await api('/reports') || [];
      // parse_reports returns oldest→newest; show newest first.
      reports = data.slice().reverse();
    } catch (e) {
      body.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">Could not load reports.</td></tr>';
      return;
    }
    render();
  }

  function render() {
    const q = (document.getElementById('reportSearch').value || '').trim().toLowerCase();
    const body = document.getElementById('reportsBody');
    const rows = reports.filter(r => !q ||
      [r.scan_id, r.network].some(v => (v || '').toLowerCase().includes(q)));

    document.getElementById('reportCount').textContent = `${rows.length} report(s)`;
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No reports yet — run a scan first.</td></tr>';
      return;
    }
    body.innerHTML = rows.map(r => `
      <tr>
        <td class="text-mono text-sm">${escapeHtml((r.scan_id || '').slice(0, 8))}…</td>
        <td class="text-mono text-sm">${escapeHtml(r.network || '')}</td>
        <td>${r.total_hosts != null ? r.total_hosts : '—'}</td>
        <td class="text-sm text-muted">${escapeHtml(r.timestamp ? formatDate(r.timestamp) : '')}</td>
        <td>${r.duration_seconds != null ? Number(r.duration_seconds).toFixed(1) + 's' : '—'}</td>
        <td>
          <div class="flex gap-1">
            <button class="btn btn-sm btn-secondary" data-json="${escapeHtml(r.scan_id)}">JSON</button>
            <button class="btn btn-sm btn-secondary" data-csv="${escapeHtml(r.scan_id)}">CSV</button>
            <button class="btn btn-sm btn-secondary" data-pdf="${escapeHtml(r.scan_id)}">PDF</button>
          </div>
        </td>
      </tr>`).join('');

    body.querySelectorAll('[data-json]').forEach(b => b.addEventListener('click', () => {
      const id = b.getAttribute('data-json');
      downloadFile(`/api/scan/${id}/export/json`, `scan_${id.slice(0, 8)}.json`);
    }));
    body.querySelectorAll('[data-csv]').forEach(b => b.addEventListener('click', () => {
      const id = b.getAttribute('data-csv');
      downloadFile(`/api/scans/${id}/csv`, `scan_${id.slice(0, 8)}.csv`);
    }));
    body.querySelectorAll('[data-pdf]').forEach(b => b.addEventListener('click', () => {
      const id = b.getAttribute('data-pdf');
      downloadFile(`/api/reports/${id}/pdf`, `scan_${id.slice(0, 8)}.pdf`);
    }));
  }
})();
