// notes.js — notes list + editor with debounced autosave and PDF export.
(function () {
  if (!requireAuth()) return;

  let notes = [];
  let current = null;       // currently-edited note object
  let dirty = false;        // unsaved local changes
  let saveTimer = null;
  const AUTOSAVE_MS = 2000;

  document.addEventListener('DOMContentLoaded', () => {
    mountSidebar('notes');
    loadScans();
    loadNotes();
    document.getElementById('newNoteBtn').addEventListener('click', newNote);
    document.getElementById('exportAllBtn').addEventListener('click', exportAll);
    document.getElementById('noteSearch').addEventListener('input', renderList);
    document.getElementById('exportNoteBtn').addEventListener('click', exportCurrent);
    document.getElementById('deleteNoteBtn').addEventListener('click', deleteCurrent);
    ['noteTitle', 'noteContent', 'tagInput', 'noteScan'].forEach(id =>
      document.getElementById(id).addEventListener('input', onEdit));
    document.getElementById('noteScan').addEventListener('change', onEdit);
    document.getElementById('tagInput').addEventListener('input', renderChips);
    // Flush a pending save if the user leaves.
    window.addEventListener('beforeunload', () => { if (dirty) saveNow(); });
  });

  function setStatus(text) {
    const el = document.getElementById('saveStatus');
    if (el) el.textContent = text;
  }

  async function loadScans() {
    try {
      const scans = await api('/scans?limit=50') || [];
      const sel = document.getElementById('noteScan');
      scans.forEach(s => {
        const o = document.createElement('option');
        o.value = s.scan_id;
        o.textContent = `${(s.scan_id || '').slice(0, 8)}… · ${s.network}`;
        sel.appendChild(o);
      });
    } catch (_) { /* optional */ }
  }

  async function loadNotes() {
    try {
      notes = await api('/notes') || [];
    } catch (e) {
      notes = [];
    }
    renderList();
  }

  function renderList() {
    const q = (document.getElementById('noteSearch').value || '').trim().toLowerCase();
    const box = document.getElementById('noteList');
    const rows = notes.filter(n => !q ||
      [n.title, n.content].some(v => (v || '').toLowerCase().includes(q)));
    if (!rows.length) {
      box.innerHTML = '<div class="text-muted text-sm p-4">No notes yet. Click “New Note”.</div>';
      return;
    }
    box.innerHTML = rows.map(n => {
      const active = current && n.note_id === current.note_id ? ' style="background:var(--bg-tertiary)"' : '';
      const preview = (n.content || '').slice(0, 60).replace(/\n/g, ' ');
      return `
        <div class="note-list-item" data-id="${escapeHtml(n.note_id)}"${active}
             style="padding:.75rem 1rem; border-bottom:1px solid var(--border-primary); cursor:pointer;">
          <div class="font-medium text-sm">${escapeHtml(n.title || 'Untitled')}</div>
          <div class="text-xs text-muted">${escapeHtml(preview)}</div>
        </div>`;
    }).join('');
    box.querySelectorAll('.note-list-item').forEach(el =>
      el.addEventListener('click', () => selectNote(el.getAttribute('data-id'))));
  }

  async function selectNote(id) {
    if (dirty) await saveNow();
    const note = notes.find(n => n.note_id === id);
    if (!note) return;
    current = note;
    document.getElementById('editorEmpty').classList.add('hidden');
    document.getElementById('editor').classList.remove('hidden');
    document.getElementById('noteTitle').value = note.title || '';
    document.getElementById('noteContent').value = note.content || '';
    document.getElementById('tagInput').value = (note.tags || []).join(', ');
    document.getElementById('noteScan').value = note.scan_id || '';
    renderChips();
    dirty = false;
    setStatus('Saved');
    renderList();
  }

  async function newNote() {
    try {
      const note = await api('/notes', { method: 'POST', body: JSON.stringify({ title: 'Untitled', content: '' }) });
      notes.unshift(note);
      renderList();
      selectNote(note.note_id);
      refreshAlertBadge();
    } catch (e) {
      showNotification('Could not create note: ' + e.message, 'danger');
    }
  }

  function parseTags() {
    return document.getElementById('tagInput').value
      .split(',').map(t => t.trim()).filter(Boolean);
  }

  function renderChips() {
    const chips = document.getElementById('tagChips');
    chips.innerHTML = parseTags().map(t => `<span class="badge badge-secondary">${escapeHtml(t)}</span>`).join('');
  }

  function onEdit() {
    if (!current) return;
    dirty = true;
    setStatus('Unsaved…');
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, AUTOSAVE_MS);
  }

  async function saveNow() {
    if (!current || !dirty) return;
    if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
    const payload = {
      title: document.getElementById('noteTitle').value,
      content: document.getElementById('noteContent').value,
      tags: parseTags(),
      scan_id: document.getElementById('noteScan').value || null
    };
    setStatus('Saving…');
    try {
      const updated = await api(`/notes/${current.note_id}`, { method: 'PATCH', body: JSON.stringify(payload) });
      // Reflect saved state locally.
      Object.assign(current, updated);
      dirty = false;
      setStatus('Saved');
      renderList();
    } catch (e) {
      // Per spec: warn and KEEP dirty so the change is retried / not lost.
      setStatus('Unsaved (save failed)');
      showNotification('Auto-save failed — will retry on next edit', 'warning');
    }
  }

  function exportCurrent() {
    if (!current) return;
    downloadFile(`/api/notes/${current.note_id}/pdf`, `note_${current.note_id.slice(0, 8)}.pdf`);
  }

  function exportAll() {
    downloadFile('/api/notes/export/pdf', 'notes.pdf');
  }

  function deleteCurrent() {
    if (!current) return;
    const id = current.note_id;
    confirm('Delete this note? This cannot be undone.', async () => {
      try {
        await api(`/notes/${id}`, { method: 'DELETE' });
        notes = notes.filter(n => n.note_id !== id);
        current = null;
        dirty = false;
        document.getElementById('editor').classList.add('hidden');
        document.getElementById('editorEmpty').classList.remove('hidden');
        renderList();
        showNotification('Note deleted', 'success');
      } catch (e) {
        showNotification('Delete failed: ' + e.message, 'danger');
      }
    });
  }
})();
