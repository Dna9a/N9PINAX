// chrome.js — shared sidebar rendering so every page has identical nav
// (Dashboard, Devices, Scan, Reports, Alerts, Notes, and admin-only Users),
// a dynamic unresolved-alert badge, user info, and logout. Call
// mountSidebar('<activeKey>') after requireAuth().

const NAV_ICONS = {
  dashboard: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>',
  devices: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>',
  scan: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>',
  reports: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>',
  alerts: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>',
  notes: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>',
  users: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>',
  logout: '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>'
};

const NAV_SECTIONS = [
  { title: 'Overview', items: [
    { key: 'dashboard', label: 'Dashboard', href: 'dashboard.html', icon: 'dashboard' },
    { key: 'devices', label: 'Devices', href: 'devices.html', icon: 'devices' }
  ]},
  { title: 'Operations', items: [
    { key: 'scan', label: 'Scan', href: 'scan.html', icon: 'scan' },
    { key: 'reports', label: 'Reports', href: 'reports.html', icon: 'reports' },
    { key: 'alerts', label: 'Alerts', href: 'alerts.html', icon: 'alerts', badge: true },
    { key: 'notes', label: 'Notes', href: 'notes.html', icon: 'notes' }
  ]},
  { title: 'Administration', items: [
    { key: 'admin', label: 'Users', href: 'admin.html', icon: 'users', adminOnly: true }
  ]}
];

function mountSidebar(activeKey) {
  const aside = document.getElementById('sidebar');
  if (!aside) return;
  const isAdmin = getRole() === 'admin';

  let nav = '';
  for (const section of NAV_SECTIONS) {
    const items = section.items.filter(it => !it.adminOnly || isAdmin);
    if (!items.length) continue;
    nav += `<div class="nav-section"><div class="nav-section-title">${section.title}</div>`;
    for (const it of items) {
      const isActive = it.key === activeKey;
      const active = isActive ? ' active' : '';
      const current = isActive ? ' aria-current="page"' : '';
      const badge = it.badge
        ? '<span class="badge badge-danger ml-auto nav-alert-badge" style="display:none">0</span>'
        : '';
      nav += `<a href="${it.href}" class="nav-item${active}"${current}>${NAV_ICONS[it.icon]}<span>${it.label}</span>${badge}</a>`;
    }
    nav += '</div>';
  }

  aside.innerHTML = `
    <div class="sidebar-header">
      <div class="sidebar-logo">N9</div>
      <span class="sidebar-brand">N9pinax</span>
    </div>
    <nav class="sidebar-nav">${nav}</nav>
    <div class="sidebar-footer">
      <div class="flex items-center gap-3">
        <div class="user-avatar" data-user-initials>A</div>
        <div class="flex-1">
          <div class="text-sm font-medium" data-user-email>admin</div>
          <div class="text-xs text-muted" data-user-role>analyst</div>
        </div>
        <button class="btn btn-icon btn-ghost" onclick="logout()" title="Logout">${NAV_ICONS.logout}</button>
      </div>
    </div>`;

  applyUserChrome();
  refreshAlertBadge();
}
