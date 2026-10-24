'use strict';
/*
 * TrustVault front end. It is a convenience, not a control: every rule is enforced by the server, and this file
 * only decides what to SHOW. Nothing here uses innerHTML; all text goes in through textContent, so a hostile
 * document title or name cannot become markup (the CSP also forbids inline script).
 */
(() => {
  const CATEGORIES = ['general', 'contracts', 'hr', 'finance', 'engineering', 'legal', 'audit'];
  const $ = (sel, root = document) => root.querySelector(sel);

  function h(tag, attrs = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'value') e.value = v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return e;
  }

  let toastTimer;
  function toast(msg, bad = false) {
    const t = $('#toast');
    t.textContent = msg;
    t.className = `show${bad ? ' bad' : ''}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = ''; }, 3500);
  }

  const store = {
    get csrf() { try { return sessionStorage.getItem('tv_csrf') || ''; } catch { return ''; } },
    set csrf(v) { try { sessionStorage.setItem('tv_csrf', v); } catch { /* private mode: /me will refetch */ } },
  };

  async function api(method, path, { json, body, headers = {} } = {}) {
    const init = { method, headers: { ...headers }, credentials: 'same-origin' };
    if (method !== 'GET') init.headers['X-CSRF-Token'] = store.csrf;
    if (json !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(json); }
    if (body !== undefined) init.body = body;
    const res = await fetch(path, init);
    if (res.status === 401 && !path.startsWith('/api/auth/login')) { location.href = '/login.html'; throw new Error('Signed out'); }
    if (!res.ok) {
      let msg = `Request failed (${res.status})`;
      try { msg = (await res.clone().json()).error.message; } catch { /* not json */ }
      const err = new Error(msg); err.status = res.status; throw err;
    }
    return res;
  }
  const getJson = async (p) => (await api('GET', p)).json();
  const send = async (m, p, json) => (await api(m, p, { json })).json().catch(() => ({}));
  const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { if (e.message !== 'Signed out') toast(e.message, true); } };

  const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '');
  const chip = (text, cls = '') => h('span', { class: `chip ${cls}` }, text);
  const table = (heads, rows) => h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, heads.map((x) => h('th', {}, x)))), h('tbody', {}, rows)));

  async function download(doc, version) {
    const res = await api('GET', `/api/documents/${doc.id}/download${version ? `?version=${version}` : ''}`);
    const cd = res.headers.get('Content-Disposition') || '';
    const m = /filename\*=UTF-8''([^;]+)/.exec(cd);
    const name = m ? decodeURIComponent(m[1]) : doc.originalName || 'document';
    const url = URL.createObjectURL(await res.blob());
    const a = h('a', { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  // ------------------------------------------------------------------------------------------------ shell
  async function shell() {
    const me = await getJson('/api/auth/me');
    store.csrf = me.csrfToken;
    const user = me.user;
    const links = [['Dashboard', '/dashboard.html'], ['Documents', '/documents.html']];
    if (user.role === 'owner') links.push(['Sharing', '/permissions.html']);
    if (user.role === 'admin') links.push(['Administration', '/audit.html']);
    const nav = $('#nav');
    for (const [label, href] of links) nav.append(h('a', { href, 'aria-current': location.pathname === href ? 'page' : null }, label));
    const initials = user.name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?';
    $('#whoami').replaceChildren(h('span', { class: 'avatar', 'aria-hidden': 'true' }, initials), h('span', { class: 'who-text' }, h('b', {}, user.name), h('small', {}, user.role)));
    $('#logout').addEventListener('click', guard(async () => { await send('POST', '/api/auth/logout'); store.csrf = ''; location.href = '/login.html'; }));
    $('#top').hidden = false;
    return user;
  }

  // ------------------------------------------------------------------------------------------------ login
  function loginPage() {
    const loginForm = $('#login-form');
    const registerForm = $('#register-form');
    const heading = $('#auth-heading');
    const subtitle = $('#auth-subtitle');
    const signInTab = $('#show-signin');
    const registerTab = $('#show-register');
    function showMode(mode) {
      const registering = mode === 'register';
      loginForm.hidden = registering;
      registerForm.hidden = !registering;
      heading.textContent = registering ? 'Create your identity' : 'Welcome back';
      subtitle.textContent = registering ? 'Register to request a TrustVault account' : 'Sign in to your TrustVault account';
      signInTab.classList.toggle('active', !registering);
      registerTab.classList.toggle('active', registering);
      $('#login-error').textContent = '';
      $('#register-error').textContent = '';
    }
    signInTab.addEventListener('click', () => showMode('login'));
    registerTab.addEventListener('click', () => showMode('register'));

    loginForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      $('#login-error').textContent = '';
      try {
        const res = await api('POST', '/api/auth/login', { json: { email: f.get('email'), password: f.get('password') } });
        store.csrf = (await res.json()).csrfToken;
        location.href = '/dashboard.html';
      } catch (e) {
        $('#login-error').textContent = e.status === 429 ? 'Too many attempts. Wait a minute.' : (e.message || 'Wrong email or password.');
      }
    });

    const adminRow = $('#admin-code-row');
    registerForm.elements.role.addEventListener('change', (ev) => {
      const isAdmin = ev.target.value === 'admin';
      adminRow.hidden = !isAdmin;
      registerForm.elements.adminCode.required = isAdmin;
      if (!isAdmin) registerForm.elements.adminCode.value = '';
    });
    registerForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      $('#register-error').textContent = '';
      try {
        const res = await api('POST', '/api/auth/register', {
          json: { name: f.get('name'), role: f.get('role'), email: f.get('email'), password: f.get('password'), ...(f.get('role') === 'admin' ? { adminCode: f.get('adminCode') } : {}) }
        });
        const result = await res.json().catch(() => ({}));
        result.email = result.email || f.get('email');
        registerForm.reset();
        adminRow.hidden = true;
        showMode('login');
        loginForm.elements.email.value = result.email;
        toast(result.message || 'Account created. Please sign in.');
      } catch (e) {
        $('#register-error').textContent = e.message || 'Unable to create account.';
      }
    });
  }

  // ------------------------------------------------------------------------------------------------ dashboard
  async function dashboardPage(user, main) {
    main.replaceChildren(h('h1', {}, `Welcome, ${user.name}`), h('p', { class: 'lede' }, 'Your secure workspace at a glance.'));
    if (user.role === 'admin') {
      const [alerts, docs, verify] = await Promise.all([getJson('/api/audit/alerts'), getJson('/api/admin/documents?limit=200'), getJson('/api/audit/verify')]);
      main.append(h('div', { class: 'grid' },
        h('div', { class: 'card stat' }, h('b', {}, docs.documents.filter((d) => !d.deletedAt).length), 'documents (metadata only)'),
        h('div', { class: 'card stat' }, h('b', {}, alerts.alerts.length), 'things worth a look (24h)'),
        h('div', { class: 'card stat' }, h('b', {}, verify.ok ? 'Intact' : 'TAMPERED'), `audit chain · ${verify.events} events`)));
      main.append(h('h2', {}, 'Worth noticing'));
      if (!alerts.alerts.length) main.append(h('p', { class: 'muted' }, 'Nothing unusual in the last 24 hours.'));
      for (const a of alerts.alerts) main.append(h('div', { class: `alert ${a.severity}` }, chip(a.severity, a.severity), ' ', a.message));
      if (!verify.ok) main.append(h('div', { class: 'alert critical' }, 'The audit trail failed verification: ', verify.problems.map((p) => `#${p.seq}: ${p.reason}`).join('; ')));
      main.append(h('p', {}, h('a', { href: '/audit.html' }, 'Open administration →')));
      return;
    }
    const { documents } = await getJson('/api/documents?limit=100');
    const mine = documents.filter((d) => d.access === 'owner');
    const shared = documents.filter((d) => d.access !== 'owner');
    main.append(h('div', { class: 'grid' },
      user.role === 'owner' && h('div', { class: 'card stat' }, h('b', {}, mine.length), 'documents you own'),
      h('div', { class: 'card stat' }, h('b', {}, shared.length), 'shared with you')));
    main.append(h('h2', {}, 'Recently updated'));
    main.append(docTable(documents.slice(0, 8), user, () => {}));
  }

  // ------------------------------------------------------------------------------------------------ documents
  function docTable(docs, user, reload) {
    if (!docs.length) return h('p', { class: 'muted' }, 'No documents.');
    const rows = docs.map((d) => {
      const acts = [];
      if (d.deletedAt) {
        acts.push(h('button', { onclick: guard(async () => { await send('POST', `/api/documents/${d.id}/restore`); toast('Restored'); reload(); }) }, 'Restore'));
      } else {
        acts.push(h('button', { onclick: guard(() => download(d)) }, 'Download'));
        if (d.access === 'owner' || d.access === 'edit') {
          const file = h('input', { type: 'file', hidden: true, onchange: guard(async (ev) => {
            const f = ev.target.files[0]; if (!f) return;
            await api('PUT', `/api/documents/${d.id}/content`, { body: f, headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(f.name) } });
            toast('New version saved'); reload();
          }) });
          acts.push(h('button', { onclick: () => file.click() }, 'New version'), file);
          acts.push(h('button', { onclick: guard(async () => {
            const t = prompt('New title', d.title); if (!t || t === d.title) return;
            await send('PATCH', `/api/documents/${d.id}`, { title: t }); reload();
          }) }, 'Rename'));
        }
        if (d.access === 'owner') {
          acts.push(h('a', { href: `/permissions.html?doc=${d.id}` }, h('button', {}, 'Share')));
          acts.push(h('button', { class: 'danger', onclick: guard(async () => {
            if (!confirm(`Move "${d.title}" to the trash? Everyone you shared it with loses access now.`)) return;
            await send('DELETE', `/api/documents/${d.id}`); toast('Moved to trash'); reload();
          }) }, 'Delete'));
        }
      }
      return h('tr', {}, h('td', {}, d.title, h('div', { class: 'note' }, d.originalName)), h('td', {}, chip(d.category)),
        h('td', {}, chip(d.access, d.access === 'owner' ? 'owner' : '')), h('td', {}, d.owner), h('td', {}, fmtSize(d.size), ` · v${d.version}`),
        h('td', {}, fmtDate(d.updatedAt)), h('td', { class: 'actions' }, acts));
    });
    return table(['Title', 'Category', 'Your access', 'Owner', 'Size', 'Updated', ''], rows);
  }

  async function documentsPage(user, main) {
    main.replaceChildren(h('h1', {}, 'Documents'), h('p', { class: 'lede' }, 'Upload, search and manage the files you can access.'));
    const results = h('div', {});
    const form = h('form', { class: 'row card' },
      h('label', {}, 'Name', h('input', { name: 'q', placeholder: 'title or file name' })),
      h('label', {}, 'Owner', h('input', { name: 'owner', placeholder: 'name or email' })),
      h('label', {}, 'Category', h('select', { name: 'category' }, h('option', { value: '' }, 'any'), CATEGORIES.map((c) => h('option', { value: c }, c)))),
      h('label', {}, 'From', h('input', { name: 'from', type: 'date' })),
      h('label', {}, 'To', h('input', { name: 'to', type: 'date' })),
      h('label', {}, 'Show', h('select', { name: 'scope' }, [['all', 'everything I can see'], ['mine', 'mine'], ['shared', 'shared with me'], ['trash', 'my trash']].map(([v, t]) => h('option', { value: v }, t)))),
      h('button', { class: 'primary', type: 'submit' }, 'Search'));
    const load = guard(async () => {
      const p = new URLSearchParams();
      for (const [k, v] of new FormData(form)) if (v) p.set(k, v);
      const { documents } = await getJson(`/api/documents?${p}`);
      results.replaceChildren(h('p', { class: 'note' }, `${documents.length} result${documents.length === 1 ? '' : 's'}`), docTable(documents, user, load));
    });
    form.addEventListener('submit', (e) => { e.preventDefault(); load(); });

    if (user.role === 'owner') {
      const up = h('form', { class: 'row card' },
        h('label', {}, 'File', h('input', { name: 'file', type: 'file', required: true, accept: '.pdf,.png,.jpg,.jpeg,.docx,.xlsx,.pptx,.txt,.csv' })),
        h('label', {}, 'Title', h('input', { name: 'title', placeholder: 'defaults to the file name' })),
        h('label', {}, 'Category', h('select', { name: 'category' }, CATEGORIES.map((c) => h('option', { value: c }, c)))),
        h('button', { class: 'primary', type: 'submit' }, 'Upload'),
        h('span', { class: 'note' }, 'PDF, images, Office files, text. Only you can open it until you share it.'));
      up.addEventListener('submit', guard(async (e) => {
        e.preventDefault();
        const f = new FormData(up); const file = f.get('file');
        const q = new URLSearchParams({ category: f.get('category') }); if (f.get('title')) q.set('title', f.get('title'));
        await api('POST', `/api/documents?${q}`, { body: file, headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(file.name) } });
        up.reset(); toast('Uploaded'); load();
      }));
      main.append(h('h2', {}, 'Upload'), up);
    }
    main.append(h('h2', {}, 'Find'), form, results);
    load();
  }

  // ------------------------------------------------------------------------------------------------ sharing
  async function permissionsPage(user, main) {
    main.replaceChildren(h('h1', {}, 'Sharing'), h('p', { class: 'lede' }, 'Decide exactly who can open each document, and revoke access at any time.'));
    const { documents } = await getJson('/api/documents?scope=mine&limit=100');
    const picker = h('select', {}, h('option', { value: '' }, 'Choose a document…'), documents.map((d) => h('option', { value: d.id }, d.title)));
    const panel = h('div', {});
    main.append(h('div', { class: 'card row' }, h('label', {}, 'Document', picker)), panel);
    const chosen = new URLSearchParams(location.search).get('doc');
    if (chosen && documents.some((d) => d.id === chosen)) picker.value = chosen;
    picker.addEventListener('change', () => show(picker.value));
    if (picker.value) show(picker.value);

    const show = guard(async (id) => {
      panel.replaceChildren();
      if (!id) return;
      const doc = documents.find((d) => d.id === id);
      const [{ grants, history }, { events }] = await Promise.all([getJson(`/api/documents/${id}/grants`), getJson(`/api/documents/${id}/audit?limit=50`)]);
      const reload = () => show(id);

      panel.append(h('h2', {}, `Who can open “${doc.title}”`));
      panel.append(grants.length ? table(['Person', 'Level', 'Since', 'Expires', ''], grants.map((g) => h('tr', {},
        h('td', {}, g.name, h('div', { class: 'note' }, g.email)), h('td', {}, chip(g.level)), h('td', {}, fmtDate(g.created_at)), h('td', {}, g.expires_at ? fmtDate(g.expires_at) : 'never'),
        h('td', { class: 'actions' },
          h('button', { onclick: guard(async () => { await send('PUT', `/api/documents/${id}/grants/${g.user_id}`, { level: g.level === 'read' ? 'edit' : 'read' }); reload(); }), disabled: g.role === 'viewer' && g.level === 'read' }, g.level === 'read' ? 'Allow edit' : 'Make read-only'),
          h('button', { class: 'danger', onclick: guard(async () => { await send('DELETE', `/api/documents/${id}/grants/${g.user_id}`); toast('Access removed. It takes effect immediately.'); reload(); }) }, 'Revoke')))))
        : h('p', { class: 'muted' }, 'Only you. Nobody else can see this document.'));

      // add a person
      const results = h('div', {});
      const level = h('select', {}, h('option', { value: 'read' }, 'read'), h('option', { value: 'edit' }, 'edit (not for viewer accounts)'));
      const expiry = h('input', { type: 'date' });
      const grantTo = (u, lvl, suggestionId) => guard(async () => {
        const body = { level: lvl ?? level.value };
        if (expiry.value) body.expiresAt = new Date(`${expiry.value}T23:59:59`).toISOString();
        if (suggestionId) body.suggestionId = suggestionId;
        await send('PUT', `/api/documents/${id}/grants/${u.id ?? u.userId}`, body);
        toast(`${u.email} now has ${body.level} access`); reload();
      });
      const search = h('input', { placeholder: 'name or email (2+ letters)', minlength: 2 });
      const find = h('form', { class: 'row card' }, h('label', {}, 'Add a person', search), h('label', {}, 'Level', level), h('label', {}, 'Expires (optional)', expiry), h('button', { type: 'submit' }, 'Find'));
      find.addEventListener('submit', guard(async (e) => {
        e.preventDefault();
        const { users } = await getJson(`/api/users/directory?q=${encodeURIComponent(search.value)}`);
        results.replaceChildren(users.length ? table(['Person', 'Role', ''], users.map((u) => h('tr', {}, h('td', {}, u.name, h('div', { class: 'note' }, u.email)), h('td', {}, chip(u.role)),
          h('td', {}, h('button', { class: 'primary', onclick: grantTo(u) }, 'Grant access'))))) : h('p', { class: 'muted' }, 'Nobody found.'));
      }));
      panel.append(find, results);

      // suggestions: propose only; the owner decides
      const sug = h('div', {});
      panel.append(h('h2', {}, 'Suggestions'), h('p', { class: 'note' }, 'Suggestions are hints based on who you have shared similar documents with. They never grant anything by themselves; you decide, and both the hint and your decision are recorded.'),
        h('button', { onclick: guard(async () => {
          const { suggestions } = await send('POST', `/api/documents/${id}/suggestions`);
          sug.replaceChildren(suggestions.length ? table(['Person', 'Why', ''], suggestions.map((s) => h('tr', {}, h('td', {}, s.name, h('div', { class: 'note' }, s.email)), h('td', {}, s.reason),
            h('td', { class: 'actions' }, h('button', { class: 'primary', onclick: grantTo(s, 'read', s.id) }, 'Accept as read'),
              h('button', { onclick: guard(async () => { await send('POST', `/api/documents/${id}/suggestions/${s.id}/reject`); toast('Dismissed'); reload(); }) }, 'Reject'))))) : h('p', { class: 'muted' }, 'No suggestions.'));
        }) }, 'Suggest who might need access'), sug);

      panel.append(h('h2', {}, 'Past access'));
      panel.append(history.length ? table(['Person', 'Level', 'Granted', 'Ended'], history.map((g) => h('tr', {}, h('td', {}, g.email), h('td', {}, chip(g.level)), h('td', {}, fmtDate(g.created_at)),
        h('td', {}, g.revoked_at ? `revoked ${fmtDate(g.revoked_at)}` : g.expires_at && Date.parse(g.expires_at) < Date.now() ? `expired ${fmtDate(g.expires_at)}` : 'active')))) : h('p', { class: 'muted' }, 'None.'));

      panel.append(h('h2', {}, 'Who touched this document'), eventTable(events, false));
    });
  }

  function eventTable(events, showDoc) {
    if (!events.length) return h('p', { class: 'muted' }, 'No events.');
    const heads = ['When', 'Who', 'What', 'Result', 'Detail'];
    if (showDoc) heads.push('Document');
    return table(heads, events.map((e) => h('tr', {},
      h('td', {}, fmtDate(e.ts)),
      h('td', {}, e.actor_email ?? '(not signed in)'),
      h('td', {}, e.action),
      h('td', {}, chip(e.outcome, e.outcome)),
      h('td', {}, h('pre', { class: 'detail' }, JSON.stringify(e.detail))),
      showDoc ? h('td', {}, e.document_id ? e.document_id.slice(0, 8) : '') : null)));
  }

  // ------------------------------------------------------------------------------------------------ administration
  async function auditPage(user, main) {
    if (user.role !== 'admin') { location.href = '/dashboard.html'; return; }
    main.replaceChildren(h('h1', {}, 'Administration'), h('p', { class: 'lede' }, 'Audit integrity, activity, documents and people.'));

    // integrity
    const integrity = h('div', { class: 'card' });
    const verify = guard(async () => {
      const r = await getJson('/api/audit/verify');
      integrity.replaceChildren(h('b', {}, 'Audit trail integrity: '), chip(r.ok ? 'intact' : 'TAMPERED', r.ok ? 'ok' : 'critical'),
        ` ${r.events} events checked against the hash chain and ${r.anchors} external anchors. `, h('button', { onclick: verify }, 'Re-verify'),
        r.problems.map((p) => h('div', { class: 'alert critical' }, `#${p.seq ?? '-'}: ${p.reason}`)));
    });
    main.append(integrity); verify();

    // alerts
    const alerts = h('div', {});
    main.append(h('h2', {}, 'Worth noticing (last 24h)'), alerts);
    getJson('/api/audit/alerts').then(({ alerts: a }) => alerts.replaceChildren(a.length ? a.map((x) => h('div', { class: `alert ${x.severity}` }, chip(x.severity, x.severity), ' ', x.message)) : h('p', { class: 'muted' }, 'Nothing unusual.')));

    // event log
    const out = h('div', {});
    const f = h('form', { class: 'row card' },
      h('label', {}, 'Person', h('input', { name: 'actor', placeholder: 'email' })),
      h('label', {}, 'Action', h('input', { name: 'action', placeholder: 'e.g. download' })),
      h('label', {}, 'Result', h('select', { name: 'outcome' }, ['', 'success', 'denied', 'error'].map((v) => h('option', { value: v }, v || 'any')))),
      h('label', {}, 'Document id', h('input', { name: 'documentId' })),
      h('label', {}, 'From', h('input', { name: 'from', type: 'date' })), h('label', {}, 'To', h('input', { name: 'to', type: 'date' })),
      h('button', { class: 'primary', type: 'submit' }, 'Filter'));
    const load = guard(async () => {
      const p = new URLSearchParams(); for (const [k, v] of new FormData(f)) if (v) p.set(k, v);
      const { events } = await getJson(`/api/audit?${p}`);
      out.replaceChildren(eventTable(events, true));
    });
    f.addEventListener('submit', (e) => { e.preventDefault(); load(); });
    main.append(h('h2', {}, 'Activity and permission changes'), f, out); load();

    // documents (metadata only)
    const docs = h('div', {});
    main.append(h('h2', {}, 'Documents (metadata only; administrators cannot open content)'), docs);
    getJson('/api/admin/documents?limit=100').then(({ documents }) => docs.replaceChildren(table(['Title', 'Owner', 'Category', 'Active grants', 'Updated', ''], documents.map((d) => h('tr', {},
      h('td', {}, d.title, h('div', { class: 'note' }, d.id)), h('td', {}, d.owner), h('td', {}, chip(d.category)), h('td', {}, d.activeGrants), h('td', {}, fmtDate(d.updatedAt)), h('td', {}, d.deletedAt ? chip('in trash') : ''))))));

    // users
    const users = h('div', {});
    const loadUsers = guard(async () => {
      const { users: list } = await getJson('/api/users');
      users.replaceChildren(table(['Person', 'Role', 'Status', ''], list.map((u) => h('tr', {}, h('td', {}, u.name, h('div', { class: 'note' }, u.email)),
        h('td', {}, h('select', { onchange: guard(async (ev) => { await send('PATCH', `/api/users/${u.id}`, { role: ev.target.value }); toast('Role changed; they must sign in again'); loadUsers(); }) },
          ['admin', 'owner', 'viewer'].map((r) => h('option', { value: r, selected: r === u.role }, r)))),
        h('td', {}, u.disabled ? chip('disabled', 'denied') : chip('active', 'ok')),
        h('td', {}, h('button', { class: u.disabled ? '' : 'danger', onclick: guard(async () => {
          if (!u.disabled && !confirm(`Disable ${u.email}? Their sessions end and all their access is revoked now.`)) return;
          await send('PATCH', `/api/users/${u.id}`, { disabled: !u.disabled }); loadUsers();
        }) }, u.disabled ? 'Enable' : 'Disable'))))));
    });
    const nu = h('form', { class: 'row card' },
      h('label', {}, 'Name', h('input', { name: 'name', required: true })), h('label', {}, 'Email', h('input', { name: 'email', type: 'email', required: true })),
      h('label', {}, 'Role', h('select', { name: 'role' }, ['viewer', 'owner', 'admin'].map((r) => h('option', { value: r }, r)))),
      h('label', {}, 'Temporary password (12+)', h('input', { name: 'password', type: 'password', required: true, minlength: 12, autocomplete: 'new-password' })),
      h('button', { class: 'primary', type: 'submit' }, 'Create account'));
    nu.addEventListener('submit', guard(async (e) => { e.preventDefault(); await send('POST', '/api/users', Object.fromEntries(new FormData(nu))); nu.reset(); toast('Account created'); loadUsers(); }));
    main.append(h('h2', {}, 'People'), nu, users); loadUsers();
  }

  // ------------------------------------------------------------------------------------------------ boot
  const pages = { dashboard: dashboardPage, documents: documentsPage, permissions: permissionsPage, audit: auditPage };
  document.addEventListener('DOMContentLoaded', async () => {
    const page = document.body.dataset.page;
    if (page === 'login') return loginPage();
    try {
      const user = await shell();
      if (page === 'permissions' && user.role !== 'owner') { location.href = '/dashboard.html'; return; }
      await pages[page](user, $('#main'));
    } catch (e) { if (e.message !== 'Signed out') $('#main').replaceChildren(h('p', { class: 'error' }, e.message)); }
  });
})();
