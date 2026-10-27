(function () {
  'use strict';

  const GH = window.GH;
  if (!GH) return;

  window.GHApp = window.GHApp || {
    pages: {},
    state: { csrf: '', sid: 0, role: 'unknown', readOnly: false, online: true, ov: null },
    registerPage: function (id, page) { this.pages[id] = page; return page; },
    helpers: {}
  };

  const app = window.GHApp;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const clear = (el) => { el.textContent = ''; return el; };
  const h = function (tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  };
  const ltr = (text, cls) => h('span', { class: 'ltr' + (cls ? ' ' + cls : '') }, text);
  const badge = (text, kind) => h('span', { class: 'badge' + (kind ? ' ' + kind : '') }, text);
  const pad = (n) => String(n).padStart(2, '0');

  function fmtBytesParts(n, perSec) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let v = Math.max(0, Number(n) || 0);
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    const txt = i === 0 ? String(Math.round(v)) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
    return { v: txt, u: units[i] + (perSec ? '/s' : '') };
  }
  const fmtBytes = (n, perSec) => { const p = fmtBytesParts(n, perSec); return p.v + ' ' + p.u; };
  const fmtDate = (unix) => {
    if (!unix) return '—';
    const d = new Date(unix * 1000);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  };
  const fmtClock = (unix) => { const d = new Date(unix * 1000); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  const fmtClockMs = (ms) => { const d = new Date(ms); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + '.' + String(d.getMilliseconds()).padStart(3, '0'); };

  async function api(path, opt) {
    opt = opt || {};
    const method = opt.method || 'GET';
    const init = { method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') {
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-CSRF-Token'] = app.state.csrf;
      init.body = JSON.stringify(opt.body || {});
    }
    let res;
    try { res = await fetch(path, init); } catch (e) { setOnline(false); throw { code: 'network' }; }
    setOnline(true);
    if (res.status === 401) { location.href = '/login'; throw { code: 'unauthorized' }; }
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) throw { code: (data && data.error) || 'http_' + res.status, detail: data && data.detail, status: res.status };
    return data;
  }

  function setOnline(on) {
    if (app.state.online === on) return;
    app.state.online = on;
    const banner = $('#banner-offline');
    if (banner) banner.classList.toggle('hidden', on);
    paintConnBadge();
  }

  function paintConnBadge() {
    const b = $('#conn-badge');
    if (!b) return;
    b.className = 'badge ' + (app.state.online ? 'ok' : 'bad');
    b.textContent = app.state.online ? GH.t('online') : GH.t('offline_short');
  }

  function errMsg(e) {
    const code = e && e.code;
    if (code === 'network') return GH.t('err_network');
    const dict = GH.DICT[GH.lang()];
    let msg = dict['err_' + code] ? GH.t('err_' + code) : GH.t('err_generic', { c: code || '?' });
    if (code === 'invalid_config' && e.detail) msg += '\n' + e.detail;
    return msg;
  }

  function toast(msg, bad) {
    const box = $('#toasts');
    if (!box) return;
    const el = h('div', { class: 'toast' + (bad ? ' bad' : ''), role: 'status' }, msg);
    box.append(el);
    setTimeout(() => el.remove(), bad ? 6500 : 3800);
  }

  function confirmDialog(title, text, extra) {
    return new Promise((resolve) => {
      const dlg = $('#dlg');
      if (!dlg) resolve(true);
      $('#dlg-title').textContent = title;
      const p = $('#dlg-text');
      clear(p);
      p.append(text);
      if (extra && extra.length) {
        const ul = h('ul');
        extra.forEach((x) => ul.append(h('li', null, x)));
        p.append(ul);
      }
      $('#dlg-no').textContent = GH.t('cancel');
      $('#dlg-yes').textContent = GH.t('confirm');
      const done = (v) => { dlg.close(); cleanup(); resolve(v); };
      const yes = () => done(true);
      const no = () => done(false);
      const cleanup = () => { $('#dlg-yes').removeEventListener('click', yes); $('#dlg-no').removeEventListener('click', no); dlg.removeEventListener('cancel', no); };
      $('#dlg-yes').addEventListener('click', yes);
      $('#dlg-no').addEventListener('click', no);
      dlg.addEventListener('cancel', no);
      dlg.showModal();
      $('#dlg-yes').focus();
    });
  }

  const NAV = [
    ['dashboard', 'dashboard'], ['tunnels', 'tunnels'], ['config', 'config'],
    ['connections', 'connections'], ['certs', 'certs'], ['account', 'account'], ['logs', 'logs']
  ];

  let current = null, timer = null, seq = 0;

  function buildNav() {
    const nav = clear($('#nav'));
    if (!nav) return;
    const id = current || 'dashboard';
    NAV.forEach(([page, ic]) => {
      const a = h('a', { href: '#' + page, 'data-page': page }, GH.icon(ic), h('span', null, GH.t('nav_' + page)));
      if (page === id) a.setAttribute('aria-current', 'page');
      nav.append(a);
    });
  }

  function openMenu() { $('#side').classList.add('open'); $('#scrim').classList.add('open'); }
  function closeMenu() { $('#side').classList.remove('open'); $('#scrim').classList.remove('open'); }

  function schedule(id) {
    clearTimeout(timer);
    const p = app.pages[id];
    if (!p || !p.interval) return;
    const my = seq;
    const loop = async () => {
      if (my !== seq) return;
      if (!document.hidden) { try { await p.refresh(); } catch (e) { /* offline banner handles it */ } }
      if (my === seq) timer = setTimeout(loop, p.interval);
    };
    timer = setTimeout(loop, p.interval);
  }

  async function route() {
    let id = location.hash.replace('#', '') || 'dashboard';
    if (!app.pages[id]) id = 'dashboard';
    seq++;
    current = id;
    $$('.page').forEach((s) => s.classList.toggle('active', s.id === 'page-' + id));
    $$('#nav a').forEach((a) => (a.getAttribute('data-page') === id ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
    $('#page-title').textContent = GH.t(app.pages[id].title);
    closeMenu();
    const p = app.pages[id];
    try { if (p.enter) await p.enter(); if (p.refresh) await p.refresh(); } catch (e) { if (e && e.code !== 'network' && e.code !== 'unauthorized') toast(errMsg(e), true); }
    schedule(id);
  }

  async function boot() {
    let s;
    try { s = await (await fetch('/api/session', { credentials: 'same-origin' })).json(); } catch (e) { location.href = '/login'; return; }
    if (!s.authenticated) { location.href = '/login'; return; }
    app.state.csrf = s.csrf; app.state.sid = s.sid; app.state.role = s.role; app.state.readOnly = !!s.read_only;
    $('#version').textContent = 'v' + s.version;
    $('#role-badge').textContent = GH.t('role_' + s.role);
    loadRepoStars();
    $('#banner-pw').classList.toggle('hidden', !s.must_change_password);
    GH.setIcon($('#menu-btn'), 'menu');
    $('#menu-btn').addEventListener('click', openMenu);
    $('#scrim').addEventListener('click', closeMenu);
    $('#logout-btn').addEventListener('click', async () => { try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ } location.href = '/login'; });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
    document.addEventListener('visibilitychange', () => { if (!document.hidden && current && app.pages[current].refresh) app.pages[current].refresh().catch(() => {}); });
    document.addEventListener('gh:lang', () => {
      buildNav(); paintConnBadge();
      $('#page-title').textContent = GH.t(app.pages[current].title);
      if (app.state.ov) $('#role-badge').textContent = GH.t('role_' + app.state.ov.role);
      if (current && app.pages[current].render) app.pages[current].render();
    });
    document.addEventListener('gh:theme', () => { if (current && app.pages[current].render) app.pages[current].render(); });
    window.addEventListener('hashchange', route);
    buildNav(); paintConnBadge();
    GH.apply();
    route();
  }

  async function loadRepoStars() {
    const count = $('#repo-star-count');
    try {
      const data = await api('/api/repo-stars');
      count.textContent = GH.t('repo_stars', { n: data.stars });
    } catch (e) {
      count.textContent = GH.t('repo_stars_unavailable');
      count.title = errMsg(e);
    }
  }

  app.helpers = {
    $, $$, h, clear, ltr, badge, fmtBytesParts, fmtBytes, fmtDate, fmtClock, fmtClockMs,
    api, errMsg, setOnline, paintConnBadge, toast, confirmDialog, buildNav, openMenu, closeMenu, route, boot
  };

  document.addEventListener('DOMContentLoaded', boot);
})();
