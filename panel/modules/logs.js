(function () {
  'use strict';

  const app = window.GHApp;
  const GH = window.GH;
  const t = GH.t;
  const helpers = app.helpers;
  const $ = helpers.$;
  const h = helpers.h;
  const clear = helpers.clear;
  const fmtClockMs = helpers.fmtClockMs;
  const api = helpers.api;

  const MAX = 1500;
  let entries = [], last = 0, paused = false, bound = false;
  const lineText = (e) => fmtClockMs(e.ts) + ' ' + e.level.padEnd(5) + ' ' + e.msg;
  const match = (e) => { const q = $('#log-filter').value.trim().toLowerCase(); return !q || (e.level + ' ' + e.msg).toLowerCase().includes(q); };
  const lineEl = (e) => h('div', { class: 'logline' }, h('span', { class: 'ts' }, fmtClockMs(e.ts)), h('span', { class: 'lv lv-' + e.level }, e.level), h('span', null, e.msg));
  function atBottom(box) { return box.scrollHeight - box.scrollTop - box.clientHeight < 40; }
  function renderAll() {
    const box = clear($('#logbox'));
    const list = entries.filter(match);
    if (!list.length) box.append(h('div', { class: 'empty' }, t('no_logs')));
    const frag = document.createDocumentFragment();
    list.forEach((e) => frag.append(lineEl(e)));
    box.append(frag);
    box.scrollTop = box.scrollHeight;
  }
  function paintPause() { $('#log-pause').textContent = paused ? t('resume') : t('pause'); }
  function reset() { entries = []; last = 0; renderAll(); }

  app.registerPage('logs', {
    title: 'nav_logs', interval: 2000,
    enter() {
      if (!bound) {
        bound = true;
        $('#log-level').addEventListener('change', () => { reset(); app.pages.logs.refresh(); });
        $('#log-filter').addEventListener('input', renderAll);
        $('#log-pause').addEventListener('click', () => { paused = !paused; paintPause(); if (!paused) app.pages.logs.refresh(); });
        $('#log-clear').addEventListener('click', () => { entries = []; renderAll(); });
        $('#log-download').addEventListener('click', () => {
          const blob = new Blob([entries.filter(match).map(lineText).join('\n') + '\n'], { type: 'text/plain' });
          const a = h('a', { href: URL.createObjectURL(blob), download: 'ghostrpc-' + Date.now() + '.log' });
          document.body.append(a); a.click(); a.remove();
        });
      }
      paintPause(); renderAll();
    },
    async refresh() {
      if (paused) return;
      const level = $('#log-level').value;
      const r = await api('/api/logs?after=' + last + (level ? '&level=' + level : '') + '&limit=500');
      last = r.last;
      if (!r.entries.length) return;
      const box = $('#logbox'), stick = atBottom(box);
      entries = entries.concat(r.entries);
      if (entries.length > MAX) entries = entries.slice(entries.length - MAX);
      if (box.querySelector('.empty')) clear(box);
      const frag = document.createDocumentFragment();
      r.entries.filter(match).forEach((e) => frag.append(lineEl(e)));
      box.append(frag);
      while (box.childElementCount > MAX) box.firstElementChild.remove();
      if (stick) box.scrollTop = box.scrollHeight;
    },
    render() { paintPause(); renderAll(); }
  });
})();
