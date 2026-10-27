(function () {
  'use strict';

  const app = window.GHApp;
  const GH = window.GH;
  const t = GH.t;
  const helpers = app.helpers;
  const $ = helpers.$;
  const h = helpers.h;
  const clear = helpers.clear;
  const ltr = helpers.ltr;
  const api = helpers.api;

  let rows = [];

  function fmtDur(seconds) {
    let remaining = Math.max(0, Math.floor(Number(seconds) || 0));
    const days = Math.floor(remaining / 86400);
    remaining %= 86400;
    const hours = Math.floor(remaining / 3600);
    remaining %= 3600;
    const minutes = Math.floor(remaining / 60);
    const secs = remaining % 60;
    if (days) return days + 'd ' + hours + 'h';
    if (hours) return hours + 'h ' + minutes + 'm';
    if (minutes) return minutes + 'm ' + secs + 's';
    return secs + 's';
  }

  function renderRows() {
    const body = clear($('#conns'));
    const q = $('#conn-filter').value.trim().toLowerCase();
    const filtered = rows.filter((r) => {
      const text = [r.kind, r.protocol, r.source, r.target, r.age].join(' ').toLowerCase();
      return !q || text.includes(q);
    });
    if (!filtered.length) { body.append(h('tr', null, h('td', { colspan: 5, class: 'empty' }, t('no_connections')))); return; }
    filtered.forEach((r) => body.append(h('tr', null,
      h('td', null, r.kind || '—'),
      h('td', null, ltr(r.protocol || '—', 'mono')),
      h('td', null, ltr(r.source || '—', 'mono')),
      h('td', null, ltr(r.target || '—', 'mono')),
      h('td', null, r.age || '—'))));
    $('#conn-total').textContent = String(filtered.length);
    $('#conn-note').textContent = filtered.length ? t('open_streams') + ': ' + filtered.length : t('no_connections');
  }

  app.registerPage('connections', {
    title: 'nav_connections', interval: 5000,
    enter() {
      $('#conn-filter').addEventListener('input', renderRows);
    },
    async refresh() {
      const data = await api('/api/streams?limit=1000');
      rows = (Array.isArray(data.streams) ? data.streams : []).map((stream) => ({
        kind: stream.kind,
        protocol: stream.proto,
        source: stream.peer,
        target: stream.target,
        age: fmtDur(data.now - stream.since)
      }));
      renderRows();
    },
    render: renderRows
  });
})();
