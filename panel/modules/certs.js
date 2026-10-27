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
  const badge = helpers.badge;
  const fmtDate = helpers.fmtDate;
  const api = helpers.api;

  let data = null;

  function render() {
    if (!data) return;
    const body = clear($('#certs'));
    if (!data.certs.length) { body.append(h('tr', null, h('td', { colspan: 5, class: 'empty' }, t('no_certs')))); return; }
    data.certs.forEach((c) => {
      const d = c.days_left;
      let kind = 'ok', label = t('cert_valid');
      if (d === null || d === undefined) { kind = 'mute'; label = '—'; }
      else if (d < 0) { kind = 'bad'; label = t('cert_expired'); }
      else if (d <= 14) { kind = 'bad'; label = t('cert_soon'); }
      else if (d <= 30) { kind = 'warn'; label = t('cert_soon'); }
      body.append(h('tr', null,
        h('td', null, ltr(c.zone, 'mono')),
        h('td', null, ltr(c.not_before ? fmtDate(c.not_before).slice(0, 10) : '—')),
        h('td', null, ltr(c.not_after ? fmtDate(c.not_after).slice(0, 10) : '—')),
        h('td', null, d === null || d === undefined ? '—' : t('days_n', { n: d })),
        h('td', null, h('div', { class: 'row' }, badge(label, kind), c.needs_renewal ? badge(t('cert_renew'), 'warn') : null))));
    });
  }

  app.registerPage('certs', { title: 'nav_certs', interval: 60000, async refresh() { data = await api('/api/certs'); render(); }, render });
})();
