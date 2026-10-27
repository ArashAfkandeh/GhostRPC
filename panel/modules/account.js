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
  const confirmDialog = helpers.confirmDialog;
  const errMsg = helpers.errMsg;
  const toast = helpers.toast;

  let sessions = [], bound = false;

  function renderSessions() {
    const box = clear($('#my-sessions'));
    sessions.forEach((s) => box.append(h('div', { class: 'li' },
      h('div', { class: 'grow' },
        h('div', { class: 'row' }, ltr(s.ip, 'mono'), s.current ? badge(t('this_session'), 'ok') : null),
        h('div', { class: 'mute' }, (s.ua || '').slice(0, 90)),
        h('div', { class: 'mute' }, t('last_active') + ': ', ltr(fmtDate(s.last_seen)))),
      s.current ? null : h('button', { class: 'btn sm danger', type: 'button', onclick: () => revoke(s.sid) }, t('revoke')))));
  }

  async function revoke(sid) {
    if (!(await confirmDialog(t('confirm_revoke_title'), t('confirm_revoke_text')))) return;
    try { await api('/api/account/sessions/' + sid, { method: 'DELETE' }); await app.pages.account.refresh(); } catch (e) { toast(errMsg(e), true); }
  }

  app.registerPage('account', {
    title: 'nav_account', interval: 15000,
    enter() {
      if (bound) return;
      bound = true;
      $('#pw-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = clear($('#pw-result'));
        const cur = $('#pw-cur').value, nw = $('#pw-new').value, nw2 = $('#pw-new2').value;
        if (nw !== nw2) { res.append(h('div', { class: 'result bad' }, t('passwords_mismatch'))); return; }
        try {
          const r = await api('/api/account/password', { method: 'POST', body: { current: cur, new: nw } });
          $('#pw-form').reset();
          $('#banner-pw').classList.add('hidden');
          if (r.relogin) {
            res.append(h('div', { class: 'result ok' }, t('password_changed_relogin')));
            setTimeout(() => { location.href = '/login'; }, 2500);
            return;
          }
          res.append(h('div', { class: 'result ok' }, t('password_changed')));
          app.pages.account.refresh();
        } catch (err) { res.append(h('div', { class: 'result bad' }, errMsg(err))); }
      });
    },
    async refresh() { sessions = (await api('/api/account/sessions')).sessions; renderSessions(); },
    render: renderSessions
  });
})();
