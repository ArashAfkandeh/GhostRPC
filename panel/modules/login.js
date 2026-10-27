/* GhostRPC panel — login page logic. */
(function () {
  'use strict';
  var GH = window.GH;
  var t = GH.t;
  var form = document.getElementById('form');
  var user = document.getElementById('u');
  var pass = document.getElementById('p');
  var err = document.getElementById('err');
  var btn = document.getElementById('submit');
  var eye = document.getElementById('pw-toggle');
  var shown = false;

  function paintEye() {
    GH.setIcon(eye, shown ? 'eyeoff' : 'eye');
    eye.setAttribute('title', t(shown ? 'hide_password' : 'show_password'));
  }
  function showError(msg) {
    err.textContent = msg;
    err.classList.remove('hidden');
  }
  function label() {
    btn.querySelector('span').textContent = t(btn.disabled ? 'signing_in' : 'sign_in');
  }

  eye.addEventListener('click', function () {
    shown = !shown;
    pass.type = shown ? 'text' : 'password';
    paintEye();
  });
  document.addEventListener('DOMContentLoaded', paintEye);
  document.addEventListener('gh:lang', function () { paintEye(); label(); });
  paintEye();

  // Already signed in? Go straight to the dashboard.
  fetch('/api/session', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (s) { if (s && s.authenticated) location.replace('/'); })
    .catch(function () { /* stay on the login page */ });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    err.classList.add('hidden');
    btn.disabled = true;
    label();
    fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user.value, password: pass.value })
    })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (res.ok) { location.replace('/'); return; }
        var code = res.d && res.d.error;
        if (code === 'locked') {
          showError(t('err_locked', { n: Math.max(1, Math.ceil(Number(res.d.detail || 60) / 60)) }));
        } else if (code === 'invalid_credentials') {
          showError(t('err_invalid_credentials'));
        } else {
          showError(t('err_bad_request'));
        }
        pass.value = '';
        pass.focus();
      })
      .catch(function () { showError(t('err_network')); })
      .then(function () { btn.disabled = false; label(); });
  });
})();
