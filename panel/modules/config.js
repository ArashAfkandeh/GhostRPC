(function () {
  'use strict';

  const app = window.GHApp;
  const GH = window.GH;
  const t = GH.t;
  const helpers = app.helpers;
  const $ = helpers.$;
  const h = helpers.h;
  const clear = helpers.clear;
  const fmtDate = helpers.fmtDate;
  const fmtBytes = helpers.fmtBytes;
  const api = helpers.api;
  const confirmDialog = helpers.confirmDialog;
  const errMsg = helpers.errMsg;
  const toast = helpers.toast;

  let cfg = null, loaded = false, bound = false;
  let guideSamples = null, guideRole = 'client';
  const ed = () => $('#editor');
  const highlight = () => $('#editor-highlight');
  const dirty = () => cfg && ed().value !== cfg.content;

  function escapeHtml(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function token(text, kind) {
    return kind ? '<span class="toml-' + kind + '">' + escapeHtml(text) + '</span>' : escapeHtml(text);
  }

  function findAssignment(line) {
    let quote = '';
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (quote) {
        if (char === '\\' && quote === '"' && i + 1 < line.length) { i++; continue; }
        if (char === quote) quote = '';
      } else if (char === '"' || char === "'") {
        quote = char;
      } else if (char === '#') {
        return -1;
      } else if (char === '=') {
        return i;
      }
    }
    return -1;
  }

  function stringEnd(source, start, quote) {
    for (let i = start + quote.length; i < source.length; i++) {
      if (quote[0] === '"' && source[i] === '\\') { i++; continue; }
      if (source.startsWith(quote, i)) return i + quote.length;
    }
    return -1;
  }

  // Token categories follow the TOML groups used by NPP-TOML-Syntax.
  function highlightValue(source, state) {
    let html = '';
    for (let i = 0; i < source.length;) {
      if (state.quote) {
        const end = stringEnd(source, i - state.quote.length, state.quote);
        if (end === -1) {
          html += token(source.slice(i), 'string');
          break;
        }
        html += token(source.slice(i, end), 'string');
        i = end;
        state.quote = '';
        continue;
      }

      if (source[i] === '#') {
        html += token(source.slice(i), 'comment');
        break;
      }
      const triple = source.slice(i, i + 3);
      if (triple === '"""' || triple === "'''") {
        const end = stringEnd(source, i, triple);
        if (end === -1) {
          state.quote = triple;
          html += token(source.slice(i), 'string');
          break;
        }
        html += token(source.slice(i, end), 'string');
        i = end;
        continue;
      }
      if (source[i] === '"' || source[i] === "'") {
        const quote = source[i];
        const end = stringEnd(source, i, quote);
        if (end === -1) {
          html += token(source.slice(i), 'string');
          break;
        }
        html += token(source.slice(i, end), 'string');
        i = end;
        continue;
      }

      const word = source.slice(i).match(/^[^\s,\[\]{}=#]+/);
      if (word) {
        const value = word[0];
        const isNumber = /^[+-]?(?:inf|nan|0x[0-9a-fA-F](?:_?[0-9a-fA-F])*|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*|(?:0|[1-9](?:_?\d)*)(?:\.(?:\d(?:_?\d)*))?(?:[eE][+-]?\d(?:_?\d)*)?)$/.test(value);
        const isDateTime = /^(?:\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/.test(value);
        const kind = /^(?:true|false)$/.test(value) ? 'boolean'
          : isNumber || isDateTime ? 'number' : null;
        html += token(value, kind);
        i += value.length;
        continue;
      }

      const char = source[i++];
      const kind = '[]{}'.includes(char) ? 'delimiter'
        : char === '=' ? 'operator'
          : char === ',' || char === '.' ? 'punctuation' : null;
      html += token(char, kind);
      if (char === '[' || char === '{') state.depth++;
      else if ((char === ']' || char === '}') && state.depth > 0) state.depth--;
    }
    return html;
  }

  function colorizeToml(source) {
    const state = { quote: '', depth: 0 };
    const lines = source.split('\n');
    const html = lines.map((line) => {
      if (!state.quote && state.depth === 0 && /^\s*\[\[?.*\]\]?\s*(?:#.*)?$/.test(line)) {
        const header = line.match(/^(\s*)(\[\[?)(.*?)(\]\]?)(\s*)(#.*)?$/);
        if (header) {
          return escapeHtml(header[1]) + token(header[2], 'header-punctuation')
            + token(header[3], 'section') + token(header[4], 'header-punctuation')
            + escapeHtml(header[5]) + (header[6] ? token(header[6], 'comment') : '');
        }
      }
      const assignment = state.quote || state.depth > 0 ? -1 : findAssignment(line);
      if (assignment >= 0) {
        const prefix = line.slice(0, assignment);
        const key = prefix.match(/^(\s*)(.*?)(\s*)$/);
        if (key && key[2]) {
          return escapeHtml(key[1])
            + token(key[2], 'key')
            + escapeHtml(key[3])
            + token('=', 'operator')
            + highlightValue(line.slice(assignment + 1), state);
        }
      }
      return highlightValue(line, state);
    }).join('\n');
    return html + (source.endsWith('\n') ? ' ' : '');
  }

  function paintHighlight() {
    const source = ed().value;
    highlight().innerHTML = colorizeToml(source);
    highlight().scrollTop = ed().scrollTop;
    highlight().scrollLeft = ed().scrollLeft;
  }

  function paintStatus() {
    const d = dirty();
    const el = $('#cfg-dirty');
    el.textContent = d ? t('unsaved') : t('saved_state');
    el.style.color = d ? 'var(--warn)' : 'var(--ok)';
    $('#cfg-mtime').textContent = cfg && cfg.modified ? t('last_modified') + ': ' + fmtDate(cfg.modified) : '';
  }
  function paintPos() {
    const v = ed().value; const p = ed().selectionStart; const before = v.slice(0, p);
    const line = before.split('\n').length; const col = p - before.lastIndexOf('\n');
    $('#cfg-pos').textContent = t('line_col', { l: line, c: col });
  }
  function result(kind, text, list) {
    const box = clear($('#cfg-result'));
    if (!kind) return;
    box.append(h('div', { class: 'result ' + kind }, text, list && list.length ? h('ul', null, list.map((x) => h('li', null, x))) : null));
  }
  const warnTexts = (codes) => (codes || []).map((c) => t('warn_' + c));

  function paintBackups() {
    const box = clear($('#backups'));
    const list = (cfg && cfg.backups) || [];
    if (!list.length) { box.append(h('div', { class: 'empty' }, t('no_backups'))); return; }
    list.forEach((b) => box.append(h('div', { class: 'li' },
      h('span', { class: 'mono ltr grow' }, b.name),
      h('span', { class: 'mute ltr' }, fmtDate(b.time)),
      h('span', { class: 'mute ltr' }, fmtBytes(b.size)),
      app.state.readOnly ? null : h('button', { class: 'btn sm', type: 'button', onclick: () => restore(b.name) }, t('restore')))));
  }

  function applyServer(c) {
    cfg = c; loaded = true;
    ed().value = c.content;
    ed().setSelectionRange(0, 0);
    ed().scrollTop = 0;
    paintHighlight();
    $('#cfg-path').textContent = c.path;
    $('#cfg-conflict').classList.add('hidden');
    result(null);
    paintStatus(); paintPos(); paintBackups();
  }

  async function load(force) {
    const c = await api('/api/config');
    if (!loaded || force) { applyServer(c); return; }
    cfg.backups = c.backups;
    cfg.modified = c.modified;
    if (c.hash !== cfg.hash) {
      if (dirty()) $('#cfg-conflict').classList.remove('hidden');
      else applyServer(c);
    }
    paintBackups(); paintStatus();
  }

  async function validate() {
    try {
      const r = await api('/api/config/validate', { method: 'POST', body: { content: ed().value } });
      if (r.ok) { result('ok', t('valid_ok'), warnTexts(r.warnings)); return r; }
      result('bad', r.error);
      return r;
    } catch (e) { result('bad', errMsg(e)); return null; }
  }

  async function save() {
    if (app.state.readOnly) return;
    const v = await validate();
    if (!v || !v.ok) return;
    if (!(await confirmDialog(t('confirm_save_title'), t('confirm_save_text'), warnTexts(v.warnings)))) return;
    try {
      const r = await api('/api/config', { method: 'PUT', body: { content: ed().value, base_hash: cfg.hash } });
      cfg.content = ed().value.replace(/\r\n/g, '\n'); ed().value = cfg.content; cfg.hash = r.hash;
      result('ok', t('saved_ok'), warnTexts(r.warnings));
      await load(true);
      result('ok', t('saved_ok'), warnTexts(r.warnings));
    } catch (e) {
      if (e.code === 'conflict') $('#cfg-conflict').classList.remove('hidden');
      result('bad', errMsg(e));
    }
  }

  async function restore(name) {
    if (!(await confirmDialog(t('confirm_restore_title'), t('confirm_restore_text')))) return;
    try { await api('/api/config/restore', { method: 'POST', body: { name } }); toast(t('restored_ok')); await load(true); }
    catch (e) { toast(errMsg(e), true); }
  }

  function downloadConfig() {
    const configuredName = cfg && cfg.path ? cfg.path.split(/[\\/]/).pop() : '';
    const safeName = configuredName.replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_');
    const filename = safeName ? (/\.toml$/i.test(safeName) ? safeName : safeName + '.toml') : 'ghostrpc-config.toml';
    const blob = new Blob([ed().value], { type: 'application/toml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = h('a', { href: url, download: filename });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function renderGuide() {
    if (!guideSamples) return;
    $('#cfg-guide-sample').innerHTML = colorizeToml(guideSamples[guideRole]);
    $('#cfg-guide-client').setAttribute('aria-selected', String(guideRole === 'client'));
    $('#cfg-guide-server').setAttribute('aria-selected', String(guideRole === 'server'));
  }

  async function openGuide() {
    const dialog = $('#cfg-guide-dialog');
    guideRole = app.state.role === 'server' ? 'server' : 'client';
    if (!dialog.open) dialog.showModal();
    if (guideSamples) { renderGuide(); return; }
    $('#cfg-guide-sample').textContent = t('config_guide_loading');
    try {
      guideSamples = await api('/api/config-guide');
      renderGuide();
    } catch (e) {
      $('#cfg-guide-sample').textContent = errMsg(e);
    }
  }

  app.registerPage('config', {
    title: 'nav_config', interval: 10000,
    enter() {
      if (!bound) {
        bound = true;
        ed().addEventListener('input', () => { paintHighlight(); paintStatus(); });
        ed().addEventListener('scroll', () => {
          highlight().scrollTop = ed().scrollTop;
          highlight().scrollLeft = ed().scrollLeft;
        });
        ['keyup', 'click', 'focus'].forEach((ev) => ed().addEventListener(ev, paintPos));
        ed().addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); save(); } });
        $('#cfg-validate').addEventListener('click', validate);
        $('#cfg-save').addEventListener('click', save);
        $('#cfg-download').addEventListener('click', downloadConfig);
        $('#cfg-guide').addEventListener('click', openGuide);
        $('#cfg-guide-client').addEventListener('click', () => { guideRole = 'client'; renderGuide(); });
        $('#cfg-guide-server').addEventListener('click', () => { guideRole = 'server'; renderGuide(); });
        $('#cfg-guide-close').addEventListener('click', () => $('#cfg-guide-dialog').close());
        $('#cfg-guide-dialog').addEventListener('click', (e) => {
          if (e.target === $('#cfg-guide-dialog')) $('#cfg-guide-dialog').close();
        });
        $('#cfg-revert').addEventListener('click', () => { if (cfg) { ed().value = cfg.content; paintHighlight(); result(null); paintStatus(); } });
        $('#cfg-reload-file').addEventListener('click', () => load(true));
        $('#cfg-reload').addEventListener('click', async () => {
          if (!(await confirmDialog(t('confirm_reload_title'), t('confirm_reload_text')))) return;
          try { await api('/api/actions/reload', { method: 'POST' }); toast(t('reload_requested')); } catch (e) { toast(errMsg(e), true); }
        });
        window.addEventListener('beforeunload', (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ''; } });
      }
      $('#cfg-readonly').classList.toggle('hidden', !app.state.readOnly);
      ed().readOnly = app.state.readOnly;
      ['#cfg-save', '#cfg-revert', '#cfg-reload'].forEach((s) => { $(s).disabled = app.state.readOnly; });
      return load(false);
    },
    render: paintStatus
  });
})();
