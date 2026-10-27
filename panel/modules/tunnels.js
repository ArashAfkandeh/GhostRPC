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
  const api = helpers.api;
  const confirmDialog = helpers.confirmDialog;
  const toast = helpers.toast;

  let data = null, ov = null, cleanListOpen = false, clearingCleanIps = false, eventsBound = false;
  const chips = (list, onFirst) => h('div', { class: 'chips' }, (list || []).map((x, i) => h('span', { class: 'chip' + (onFirst && i === 0 ? ' on' : '') }, x)));
  const empty = (cols, text) => h('tr', null, h('td', { colspan: cols, class: 'empty' }, text));

  function renderProtos() {
    const box = clear($('#protos'));
    const currentType = clear($('#current-tunnel-type'));
    const list = (data.client && data.client.protocols) || (ov && ov.config && ov.config.protocols) || [];
    list.forEach((p, i) => box.append(h('span', { class: 'chip' + (i === 0 ? ' on' : '') }, ltr((i + 1) + '.'), ' ', p === 'h2' ? 'HTTP/2 (gRPC)' : 'WssMux')));
    if (data.server) {
      const a = data.server.accepts;
      box.append(h('span', { class: 'mute' }, t('server_accepts') + ':'),
        badge('HTTP/2', a.h2 ? 'ok' : 'mute'), badge('WssMux', a.wssmux ? 'ok' : 'mute'));
    }
    if (data.role === 'client') {
      const path = data.client && data.client.path;
      const pathKey = path === 'direct' ? 'direct' : path === 'reverse' ? 'reverse' : 'unavailable';
      currentType.append(h('span', { class: 'current-tunnel-label' }, t('current_tunnel_type') + ':'),
        badge(t('tunnel_path_' + pathKey), pathKey === 'unavailable' ? 'warn' : 'ok'));
    }
  }

  const leg = (cls, label, n) => h('span', { class: 'leg' }, h('span', { class: 'dot ' + cls }), label + ' ', ltr(String(n)));

  function renderNodes() {
    const section = $('#direct-nodes-section'); const body = clear($('#nodes'));
    $('#nodes-card').classList.toggle('hidden', data.role !== 'client');
    section.classList.toggle('hidden', data.role !== 'client');
    if (data.role !== 'client') return;
    const c = data.client;
    if (!c || !c.nodes.length) { body.append(empty(5, t('no_nodes'))); return; }
    c.nodes.forEach((n) => {
      const up = n.h2 + n.wssmux;
      const kind = up === 0 ? 'bad' : n.down > 0 ? 'warn' : 'ok';
      const seg = (cls, v) => { const i = h('i', { class: cls }); i.style.width = (v / n.slots * 100).toFixed(1) + '%'; return i; };
      body.append(h('tr', null,
        h('td', null, n.location || '—'),
        h('td', null, ltr(n.sni, 'mono')),
        h('td', null,
          h('div', { class: 'bar' }, seg('b-h2', n.h2), seg('b-ws', n.wssmux)),
          h('div', { class: 'row legend' }, leg('tx', 'HTTP/2', n.h2), leg('rx', 'WssMux', n.wssmux), leg('idle', t('legend_down'), n.down))),
        h('td', null, n.latency_ms === null || n.latency_ms === undefined ? '—' : ltr(n.latency_ms + ' ms')),
        h('td', null, h('div', { class: 'row' },
          badge(kind === 'ok' ? t('healthy') : kind === 'warn' ? t('degraded') : t('offline'), kind),
          n.cooling_h2 ? badge('HTTP/2 ' + t('cooling'), 'warn') : null,
          n.cooling_wssmux ? badge('WssMux ' + t('cooling'), 'warn') : null))));
    });
  }

  function renderReverse() {
    const body = clear($('#reverse')); const r = data.reverse;
    if (data.role === 'server') {
      $('#reverse-title').textContent = t('dialers_title');
      const list = (ov && ov.config && ov.config.reverse) || [];
      if (!list.length) { body.append(empty(5, t('no_dialers'))); return; }
      list.forEach((d) => {
        const host = String(d.sni || '').split(':')[0];
        const live = data.sessions.filter((s) => s.dir === 'out' && s.kind === 'reverse' && s.peer === host).length;
        const slots = Number(d.pool_size) || 0;
        const sni = d.sni || (d.clean_ip || [])[0] || '—';
        body.append(h('tr', null,
          h('td', null, d.location || '—'),
          h('td', null, ltr(sni, 'mono')),
          h('td', null,
            h('div', { class: 'bar' }, h('i', { class: 'b-ws', style: 'width:' + (slots ? Math.min(100, live / slots * 100).toFixed(1) : 0) + '%' })),
            h('div', { class: 'row legend' }, leg('rx', t('active_tunnels'), live), leg('idle', t('pool'), slots))),
          h('td', null, '—'),
          h('td', null, badge(live ? t('healthy') : t('reverse_waiting'), live ? 'ok' : 'warn'))));
      });
      return;
    }
    $('#reverse-title').textContent = t('reverse_title');
    if (!r || !r.enabled) { body.append(empty(5, t('reverse_disabled'))); return; }
    (r.groups || []).forEach((g) => {
      const parked = Number(g.parked) || 0;
      const sessions = Number(g.wssmux_sessions) || 0;
      const total = parked + sessions;
      body.append(h('tr', null,
        h('td', null, g.location || t('group_unlabeled')),
        h('td', null, '—'),
        h('td', null,
          h('div', { class: 'bar' },
            h('i', { class: 'b-h2', style: 'width:' + (total ? (parked / total * 100).toFixed(1) : 0) + '%' }),
            h('i', { class: 'b-ws', style: 'width:' + (total ? (sessions / total * 100).toFixed(1) : 0) + '%' })),
          h('div', { class: 'row legend' }, leg('tx', t('parked'), parked), leg('rx', t('ws_sessions'), sessions))),
        h('td', null, g.latency_ms === null || g.latency_ms === undefined ? '—' : ltr(g.latency_ms + ' ms')),
        h('td', null, badge(total ? t('reverse_ready') : t('reverse_waiting'), total ? 'ok' : 'warn'))));
    });
    if (!(r.groups || []).length) body.append(empty(5, t('no_reverse_groups')));
  }

  function renderClean() {
    const card = $('#clean-card'); const box = clear($('#clean'));
    const rescan = $('#rescan-clean-ips');
    const isClient = data.role === 'client';
    const hasClientData = isClient && data.client && data.client.clean_ips;
    const serverEntries = !isClient && data.role === 'server' && data.reverse
      ? (data.reverse.clean_ips || []) : [];
    card.classList.toggle('hidden', isClient && !hasClientData);
    rescan.classList.toggle('hidden', !isClient);
    if (isClient) {
      if (!hasClientData) return;
      const ips = data.client.clean_ips;
      const list = Array.isArray(ips.list) ? ips.list : [];
      rescan.disabled = clearingCleanIps || app.state.readOnly || !ips.scanner_running;
      rescan.title = ips.scanner_running ? '' : t('clean_ips_scan_unavailable');
      box.append(h('div', { class: 'kpi' },
        h('div', { class: 'value num' }, Number(ips.count) || list.length),
        h('div', { class: 'sub' }, t('ip_count', { n: Number(ips.count) || list.length }))));
      if (!list.length) {
        box.append(h('p', { class: 'mute' }, t('no_ips')));
        return;
      }
      box.append(cleanIpDetails(list));
      return;
    }

    rescan.disabled = true;
    if (!serverEntries.length) {
      box.append(h('p', { class: 'mute' }, t('no_ips')));
      return;
    }
    serverEntries.forEach((entry) => {
      const list = Array.isArray(entry.list) ? entry.list : [];
      box.append(h('div', { class: 'kpi' },
        h('div', { class: 'value num' }, Number(entry.count) || list.length),
        h('div', { class: 'sub' }, [
          entry.location,
          entry.sni,
          t('ip_count', { n: Number(entry.count) || list.length })
        ].filter(Boolean).join(' · '))));
      if (list.length) box.append(cleanIpDetails(list));
      else box.append(h('p', { class: 'mute' }, t('no_ips')));
    });
  }

  function cleanIpDetails(list) {
    const details = h('details', { class: 'fold', open: cleanListOpen },
      h('summary', null, t('show_ips')),
      h('div', { class: 'chips' }, list.map((ip) => h('span', { class: 'chip' }, ip))));
    details.addEventListener('toggle', () => { cleanListOpen = details.open; });
    return details;
  }

  function renderDead() {
    const box = clear($('#dead'));
    const list = Array.isArray(data.dead_targets) ? data.dead_targets : [];
    if (!list.length) { box.append(h('span', { class: 'mute' }, t('no_dead_targets'))); return; }
    list.forEach((x) => box.append(h('span', { class: 'chip' }, x)));
  }

  function render() {
    if (!data) return;
    renderProtos(); renderNodes(); renderReverse(); renderClean(); renderDead();
  }

  app.registerPage('tunnels', {
    title: 'nav_tunnels', interval: 5000,
    enter() {
      if (eventsBound) return;
      eventsBound = true;
      $('#rescan-clean-ips').addEventListener('click', async () => {
        if (clearingCleanIps || !data || data.role !== 'client' || !data.client || !data.client.clean_ips.scanner_running) return;
        if (!(await confirmDialog(t('confirm_clean_ips_title'), t('confirm_clean_ips_text')))) return;
        clearingCleanIps = true;
        $('#rescan-clean-ips').disabled = true;
        try {
          const result = await api('/api/actions/rescan-clean-ips', { method: 'POST' });
          cleanListOpen = false;
          toast(t('clean_ips_scan_requested', { n: result.cleared }));
          await app.pages.tunnels.refresh();
        } catch (e) {
          toast(helpers.errMsg(e), true);
        } finally {
          clearingCleanIps = false;
          renderClean();
        }
      });
    },
    async refresh() {
      const [next, overview] = await Promise.all([api('/api/tunnels'), api('/api/overview')]);
      data = next; ov = overview;
      render();
    },
    render
  });
})();
