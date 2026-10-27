(function () {
  'use strict';

  var app = window.GHApp;
  var GH = window.GH;
  var core = app.helpers;
  var $ = core.$;
  var $$ = core.$$;
  var h = core.h;
  var clear = core.clear;
  var ltr = core.ltr;
  var badge = core.badge;
  var fmtBytes = core.fmtBytes;
  var fmtBytesParts = core.fmtBytesParts;
  var fmtClock = core.fmtClock;
  var fmtDate = core.fmtDate;
  var api = core.api;
  var t = GH.t;

  function makeChart(host) {
    var SVG_NS = 'http://www.w3.org/2000/svg';
    var W = 1000, H = 230, PAD_T = 12, PAD_B = 4;
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img');
    var defs = document.createElementNS(SVG_NS, 'defs');
    ['tx', 'rx'].forEach(function (k) {
      var g = document.createElementNS(SVG_NS, 'linearGradient');
      g.setAttribute('id', 'g-' + k);
      g.setAttribute('x1', '0');
      g.setAttribute('y1', '0');
      g.setAttribute('x2', '0');
      g.setAttribute('y2', '1');
      g.setAttribute('class', 'g-' + k);
      g.appendChild(document.createElementNS(SVG_NS, 'stop'));
      g.lastChild.setAttribute('offset', '0');
      g.lastChild.setAttribute('stop-opacity', '0.32');
      g.appendChild(document.createElementNS(SVG_NS, 'stop'));
      g.lastChild.setAttribute('offset', '1');
      g.lastChild.setAttribute('stop-opacity', '0');
      defs.appendChild(g);
    });
    svg.appendChild(defs);
    for (var i = 0; i < 4; i++) {
      var y = PAD_T + ((H - PAD_T - PAD_B) * i) / 3;
      var line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('class', 'grid-line');
      line.setAttribute('x1', '0');
      line.setAttribute('x2', String(W));
      line.setAttribute('y1', String(y));
      line.setAttribute('y2', String(y));
      svg.appendChild(line);
    }
    var areaRx = document.createElementNS(SVG_NS, 'path');
    var areaTx = document.createElementNS(SVG_NS, 'path');
    var lineRx = document.createElementNS(SVG_NS, 'path');
    var lineTx = document.createElementNS(SVG_NS, 'path');
    var cross = document.createElementNS(SVG_NS, 'line');
    areaRx.setAttribute('class', 'area-rx');
    areaTx.setAttribute('class', 'area-tx');
    lineRx.setAttribute('class', 'line rx');
    lineTx.setAttribute('class', 'line tx');
    cross.setAttribute('class', 'cross');
    cross.setAttribute('y1', '0');
    cross.setAttribute('y2', String(H));
    cross.setAttribute('x1', '0');
    cross.setAttribute('x2', '0');
    cross.setAttribute('visibility', 'hidden');
    svg.append(areaRx, areaTx, lineRx, lineTx, cross);
    var ylabs = [0, 1, 2].map(function () { return h('span', { class: 'ylab' }); });
    var xl = h('span', { class: 'xlab' });
    var xr = h('span', { class: 'xlab' });
    var tip = h('div', { class: 'tip hidden' });
    clear(host).append(svg, ...ylabs, xl, xr, tip);
    xr.style.right = '0';

    var pts = [], t0 = 0, span = 900, max = 1;
    var xOf = function (ts) { return ((ts - t0) / span) * W; };
    var yOf = function (v) { return H - PAD_B - (v / max) * (H - PAD_T - PAD_B); };
    var nice = function (v) { if (v <= 0) return 1024; var p = Math.pow(2, Math.ceil(Math.log2(v))); return Math.max(1024, v <= p * 0.6 ? p * 0.75 : p); };
    var path = function (key) {
      return pts.map(function (p, i) {
        return (i ? 'L' : 'M') + xOf(p.t).toFixed(1) + ' ' + yOf(p[key]).toFixed(1);
      }).join('');
    };
    var area = function (key) {
      if (!pts.length) return '';
      return path(key) + 'L' + xOf(pts[pts.length - 1].t).toFixed(1) + ' ' + H + 'L' + xOf(pts[0].t).toFixed(1) + ' ' + H + 'Z';
    };

    function update(points, res) {
      pts = points || [];
      span = res === 'min' ? 86400 : 900;
      var now = pts.length ? pts[pts.length - 1].t : Math.floor(Date.now() / 1000);
      t0 = now - span;
      max = nice(pts.reduce(function (m, p) { return Math.max(m, p.tx, p.rx); }, 0));
      lineTx.setAttribute('d', path('tx'));
      lineRx.setAttribute('d', path('rx'));
      areaTx.setAttribute('d', area('tx'));
      areaRx.setAttribute('d', area('rx'));
      [max, max / 2, 0].forEach(function (v, i) {
        ylabs[i].textContent = fmtBytes(v, true);
      });
      ylabs[0].style.top = (PAD_T / H * 100) + '%';
      ylabs[1].style.top = ((PAD_T + (H - PAD_T - PAD_B) / 2) / H * 100) + '%';
      ylabs[2].style.top = ((H - PAD_B) / H * 100) + '%';
      xl.textContent = fmtClock(t0);
      xr.textContent = fmtClock(now);
    }

    host.addEventListener('pointermove', function (e) {
      if (!pts.length) return;
      var r = host.getBoundingClientRect();
      var fx = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
      var ts = t0 + fx * span;
      var best = pts[0];
      for (var i = 0; i < pts.length; i++) {
        if (Math.abs(pts[i].t - ts) < Math.abs(best.t - ts)) best = pts[i];
      }
      var x = (xOf(best.t) / W) * r.width;
      cross.setAttribute('x1', xOf(best.t));
      cross.setAttribute('x2', xOf(best.t));
      cross.setAttribute('visibility', 'visible');
      clear(tip).append(
        h('div', { class: 'mute' }, fmtDate(best.t)),
        h('div', null, h('span', { class: 'dot tx' }), ltr(fmtBytes(best.tx, true))),
        h('div', null, h('span', { class: 'dot rx' }), ltr(fmtBytes(best.rx, true))),
        h('div', { class: 'mute' }, t('active_streams') + ': ', ltr(String(best.streams)))
      );
      tip.classList.remove('hidden');
      tip.style.left = Math.min(Math.max(x + 12, 0), Math.max(0, r.width - 170)) + 'px';
    });
    host.addEventListener('pointerleave', function () { cross.setAttribute('visibility', 'hidden'); tip.classList.add('hidden'); });
    return { update: update };
  }

  var chart = null;
  var res = 'sec';
  var ov = null;
  var series = [];

  function setRate(id, val) {
    var p = fmtBytesParts(val, true);
    var el = $(id);
    clear(el).append(p.v, h('small', null, p.u));
  }

  function kv(dl, rows) {
    clear(dl);
    rows.forEach(function (row) {
      var k = row[0];
      var v = row[1];
      if (v !== null && v !== undefined) dl.append(h('dt', null, k), h('dd', null, v));
    });
  }

  function chips(list) {
    return h('div', { class: 'chips' }, (list || []).map(function (x, i) {
      return h('span', { class: 'chip' + (i === 0 ? ' on' : '') }, x);
    }));
  }

  function onoff(b) { return badge(b ? t('on') : t('off'), b ? 'ok' : 'mute'); }

  function renderState() {
    var dot = $('#kpi-state-dot');
    var val = $('#kpi-state');
    var sub = $('#kpi-state-sub');
    var kind = 'ok';
    var title = t('st_running');
    var text = t('st_sub_server');
    if (ov.role === 'client') {
      var m = { direct: ['ok', 'st_direct', 'st_sub_direct'], reverse: ['ok', 'st_reverse', 'st_sub_reverse'], starting: ['warn', 'st_starting', 'st_sub_starting'], unavailable: ['bad', 'st_unavailable', 'st_sub_unavailable'] };
      var x = m[ov.path] || m.starting;
      kind = x[0]; title = t(x[1]); text = t(x[2]);
    } else if (ov.role !== 'server') { kind = 'warn'; title = t('st_starting'); text = t('st_sub_unknown'); }
    dot.className = 'dot ' + kind;
    val.textContent = title; sub.textContent = text;
  }

  function renderRoute() {
    var box = clear($('#route'));
    var node = function (icon, title, sub, kind) {
      return h('div', { class: 'node' + (kind ? ' node-' + kind : '') },
        h('span', { class: 'node-icon' }, GH.icon(icon)),
        h('div', { class: 'node-copy' }, h('b', null, title), h('span', null, sub || '\u00a0')));
    };
    var link = function (tag, live) {
      return h('div', { class: 'link' + (live ? ' live' : '') },
        h('span', { class: 'link-line' }),
        tag ? h('span', { class: 'tag' }, tag) : null);
    };
    var streams = ov.streams.active + ' ' + t('route_streams');
    if (ov.role === 'client') {
      var live = ov.path === 'direct' || ov.path === 'reverse';
      box.append(node('connections', t('route_users'), t('kind_user'), 'muted'),
        link(t('tag_tunnel'), ov.streams.active > 0),
        node('dashboard', t('route_this_client'), streams, 'local'),
        link(ov.path === 'reverse' ? t('tag_reverse') : t('tag_direct'), live),
        node('tunnels', t('route_remote_server'), ov.sessions.total + ' ' + t('route_tunnels'), live ? 'live' : 'muted'),
        link('', live && ov.streams.active > 0),
        node('connections', t('route_targets'), t('target'), 'muted'));
    } else {
      box.append(node('connections', t('route_remote_client'), ov.sessions.total + ' ' + t('route_tunnels'), ov.sessions.total > 0 ? 'live' : 'muted'),
        link(t('tag_tunnel'), ov.sessions.total > 0),
        node('tunnels', t('route_this_server'), streams, 'local'),
        link('', ov.streams.active > 0),
        node('connections', t('route_targets'), t('target'), 'muted'));
    }
  }

  function renderSummary() {
    var c = ov.config, dl = $('#summary');
    if (!c || c.role === 'unknown') { clear(dl); return; }
    var rows = [];
    rows.push([t('sum_protocols'), chips(c.protocols)]);
    if (c.role === 'server') {
      rows.push([t('sum_listen'), ltr(c.bind_addr || '—', 'mono')]);
      rows.push([t('sum_tunnel_sni'), (c.tunnel_sni && c.tunnel_sni.length) ? chips(c.tunnel_sni) : t('none')]);
      rows.push([t('sum_camouflage'), c.camouflage_target ? ltr(c.camouflage_target, 'mono') : t('none')]);
      rows.push([t('sum_dialers'), String((c.reverse || []).length)]);
      rows.push([t('sum_sni_proxy'), String((c.sni_proxy || []).length)]);
      rows.push([t('sum_web'), t('routes_n', { n: (c.web_server || []).length })]);
    } else {
      rows.push([t('sum_remotes'), String((c.remotes || []).length)]);
      rows.push([t('sum_pool'), String(c.pool_size_per_node)]);
      rows.push([t('sum_reverse_bind'), c.reverse_bind_addr ? ltr(c.reverse_bind_addr, 'mono') : t('off')]);
      rows.push([t('sum_scanner'), c.scanner_cdn || 'auto']);
      rows.push([t('sum_sni_proxy'), String((c.sni_proxy || []).length)]);
      rows.push([t('sum_web'), t('routes_n', { n: (c.web_server || []).length })]);
    }
    rows.push([t('sum_secret'), badge(c.secret_set ? t('secret_set') : t('secret_unset'), c.secret_set ? 'ok' : 'warn')]);
    rows.push([t('sum_acme'), onoff(c.acme)]);
    kv(dl, rows);
    Array.from(dl.children).forEach(function (item, index) {
      item.classList.add(index % 2 === 0 ? 'summary-label' : 'summary-value');
    });
  }

  function renderSystem() {
    var s = ov.system || {}, grid = clear($('#system'));
    var bar = function (frac, kind) {
      var i = h('i', { class: 'b-' + kind });
      i.style.width = Math.min(100, Math.max(0, frac * 100)).toFixed(1) + '%';
      return h('div', { class: 'bar' }, i);
    };
    var metric = function (icon, label, value, detail, meter) {
      grid.append(h('article', { class: 'resource-card' },
        h('div', { class: 'resource-heading' }, h('span', { class: 'resource-icon' }, GH.icon(icon)), h('span', null, label)),
        h('div', { class: 'resource-value' }, value),
        detail ? h('div', { class: 'resource-detail' }, detail) : null,
        meter ? h('div', { class: 'resource-meter' }, meter) : null));
    };
    if (s.host) metric('dashboard', t('sys_host'), ltr(s.host, 'mono'), null);
    metric('tunnels', t('sys_cpu'), t('cores', { n: s.cpus || 1 }), null);
    if (s.load && s.load.length) {
      var frac = s.load[0] / (s.cpus || 1);
      metric('dashboard', t('sys_load'), ltr(s.load.map(function (x) { return x.toFixed(2); }).join('  '), 'num'),
        null, bar(frac, frac > 1 ? 'bad' : frac > 0.7 ? 'warn' : 'ok'));
    }
    if (s.mem_total) {
      var used = s.mem_total - (s.mem_available || 0);
      var memoryFraction = used / s.mem_total;
      metric('account', t('sys_memory'), ltr(fmtBytes(used) + ' / ' + fmtBytes(s.mem_total), 'num'),
        Math.round(memoryFraction * 100) + '%', bar(memoryFraction, memoryFraction > 0.9 ? 'bad' : memoryFraction > 0.75 ? 'warn' : 'ok'));
    }
    if (s.rss) metric('connections', t('sys_process'), ltr(fmtBytes(s.rss), 'num'), null);
    if (s.threads) metric('connections', t('sys_threads'), ltr(String(s.threads), 'num'), null);
    if (s.fds) {
      var fdFraction = s.fd_limit ? s.fds / s.fd_limit : 0;
      metric('config', t('sys_fds'), ltr(s.fds + (s.fd_limit ? ' / ' + s.fd_limit : ''), 'num'),
        null, s.fd_limit ? bar(fdFraction, fdFraction > 0.8 ? 'bad' : 'ok') : null);
    }
  }

  function render() {
    if (!ov) return;
    $('#role-badge').textContent = t('role_' + ov.role);
    $('#version').textContent = 'v' + ov.version;
    setRate('#tx-rate', ov.traffic.tx_rate); setRate('#rx-rate', ov.traffic.rx_rate);
    $('#tx-total').textContent = fmtBytes(ov.traffic.tx_total); $('#rx-total').textContent = fmtBytes(ov.traffic.rx_total);
    renderState();
    $('#kpi-streams').textContent = ov.streams.active;
    $('#kpi-streams-total').textContent = ov.streams.total;
    $('#kpi-sessions').textContent = ov.sessions.total;
    clear($('#kpi-sessions-sub')).append(
      h('span', { class: 'session-protocol session-h2' }, h('span', { class: 'session-protocol-name' }, 'HTTP/2'), h('b', null, String(ov.sessions.h2))),
      h('span', { class: 'session-protocol session-wssmux' }, h('span', { class: 'session-protocol-name' }, 'WssMux'), h('b', null, String(ov.sessions.wssmux))));
    $('#kpi-rejected').closest('.card').classList.toggle('hidden', ov.role !== 'server');
    $('#kpi-rejected').textContent = ov.unauthorized;
    renderRoute(); renderSummary(); renderSystem();
    if (chart) chart.update(series, res);
  }

  app.registerPage('dashboard', {
    title: 'nav_dashboard', interval: 2000,
    enter: function () {
      if (!chart) {
        chart = makeChart($('#chart'));
        $$('#range-seg button').forEach(function (b) {
          b.addEventListener('click', function () {
            res = b.dataset.res;
            $$('#range-seg button').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
            app.pages.dashboard.refresh();
          });
        });
      }
    },
    refresh: async function () {
      var o = await api('/api/overview');
      var s = await api('/api/series?res=' + res);
      ov = o; app.state.ov = o; series = s.points;
      render();
    },
    render: render
  });
})();
