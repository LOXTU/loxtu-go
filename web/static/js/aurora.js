/**
 * LoxTu Go — Aurora v4
 * Free-floating · mouse repel · attract + pulse · detail panel
 * Single rAF loop · no deps
 */
(function () {
  'use strict';

  var CLOUD_CONFIGS = [
    { size: 450, color: 'rgba(45,212,191,0.25)', blur: 80 },
    { size: 350, color: 'rgba(13,148,136,0.3)', blur: 90 },
    { size: 500, color: 'rgba(244,183,64,0.2)', blur: 100 },
    { size: 300, color: 'rgba(45,212,191,0.2)', blur: 70 },
    { size: 400, color: 'rgba(13,148,136,0.25)', blur: 85 },
  ];

  var LIGHT_CLOUDS = [
    { size: 420, color: 'rgba(200,210,220,0.2)', blur: 80 },
    { size: 380, color: 'rgba(220,228,235,0.25)', blur: 90 },
    { size: 480, color: 'rgba(180,192,205,0.15)', blur: 100 },
    { size: 320, color: 'rgba(210,218,228,0.2)', blur: 70 },
    { size: 360, color: 'rgba(190,200,212,0.2)', blur: 85 },
  ];

  var clouds = [];
  var mouseX = -1000, mouseY = -1000;
  var isAttracted = false;
  var attractedEl = null;
  var attractPositions = [];
  var rafId = null;
  var dispersalCount = 0;

  // ── Init ──
  document.addEventListener('DOMContentLoaded', init);
  document.addEventListener('htmx:afterSwap', onAfterSwap);

  function init() {
    var bg = document.getElementById('aurora-background');
    if (!bg) return;
    // Only build if empty (HTMX may re-fire)
    if (bg.children.length > 0) return;
    rebuild(bg);
    enableCloudAttraction('#auth-container');
    enableCloudAttraction('.card-glass');
    enableCloudAttraction('.bento-item');
    rafId = requestAnimationFrame(loop);
  }

  // ── Theme change: rebuild clouds ──
  function rebuild(bg) {
    bg = bg || document.getElementById('aurora-background');
    if (!bg) return;
    bg.innerHTML = '';
    var theme = document.documentElement.getAttribute('data-theme');
    var configs = theme === 'light' ? LIGHT_CLOUDS : CLOUD_CONFIGS;
    buildClouds(bg, configs);
  }

  window.addEventListener('themeChanged', function () {
    cancelAnimationFrame(rafId);
    rebuild();
    rafId = requestAnimationFrame(loop);
  });

  function onAfterSwap(e) {
    var t = e.detail && e.detail.target;
    if (!t) return;
    // Re-init background if HTMX cleared it
    if (t.id === 'auth-container' || t.id === 'dashboard-grid') {
      var bg = document.getElementById('aurora-background');
      if (bg && bg.children.length === 0) buildClouds(bg);
    }
    // Detail panel open
    if (t.id === 'detail-panel-content') {
      var p = document.getElementById('detail-panel');
      var o = document.getElementById('detail-overlay');
      if (p) p.classList.add('open');
      if (o) o.classList.add('open');
    }
  }

  // ── Build ──
  function buildClouds(bg, configs) {
    configs = configs || CLOUD_CONFIGS;
    clouds = [];
    var w = window.innerWidth, h = window.innerHeight;
    configs.forEach(function (cfg) {
      var el = document.createElement('div');
      el.className = 'aurora-cloud';
      el.style.cssText = [
        'position:absolute;border-radius:50%;',
        'filter:blur(' + cfg.blur + 'px);-webkit-filter:blur(' + cfg.blur + 'px);',
        'opacity:0.35;will-change:transform;pointer-events:none;',
        'width:' + cfg.size + 'px;height:' + cfg.size + 'px;',
        'background:radial-gradient(circle,' + cfg.color + ',transparent 70%);',
      ].join('');
      bg.appendChild(el);
      clouds.push({
        el: el, size: cfg.size,
        x: Math.random() * (w - cfg.size),
        y: Math.random() * (h - cfg.size),
        vx: (Math.random() - 0.5) * 0.6,
        vy: (Math.random() - 0.5) * 0.6,
        phase: Math.random() * Math.PI * 2,
      });
    });
  }

  // ── Main loop: free float OR attract pulse ──
  function loop() {
    var w = window.innerWidth, h = window.innerHeight;
    var now = Date.now() / 1000;

    clouds.forEach(function (c) {
      if (isAttracted && attractedEl) {
        // Pulsing around attracted element
        var base = attractPositions[clouds.indexOf(c) % attractPositions.length];
        if (!base) return;
        var ox = Math.sin(now * 0.8 + c.phase) * 8;
        var oy = Math.cos(now * 0.6 + c.phase) * 8;
        // Mouse push during pulse
        var dx = mouseX - (base.x + c.size / 2);
        var dy = mouseY - (base.y + c.size / 2);
        var dist = Math.sqrt(dx * dx + dy * dy);
        var pushX = 0, pushY = 0;
        if (dist < 150 && dist > 1) {
          var f = (150 - dist) / 150;
          pushX = -dx * f * 0.12;
          pushY = -dy * f * 0.12;
        }
        c.el.style.transform = 'translate(' + (base.x + ox + pushX) + 'px,' + (base.y + oy + pushY) + 'px)';
        c.el.style.opacity = '0.55';
        return;
      }

      // Free float
      c.phase += 0.008;
      var nx = c.x + c.vx + Math.sin(c.phase) * 0.4;
      var ny = c.y + c.vy + Math.cos(c.phase * 0.7) * 0.4;

      // Mouse repel
      if (mouseX > -500) {
        var dx = c.x + c.size / 2 - mouseX;
        var dy = c.y + c.size / 2 - mouseY;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 250 && dist > 1) {
          var force = (250 - dist) / 250 * 1.2;
          nx += (dx / dist) * force;
          ny += (dy / dist) * force;
        }
      }

      // Bounce off walls
      if (nx < -c.size * 0.3) { nx = -c.size * 0.3; c.vx *= -0.5; }
      if (nx > w - c.size * 0.7) { nx = w - c.size * 0.7; c.vx *= -0.5; }
      if (ny < -c.size * 0.3) { ny = -c.size * 0.3; c.vy *= -0.5; }
      if (ny > h - c.size * 0.7) { ny = h - c.size * 0.7; c.vy *= -0.5; }

      c.x = nx; c.y = ny;
      c.el.style.transform = 'translate(' + nx + 'px,' + ny + 'px)';
      c.el.style.opacity = '0.35';
    });

    rafId = requestAnimationFrame(loop);
  }

  // ── Attraction on mouseenter ──
  function enableCloudAttraction(sel) {
    document.querySelectorAll(sel).forEach(function (el) {
      el.addEventListener('mouseenter', function () { attractCloudsTo(el, true); });
      el.addEventListener('mouseleave', function () { attractCloudsTo(el, false); });
    });
  }

  function attractCloudsTo(el, enter) {
    if (enter && !isAttracted) {
      isAttracted = true;
      attractedEl = el;
      var rect = el.getBoundingClientRect();
      var pad = 60;
      attractPositions = [
        { x: rect.left - pad - 120, y: rect.top - pad - 120 },
        { x: rect.right + pad - 50, y: rect.top - pad - 80 },
        { x: rect.left - pad - 80, y: rect.bottom + pad - 100 },
        { x: rect.right + pad - 120, y: rect.bottom + pad - 120 },
        { x: (rect.left + rect.right) / 2 - 200, y: rect.top - pad * 1.5 },
      ];

      var pending = clouds.length;
      clouds.forEach(function (c, i) {
        var pos = attractPositions[i % attractPositions.length];
        var anim = c.el.animate([
          { transform: 'translate(' + c.x + 'px,' + c.y + 'px)', opacity: '0.35' },
          { transform: 'translate(' + pos.x + 'px,' + pos.y + 'px)', opacity: '0.55' },
        ], { duration: 2000, easing: 'cubic-bezier(0.16,1,0.3,1)', fill: 'forwards' });
        anim.onfinish = function () {
          c.x = pos.x; c.y = pos.y;
          pending--;
          if (pending === 0) {
            // Pulsation starts automatically via loop (isAttracted = true)
          }
        };
      });
      el.classList.add('aurora-attract');
    }

    if (!enter && isAttracted && attractedEl === el) {
      isAttracted = false;
      attractedEl = null;
      el.classList.remove('aurora-attract');

      // Dispersal: animate to random positions over 2s
      var w = window.innerWidth, h = window.innerHeight;
      dispersalCount = clouds.length;
      clouds.forEach(function (c) {
        var tx = Math.random() * (w - c.size) * 0.8 + w * 0.1;
        var ty = Math.random() * (h - c.size) * 0.8 + h * 0.1;
        c.el.animate([
          { transform: 'translate(' + c.x + 'px,' + c.y + 'px)', opacity: '0.55' },
          { transform: 'translate(' + tx + 'px,' + ty + 'px)', opacity: '0.35' },
        ], { duration: 2000, easing: 'cubic-bezier(0.16,1,0.3,1)', fill: 'forwards' });
        c.x = tx; c.y = ty;
        c.vx = (Math.random() - 0.5) * 0.6;
        c.vy = (Math.random() - 0.5) * 0.6;
        c.el.style.opacity = '0.35';
        c.el.style.transform = 'translate(' + tx + 'px,' + ty + 'px)';
      });
    }
  }

  // ── Detail panel ──
  function closeDetail() {
    var p = document.getElementById('detail-panel');
    var o = document.getElementById('detail-overlay');
    if (p) p.classList.remove('open');
    if (o) o.classList.remove('open');
  }

  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('#detail-overlay')) closeDetail();
    if (e.target.closest && e.target.closest('.close-btn')) closeDetail();
  });

  document.addEventListener('mousemove', function (e) {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });
})();