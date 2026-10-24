'use strict';
/*
 * TrustVault motion controller. Purely cosmetic: it never touches data, forms or the API, and the site works
 * without it. Loaded in <head> (not deferred) so `html.fx` is set before first paint and the entrance animations
 * start from their hidden state instead of flashing. It uses only DOM APIs the CSP allows (classList, CSSOM
 * style.setProperty); no inline styles or scripts, no innerHTML.
 */
(() => {
  const root = document.documentElement;
  root.classList.add('fx');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (s, r = document) => r.querySelector(s);
  const rand = (a, b) => a + Math.random() * (b - a);

  // ---------------------------------------------------------------- fireflies
  function fireflies(count) {
    if (reduce) return;
    const layer = document.createElement('div');
    layer.className = 'fireflies';
    layer.setAttribute('aria-hidden', 'true');
    for (let i = 0; i < count; i++) {
      const f = document.createElement('span');
      f.className = 'fly';
      const s = rand(2.5, 5);
      f.style.setProperty('--x', `${rand(2, 98).toFixed(1)}%`);
      f.style.setProperty('--y', `${rand(4, 96).toFixed(1)}%`);
      f.style.setProperty('--s', `${s.toFixed(1)}px`);
      f.style.setProperty('--dx', `${rand(-90, 90).toFixed(0)}px`);
      f.style.setProperty('--dy', `${rand(-110, 70).toFixed(0)}px`);
      f.style.setProperty('--dur', `${rand(9, 20).toFixed(1)}s`);
      f.style.setProperty('--blink', `${rand(2.4, 6).toFixed(1)}s`);
      f.style.setProperty('--delay', `${(-rand(0, 12)).toFixed(1)}s`);
      f.style.setProperty('--peak', rand(0.55, 1).toFixed(2));
      layer.append(f);
    }
    document.body.prepend(layer);
  }

  // ---------------------------------------------------------------- count-up numbers
  function countUp(el) {
    const target = Number(el.textContent);
    if (!Number.isFinite(target) || reduce || target === 0) return;
    el.textContent = '0';
    const txt = el.firstChild;
    const t0 = performance.now();
    const dur = 900 + Math.min(target, 200) * 3;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      txt.data = String(Math.round(target * (1 - Math.pow(1 - p, 3)))); // characterData only: does not re-trigger the observer
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ---------------------------------------------------------------- tag freshly rendered content for entrance animation
  const SEL = '#main > h1, #main > h2, #main > .lede, #main > p, #main > .card, #main > .grid > *, #main > .table-wrap, #main > .alert, #main > div > .card, #main > div > .table-wrap, #main > div > h2, #main > div > .alert, #main > div > p';
  let queued = false;
  function enhance() {
    queued = false;
    let i = 0;
    for (const el of document.querySelectorAll(SEL)) {
      if (el.classList.contains('fx-in')) continue;
      el.classList.add('fx-in');
      el.style.setProperty('--d', `${Math.min(i++ * 0.07, 0.8).toFixed(2)}s`);
    }
    for (const table of document.querySelectorAll('#main tbody')) {
      let r = 0;
      for (const tr of table.children) {
        if (tr.classList.contains('fx-row')) { r++; continue; }
        tr.classList.add('fx-row');
        tr.style.setProperty('--d', `${(0.25 + Math.min(r++ * 0.045, 0.7)).toFixed(2)}s`);
      }
    }
    let n = 0;
    for (const a of document.querySelectorAll('#nav a:not(.fx-nav)')) { a.classList.add('fx-nav'); a.style.setProperty('--i', String(n++)); }
    for (const b of document.querySelectorAll('.stat > b:not([data-counted])')) {
      b.dataset.counted = '1';
      if (/^\d+$/.test(b.textContent)) countUp(b);
    }
  }
  function schedule() { if (!queued) { queued = true; requestAnimationFrame(enhance); } }

  // ---------------------------------------------------------------- button ripple
  document.addEventListener('pointerdown', (ev) => {
    if (reduce) return;
    const btn = ev.target.closest && ev.target.closest('button');
    if (!btn || btn.disabled || btn.classList.contains('link') || btn.classList.contains('lamp-pull') || btn.classList.contains('page-lamp-btn')) return;
    const box = btn.getBoundingClientRect();
    const dot = document.createElement('span');
    dot.className = 'ripple';
    dot.style.setProperty('left', `${ev.clientX - box.left}px`);
    dot.style.setProperty('top', `${ev.clientY - box.top}px`);
    btn.append(dot);
    setTimeout(() => dot.remove(), 700);
  });

  // ---------------------------------------------------------------- page-to-page transition (dim, then navigate)
  document.addEventListener('click', (ev) => {
    if (reduce || ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    const a = ev.target.closest && ev.target.closest('a[href]');
    if (!a || (a.target && a.target !== '_self') || a.hasAttribute('download')) return;
    const url = new URL(a.href, location.href);
    if (url.origin !== location.origin || (url.pathname === location.pathname && url.search === location.search)) return;
    ev.preventDefault();
    root.classList.add('leaving');
    setTimeout(() => { location.href = url.href; }, 260);
  });
  window.addEventListener('pageshow', (e) => { if (e.persisted) root.classList.remove('leaving'); });

  // ---------------------------------------------------------------- login: the lamp
  function lampScene() {
    const body = document.body;
    const scene = $('#lamp');
    const pull = $('#lamp-pull');
    const card = $('.auth-card');
    if (!scene || !pull) { body.classList.add('lit', 'ready', 'settled'); return; }
    let on = false;
    const timers = [];
    const later = (fn, ms) => timers.push(setTimeout(fn, ms));

    function setLamp(next, { flicker = false } = {}) {
      on = next;
      scene.classList.toggle('on', on);
      pull.setAttribute('aria-pressed', String(on));
      pull.setAttribute('aria-label', on ? 'Switch the lamp off' : 'Switch the lamp on');
      scene.classList.remove('pull'); void scene.getBoundingClientRect(); scene.classList.add('pull');
      if (flicker && on && !reduce) { scene.classList.remove('flicker'); void scene.getBoundingClientRect(); scene.classList.add('flicker'); }
      body.classList.toggle('lit', on);
    }

    pull.addEventListener('click', () => { timers.forEach(clearTimeout); body.classList.add('ready', 'settled'); setLamp(!on, { flicker: true }); });
    // keyboard users who tab into the form should never be left in the dark
    card.addEventListener('focusin', () => { if (!on) setLamp(true, { flicker: true }); });

    if (reduce) { body.classList.add('ready', 'settled'); setLamp(true); return; }

    // the intro: copy fades in, the cord is pulled, the bulb flickers on, the form comes into focus
    later(() => body.classList.add('ready'), 150);
    later(() => setLamp(true, { flicker: true }), 1100);
    later(() => body.classList.add('settled'), 4200);

    // soft highlight that follows the cursor across the glass card
    card.addEventListener('pointermove', (e) => {
      const b = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${e.clientX - b.left}px`);
      card.style.setProperty('--my', `${e.clientY - b.top}px`);
    });

    // wrong password: shake the card
    for (const id of ['login-error', 'register-error']) {
      const el = document.getElementById(id);
      if (!el) continue;
      new MutationObserver(() => {
        if (!el.textContent.trim()) return;
        card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
        setTimeout(() => card.classList.remove('shake'), 560);
      }).observe(el, { childList: true, characterData: true, subtree: true });
    }
  }


  // ---------------------------------------------------------------- app pages: the pendant lamp
  const NS = 'http://www.w3.org/2000/svg';
  function svgEl(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (parent) parent.append(e);
    return e;
  }
  const pref = {
    get() { try { return localStorage.getItem('tv_lamp'); } catch { return null; } },
    set(v) { try { localStorage.setItem('tv_lamp', v); } catch { /* storage blocked: fine */ } },
  };
  function pendantLamp() {
    const body = document.body;
    const light = document.createElement('div');
    light.className = 'page-light';
    light.setAttribute('aria-hidden', 'true');
    const wrap = document.createElement('div');
    wrap.className = 'page-lamp';
    const svg = svgEl('svg', { class: 'page-lamp-svg', viewBox: '0 0 120 150', 'aria-hidden': 'true', focusable: 'false' }, wrap);
    svgEl('line', { class: 'pl-cord', x1: '60', y1: '-60', x2: '60', y2: '62' }, svg);
    svgEl('rect', { class: 'pl-cap', x: '54', y: '54', width: '12', height: '9', rx: '2' }, svg);
    svgEl('path', { class: 'pl-shade', d: 'M20 116 C20 84 38 64 60 64 C82 64 100 84 100 116 Z' }, svg);
    svgEl('rect', { class: 'pl-rim', x: '15', y: '114', width: '90', height: '6', rx: '3' }, svg);
    svgEl('ellipse', { class: 'pl-bulb', cx: '60', cy: '121', rx: '22', ry: '4.5' }, svg);
    const g = svgEl('g', { class: 'pl-pull' }, svg);
    svgEl('line', { class: 'pl-chain', x1: '90', y1: '118', x2: '90', y2: '138' }, g);
    svgEl('circle', { class: 'pl-bead', cx: '90', cy: '143', r: '4' }, g);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'page-lamp-btn';
    btn.title = 'Switch the lamp on or off';
    wrap.append(btn);
    body.prepend(light, wrap);

    let on = false;
    function set(next, flicker) {
      on = next;
      btn.setAttribute('aria-pressed', String(on));
      btn.setAttribute('aria-label', on ? 'Switch the lamp off' : 'Switch the lamp on');
      body.classList.remove('lamp-tug'); void body.offsetWidth; body.classList.add('lamp-tug');
      if (flicker && on && !reduce) { body.classList.remove('lamp-flicker'); void body.offsetWidth; body.classList.add('lamp-flicker'); }
      body.classList.toggle('lamp-on', on);
    }
    btn.addEventListener('click', () => { const next = !on; pref.set(next ? 'on' : 'off'); set(next, true); });
    btn.setAttribute('aria-pressed', 'false');
    btn.setAttribute('aria-label', 'Switch the lamp on');
    if (pref.get() === 'off') return;           // they switched it off last time: leave the room dark
    if (reduce) { set(true, false); return; }
    setTimeout(() => set(true, true), 900);     // the lamp comes on a moment after the page appears
  }

  // ---------------------------------------------------------------- boot
  document.addEventListener('DOMContentLoaded', () => {
    const login = document.body.classList.contains('auth-page');
    fireflies(login ? 40 : 16);
    if (login) { lampScene(); return; }
    pendantLamp();
    const main = $('#main');
    if (main) new MutationObserver(schedule).observe(main, { childList: true, subtree: true });
    const nav = $('#nav');
    if (nav) new MutationObserver(schedule).observe(nav, { childList: true });
    schedule();
  });
})();
