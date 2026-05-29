/**
 * CyberShield — main.js
 * Pure vanilla JS, no external libraries
 */

'use strict';

/* ── Utility ──────────────────────────────────────────────────── */
// $ = querySelector (single element, by CSS selector)
// $$ = querySelectorAll (all matching elements, by CSS selector)
const $  = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

/* ── Navbar scroll effect ─────────────────────────────────────── */
(function initNavbarScroll() {
  const navbar = $('#navbar');
  if (!navbar) return;

  const onScroll = () => {
    navbar.classList.toggle('scrolled', window.scrollY > 40);
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();

/* ── Mobile hamburger menu ────────────────────────────────────── */
(function initHamburger() {
  const hamburger = $('#hamburger');
  const navLinks  = $('#navLinks');
  if (!hamburger || !navLinks) return;

  hamburger.addEventListener('click', () => {
    const isOpen = hamburger.classList.toggle('open');
    navLinks.classList.toggle('open', isOpen);
    hamburger.setAttribute('aria-expanded', String(isOpen));
    document.body.style.overflow = isOpen ? 'hidden' : '';
  });

  // Close on nav link click
  navLinks.addEventListener('click', (e) => {
    if (e.target.classList.contains('nav-link')) {
      hamburger.classList.remove('open');
      navLinks.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
    }
  });

  // Close on outside click
  document.addEventListener('click', (e) => {
    const navbar = $('#navbar');
    if (navbar && !navbar.contains(e.target)) {
      hamburger.classList.remove('open');
      navLinks.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
    }
  });
})();

/* ── Typing animation ─────────────────────────────────────────── */
(function initTypingAnimation() {
  const el = $('#typingText');
  if (!el) return;

  const phrases = [
    'Phishing Detection',
    'Threat Monitoring',
    'Password Analysis',
    'QR Code Scanning',
    'Real-time Intelligence',
  ];

  let phraseIndex = 0;
  let charIndex   = 0;
  let isDeleting  = false;
  let isPaused    = false;

  const TYPING_SPEED   = 80;
  const DELETING_SPEED = 45;
  const PAUSE_AFTER    = 1800;
  const PAUSE_BEFORE   = 300;

  function tick() {
    const current = phrases[phraseIndex];
    if (isPaused) return;

    if (!isDeleting) {
      el.textContent = current.slice(0, charIndex + 1);
      charIndex++;
      if (charIndex === current.length) {
        isPaused = true;
        setTimeout(() => { isPaused = false; isDeleting = true; loop(); }, PAUSE_AFTER);
        return;
      }
    } else {
      el.textContent = current.slice(0, charIndex - 1);
      charIndex--;
      if (charIndex === 0) {
        isDeleting  = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
        isPaused    = true;
        setTimeout(() => { isPaused = false; loop(); }, PAUSE_BEFORE);
        return;
      }
    }
    loop();
  }

  function loop() {
    setTimeout(tick, isDeleting ? DELETING_SPEED : TYPING_SPEED);
  }

  setTimeout(loop, 600);
})();

/* ── Matrix rain canvas ───────────────────────────────────────── */
(function initMatrixRain() {
  const canvas = $('#matrixCanvas');
  if (!canvas) return;

  const ctx       = canvas.getContext('2d');
  const CHARS     = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF<>{}[]|/\\';
  const FONT_SIZE = 14;
  let columns, drops;

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    columns = Math.floor(canvas.width / FONT_SIZE);
    drops   = new Array(columns).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(10, 14, 26, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = `${FONT_SIZE}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      const y    = drops[i] * FONT_SIZE;

      if (drops[i] * FONT_SIZE < canvas.height * 0.15) {
        ctx.fillStyle = '#ffffff';
      } else {
        const alpha = Math.max(0.15, 1 - (drops[i] * FONT_SIZE) / canvas.height);
        ctx.fillStyle = `rgba(0, 255, 136, ${alpha})`;
      }

      ctx.fillText(char, i * FONT_SIZE, y);

      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize, { passive: true });

  let animId;
  function animate() { draw(); animId = requestAnimationFrame(animate); }
  animate();

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(animId);
    else animate();
  });
})();

/* ── Intersection Observer — fade-in on scroll ────────────────── */
(function initScrollAnimations() {
  const elements = $$('.fade-in');
  if (!elements.length) return;

  elements.forEach((el) => {
    const delay = el.dataset.delay;
    if (delay) el.style.transitionDelay = `${delay}ms`;
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
  );

  elements.forEach((el) => observer.observe(el));
})();

/* ── Active nav link on scroll ────────────────────────────────── */
(function initActiveNav() {
  const sections = $$('section[id]');
  const navLinks = $$('.nav-link');
  if (!sections.length || !navLinks.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.id;
          navLinks.forEach((link) => {
            const href = link.getAttribute('href');
            link.classList.toggle('active', href === `#${id}`);
          });
        }
      });
    },
    { threshold: 0.4 }
  );

  sections.forEach((s) => observer.observe(s));
})();

/* ── Counter animation for stats ─────────────────────────────── */
(function initCounters() {
  const statNumbers = $$('.stat-number[data-target]');
  if (!statNumbers.length) return;

  function animateCounter(el) {
    const target   = parseInt(el.dataset.target, 10);
    const suffix   = el.dataset.suffix  || '';
    const prefix   = el.dataset.prefix  || '';
    const isStatic = el.dataset.static;

    if (isStatic || isNaN(target) || target === 0) return;

    const duration = 1800;
    const start    = performance.now();

    function step(now) {
      const elapsed  = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased    = 1 - Math.pow(1 - progress, 3);
      const current  = Math.floor(eased * target);
      el.textContent = prefix + current + suffix;
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = prefix + target + suffix;
    }

    requestAnimationFrame(step);
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.5 }
  );

  statNumbers.forEach((el) => observer.observe(el));
})();

/* ── Back to top button ───────────────────────────────────────── */
(function initBackToTop() {
  const btn = $('#backToTop');
  if (!btn) return;

  window.addEventListener('scroll', () => {
    btn.classList.toggle('visible', window.scrollY > 400);
  }, { passive: true });

  btn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
})();

/* ── Smooth scroll for anchor links ──────────────────────────── */
(function initSmoothScroll() {
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[href^="#"]');
    if (!link) return;

    const href = link.getAttribute('href');
    if (href === '#' || href === '#!') return;

    const target = document.querySelector(href);
    if (!target) return;

    e.preventDefault();
    const navHeight = $('#navbar')?.offsetHeight || 70;
    const top = target.getBoundingClientRect().top + window.scrollY - navHeight;
    window.scrollTo({ top, behavior: 'smooth' });
  });
})();

/* ── Subtle card tilt on mouse move ──────────────────────────── */
(function initCardTilt() {
  const cards = $$('.feature-card');
  if (!cards.length || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  cards.forEach((card) => {
    card.addEventListener('mousemove', (e) => {
      const rect    = card.getBoundingClientRect();
      const x       = e.clientX - rect.left;
      const y       = e.clientY - rect.top;
      const cx      = rect.width  / 2;
      const cy      = rect.height / 2;
      const rotateX = ((y - cy) / cy) * -5;
      const rotateY = ((x - cx) / cx) *  5;
      card.style.transform = `translateY(-6px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    });

    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
    });
  });
})();
