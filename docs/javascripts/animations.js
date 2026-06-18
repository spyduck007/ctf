// animations.js — Scroll animations, counter animations, hero typing effect, table enhancements

document$.subscribe(function () {

  // =====================================================================
  // 0. Auto-calculate CTF stats from the results table
  // =====================================================================

  (function () {
    var table = document.querySelector('.ctf-stats-grid ~ .md-typeset__scrollwrap table, .ctf-stats-grid + * table, .md-typeset table');
    if (!table) return;

    var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
    var total = rows.length;
    var firstPlace = 0;
    var topTen = 0;

    rows.forEach(function (row) {
      var cells = row.querySelectorAll('td');
      if (cells.length < 2) return;
      var rankText = cells[1].textContent.trim();
      var match = rankText.match(/(\d+)/);
      if (match) {
        var rank = parseInt(match[1], 10);
        if (rank === 1) firstPlace++;
        if (rank <= 10) topTen++;
      }
    });

    var statBoxes = document.querySelectorAll('.ctf-stats-grid .stat-number[data-count]');
    var labels = document.querySelectorAll('.ctf-stats-grid .stat-title');

    statBoxes.forEach(function (box, i) {
      var label = labels[i] ? labels[i].textContent.trim() : '';
      if (label === 'Competitions') box.setAttribute('data-count', total);
      else if (label === '1st Place Finishes') box.setAttribute('data-count', firstPlace);
      else if (label === 'Top-10 Finishes') box.setAttribute('data-count', topTen);
      box.textContent = '—';
    });
  })();

  // =====================================================================
  // 1. Scroll-triggered reveal animations
  // =====================================================================

  if ('IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: '0px 0px -40px 0px' }
    );

    document.querySelectorAll('[data-animate]').forEach(function (el) {
      revealObserver.observe(el);
    });
    // Animate table wrappers (animating the table itself breaks :not([class]) CSS selectors)
    document.querySelectorAll('.md-typeset__table').forEach(function (el) {
      el.setAttribute('data-animate', '');
      revealObserver.observe(el);
    });
  } else {
    document.querySelectorAll('[data-animate]').forEach(function (el) {
      el.classList.add('is-visible');
    });
    document.querySelectorAll('.md-typeset__table').forEach(function (el) {
      el.classList.add('is-visible');
    });
  }

  // =====================================================================
  // 2. Counter animations
  // =====================================================================

  function easeOutExpo(t) {
    return t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
  }

  function runCounter(el) {
    var target = parseInt(el.dataset.count, 10);
    if (isNaN(target)) return;
    var suffix = el.dataset.suffix || '';
    var duration = 1800;
    var startTime = null;

    function step(ts) {
      if (!startTime) startTime = ts;
      var elapsed = ts - startTime;
      var progress = Math.min(elapsed / duration, 1);
      var value = Math.floor(easeOutExpo(progress) * target);
      el.textContent = value + suffix;
      if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
  }

  if ('IntersectionObserver' in window) {
    var counterObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            runCounter(entry.target);
            counterObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.3 }
    );

    document.querySelectorAll('[data-count]').forEach(function (el) {
      // Set to dash so non-JS users still see something
      if (el.textContent.trim() === el.dataset.count) {
        el.textContent = '—';
      }
      counterObserver.observe(el);
    });
  }

  // =====================================================================
  // 3. Hero typing effect
  // =====================================================================

  var typedEl = document.querySelector('.hero__typed');
  if (typedEl) {
    var fullText = typedEl.dataset.text || typedEl.textContent.trim();

    // Build cursor element
    var cursor = document.createElement('span');
    cursor.className = 'hero__cursor';
    typedEl.textContent = '';
    typedEl.parentNode.insertBefore(cursor, typedEl.nextSibling);

    // Animate typing with an initial delay
    var charIndex = 0;
    var startDelay = 500;

    setTimeout(function () {
      var typeTimer = setInterval(function () {
        typedEl.textContent = fullText.slice(0, ++charIndex);
        if (charIndex >= fullText.length) {
          clearInterval(typeTimer);
          // Fade out cursor after a pause
          setTimeout(function () {
            cursor.style.transition = 'opacity 0.5s';
            cursor.style.opacity = '0';
          }, 2400);
        }
      }, 75);
    }, startDelay);
  }

  // =====================================================================
  // 4. CTF table rank highlighting
  // =====================================================================

  var tableRows = document.querySelectorAll('.md-typeset table tbody tr');
  tableRows.forEach(function (row) {
    var cells = row.querySelectorAll('td');
    if (cells.length < 2) return;
    var rankText = cells[1].textContent.trim();
    var rank = parseInt(rankText, 10);
    if (rank === 1) {
      row.classList.add('rank-first');
    } else if (rank === 2 || rank === 3) {
      row.classList.add('rank-podium');
    }
  });

  // =====================================================================
  // 5. Subtle card entrance stagger on page load
  // =====================================================================

  var cards = document.querySelectorAll('.writeup-grid:not(.filterable) .writeup-card');
  cards.forEach(function (card, i) {
    card.style.opacity = '0';
    card.style.transform = 'translateY(14px)';
    card.style.transition = 'opacity 0.4s ease ' + (i * 0.07) + 's, transform 0.4s ease ' + (i * 0.07) + 's';
    // Trigger after a brief paint
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        card.style.opacity = '1';
        card.style.transform = 'translateY(0)';
      });
    });
  });

});
