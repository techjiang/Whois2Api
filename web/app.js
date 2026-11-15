/* Whois2Api UI. Vanilla JS, no build step, no dependencies. */
(function () {
  'use strict';

  var T = window.W2A;
  var form = document.getElementById('lookup');
  var input = document.getElementById('domain');
  var output = document.getElementById('output');
  var versionEl = document.getElementById('version');
  var langBtn = document.getElementById('lang');
  var abort = null;
  // Last successful payload, so the "Copy JSON" and raw-payload actions do not
  // re-run the lookup.
  var lastResult = null;
  // Last failure, kept so a language switch can re-render it in the new
  // language instead of leaving a stale English sentence on screen.
  var lastError = null;
  var lastName = '';
  // Raw payload and whether it is expanded. Kept outside the DOM because a
  // language switch rebuilds the card: without this, the payload survives but
  // the panel does not, and the button offers to fetch it again from a
  // registry we already asked.
  var lastRaw = '';
  var lastRawSource = '';
  var rawVisible = false;

  // Fill in the host in the documentation examples.
  Array.prototype.forEach.call(document.querySelectorAll('.host'), function (el) {
    el.textContent = location.origin;
  });

  langBtn.addEventListener('click', function () {
    T.setLang(T.other());
    langBtn.textContent = T.t('lang.other');
    langBtn.setAttribute('aria-label', T.t('lang.other'));
  });

  // Re-render whatever is on screen so switching language never leaves a
  // half-translated card behind.
  T.onChange(function () {
    if (lastResult) render(lastResult);
    else if (lastError) renderError(lastError.body, lastError.name);
  });

  document.getElementById('examples').addEventListener('click', function (ev) {
    var btn = ev.target.closest('button[data-d]');
    if (!btn) return;
    input.value = btn.getAttribute('data-d');
    form.requestSubmit();
  });

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var name = input.value.trim();
    if (name) lookup(name);
  });

  function lookup(name) {
    if (abort) abort.abort();
    abort = new AbortController();
    lastResult = null;
    lastError = null;
    lastName = name;
    lastRaw = '';
    lastRawSource = '';
    rawVisible = false;

    output.innerHTML = '';
    output.appendChild(statusCard(name));

    // ?raw=1 costs nothing extra when the answer is fresh (same request, one
    // more field), so a cold lookup can show its payload with no second
    // round-trip. Cached answers come back without it, and the raw button then
    // re-queries with ?fresh=1.
    fetch('/api/v1/domain/' + encodeURIComponent(name) + '?raw=1', { signal: abort.signal })
      .then(function (res) {
        return res.json().then(function (body) { return { status: res.status, body: body }; });
      })
      .then(function (result) {
        if (result.status === 200) {
          lastResult = result.body;
          render(result.body);
        } else {
          lastError = { body: result.body, name: name };
          renderError(result.body, name);
        }
      })
      .catch(function (err) {
        if (err.name === 'AbortError') return;
        var body = { error: { message: T.t('error.network'), hint: T.t('error.networkHint') } };
        lastError = { body: null, name: name, local: body };
        renderError(body, name);
      });
  }

  function statusCard(name) {
    var card = el('section', 'card');
    card.appendChild(el('h2', null, T.t('status.looking', { name: name })));
    var p = el('p', 'hint');
    p.appendChild(el('span', 'spinner'));
    p.appendChild(document.createTextNode(T.t('status.progress')));
    card.appendChild(p);
    return card;
  }

  function renderError(body, name) {
    output.innerHTML = '';
    var card = el('section', 'card error-card');
    card.appendChild(el('h2', null, T.t('error.looking', { name: name })));
    var msg = T.errorText(body, 'message') || T.t('error.unknown');
    card.appendChild(el('p', null, msg));
    var hint = T.errorText(body, 'hint');
    if (hint && hint !== msg) card.appendChild(el('p', 'hint', hint));
    output.appendChild(card);
  }

  function render(result) {
    var d = result.domain || {};
    var meta = result.meta || {};
    output.innerHTML = '';

    var card = el('section', 'card');
    var head = el('div', 'card-head');
    // The heading is the name the caller asked for, not the record key. A
    // cached answer for www.example.com is stored under example.com, so using
    // d.name here would title the card with a name nobody typed.
    var shown = d.unicode || d.input || d.name || '';
    head.appendChild(el('h2', null, shown));
    // For IDN input the ASCII form is worth showing: that is the name the
    // registry actually answered about. For a subdomain the verdict line below
    // already names the parent, so repeating it here would just be noise.
    if (d.unicode && d.name) head.appendChild(el('span', 'unicode', d.name));
    head.appendChild(verdictPill(d.status));
    card.appendChild(head);

    if (d.subdomain_of) {
      card.appendChild(el('p', 'verdict-line', T.t('sentence.subdomain', { d: d.subdomain_of })));
    } else {
      card.appendChild(el('p', 'verdict-line', verdictSentence(d)));
    }

    var fields = [
      ['field.registrar', d.registrar],
      ['field.registrar_id', d.registrar_id],
      ['field.registry_id', d.registry_id],
      ['field.created', fmtDate(d.created_at)],
      ['field.updated', fmtDate(d.updated_at)],
      ['field.expires', expiry(d.expires_at, d.days_until_expiry)],
      ['field.dnssec', d.dnssec],
      ['field.suffix', d.suffix],
      [d.subdomain_of ? 'field.dns_of' : 'field.dns',
        d.dns_resolves === undefined ? '' : (d.dns_resolves ? T.t('value.yes') : T.t('value.no'))],
      ['field.source', d.source]
    ];

    var dl = el('dl', 'fields');
    fields.forEach(function (pair) {
      if (!pair[1]) return;
      // field.dns_of names the domain the probe actually measured, because on a
      // subdomain card the answer is about the registrable domain, not the name
      // in the title.
      dl.appendChild(el('dt', null, T.t(pair[0], { d: d.subdomain_of || '' })));
      var dd = el('dd');
      if (pair[0] === 'field.registrar' && d.registrar_url) {
        var a = el('a', null, pair[1]);
        a.href = d.registrar_url;
        a.rel = 'noopener noreferrer nofollow';
        a.target = '_blank';
        dd.appendChild(a);
      } else {
        dd.textContent = pair[1];
      }
      dl.appendChild(dd);
    });

    if (d.name_servers && d.name_servers.length) {
      dl.appendChild(el('dt', null, T.t('field.nameservers')));
      var nsDD = el('dd', 'tags');
      d.name_servers.slice(0, 8).forEach(function (ns) {
        nsDD.appendChild(el('span', 'pill neutral', ns));
      });
      if (d.name_servers.length > 8) {
        nsDD.appendChild(el('span', 'pill neutral', T.t('more', { n: d.name_servers.length - 8 })));
      }
      dl.appendChild(nsDD);
    }

    if (d.statuses && d.statuses.length) {
      dl.appendChild(el('dt', null, T.t('field.statuses')));
      var stDD = el('dd', 'tags');
      d.statuses.forEach(function (s) {
        if (s.url) {
          var a = el('a', 'pill neutral', s.code);
          a.href = s.url;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          stDD.appendChild(a);
        } else {
          stDD.appendChild(el('span', 'pill neutral', s.code));
        }
      });
      dl.appendChild(stDD);
    }

    if (dl.children.length) card.appendChild(dl);

    if (d.alerts && d.alerts.length) {
      var ul = el('ul', 'alerts');
      d.alerts.forEach(function (a) {
        // Severity comes from the code, not from grepping the English prose.
        ul.appendChild(el('li', stopNotice(a.code) ? 'stop' : null, T.notice(a)));
      });
      card.appendChild(ul);
    }

    var metaLine = el('div', 'meta');
    // A cache hit did not take 0 ms of registry time — it took none. Saying
    // "0 ms" invites the reader to think the timer is broken, so report the
    // cache age instead of a duration that was never measured.
    var answered;
    if (meta.cached) {
      var age = duration(meta.cache_age_seconds);
      answered = meta.stale
        ? T.t('meta.stale', { age: age })
        : T.t('meta.cached', { age: age });
    } else {
      answered = T.t('meta.answered', { ms: meta.total_ms || 0 });
    }
    metaLine.appendChild(el('div', null, answered));
    if (meta.channels && meta.channels.length) {
      metaLine.appendChild(el('div', null, T.t('meta.channels') + meta.channels.map(function (c) {
        return c.channel + ' ' + c.ms + 'ms' + (c.ok ? '' : ' ✕');
      }).join(' · ')));
    }
    (meta.warnings || []).forEach(function (w) {
      // The "cached answers carry no raw payload" note is for API clients. The
      // raw button below already says the same thing, so repeating it as a
      // warning just adds noise to a perfectly fine answer.
      if (w.code === 'cached_without_raw') return;
      metaLine.appendChild(el('div', null, T.notice(w)));
    });
    card.appendChild(metaLine);
    card.appendChild(actions(result));

    output.appendChild(card);

    // Re-open the payload panel after a re-render (language switch) so the
    // reader does not lose what they were looking at. This has to run after the
    // card is in the document: showRaw finds its host through #output.
    if (lastRaw) showRaw(lastRaw, lastRawSource);
  }

  // duration renders a coarse, human-scale age. Precision here would be false
  // precision: nobody cares whether a cached answer is 43 or 44 seconds old.
  function duration(seconds) {
    var n = Math.max(0, Math.round(seconds || 0));
    if (n < 90) return T.t('dur.seconds', { n: n });
    if (n < 5400) return T.t('dur.minutes', { n: Math.round(n / 60) });
    return T.t('dur.hours', { n: Math.round(n / 3600) });
  }

  // stopNotice marks caveats that mean "do not act on this answer".
  function stopNotice(code) {
    return ['rate_limited', 'blocked', 'expired',
      'dns_resolves_but_available', 'no_answer_no_dns',
      'cached_without_raw', 'no_upstream_payload'].indexOf(code) !== -1;
  }

  // actions renders the per-result toolbar: copy the JSON, or expand the raw
  // upstream payload that produced the verdict.
  function actions(result) {
    var bar = el('div', 'actions');

    var copy = el('button', 'ghost', T.t('action.copy'));
    copy.type = 'button';
    copy.addEventListener('click', function () {
      // Copy the answer without the raw dump: people pasting a verdict into a
      // bug report want the structured part.
      var clone = JSON.parse(JSON.stringify(result));
      if (clone.domain) delete clone.domain.raw;
      var text = JSON.stringify(clone, null, 2);
      var ok = function () {
        copy.textContent = T.t('action.copied');
        setTimeout(function () { copy.textContent = T.t('action.copy'); }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(ok, function () { fallbackCopy(text, ok); });
      } else {
        fallbackCopy(text, ok);
      }
    });
    bar.appendChild(copy);

    // The payload may have arrived with this answer, or from an earlier
    // re-query for the same name. Both count as "already have it": fetching a
    // second time would look like the first fetch had failed.
    if (!lastRaw && result.domain && result.domain.raw) {
      lastRaw = result.domain.raw;
      lastRawSource = result.domain.source || 'none';
    }
    var raw = lastRaw;
    var rawBtn = el('button', 'ghost', raw ? T.t('action.raw') : T.t('action.rawRequery'));
    rawBtn.type = 'button';
    if (!raw) rawBtn.title = T.t('action.rawTitle');
    if (raw && rawVisible) rawBtn.textContent = T.t('action.hideRaw');
    rawBtn.addEventListener('click', function () {
      if (lastRaw) {
        rawVisible = !rawVisible;
        showRaw(lastRaw, lastRawSource);
        rawBtn.textContent = rawVisible ? T.t('action.hideRaw') : T.t('action.raw');
        return;
      }
      rawBtn.disabled = true;
      rawBtn.textContent = T.t('action.fetching');
      // fresh=1 forces a registry round-trip: a cached entry has no payload,
      // and silently returning an empty one would look like a silent registry.
      fetch('/api/v1/domain/' + encodeURIComponent(lastName) + '?raw=1&fresh=1')
        .then(function (r) { return r.json(); })
        .then(function (body) {
          var payload = (body.domain && body.domain.raw) || '';
          if (!payload) {
            rawBtn.textContent = T.t('action.rawUnavailable');
            return;
          }
          lastRaw = payload;
          lastRawSource = (body.domain && body.domain.source) || 'none';
          rawVisible = true;
          showRaw(lastRaw, lastRawSource);
          rawBtn.disabled = false;
          rawBtn.textContent = T.t('action.hideRaw');
        })
        .catch(function () {
          rawBtn.disabled = false;
          rawBtn.textContent = T.t('action.rawRequery');
        });
    });
    bar.appendChild(rawBtn);

    return bar;
  }

  // showRaw renders the payload under the card it belongs to and returns the
  // panel. It is idempotent: the card is rebuilt on every re-render, so this is
  // also how the panel comes back after a language switch.
  function showRaw(raw, source) {
    var card = output.querySelector('.card');
    if (!card) return null;
    var details = card.querySelector('details.raw');
    if (!details) {
      details = el('details', 'raw');
      details.appendChild(el('summary', null, T.t('raw.summary.' + source)));
      var pre = el('pre');
      pre.textContent = raw;
      details.appendChild(pre);
      // The summary belongs to <details>, so the browser toggles it for us.
      // Track that here, or the next re-render silently re-opens a panel the
      // reader had just closed.
      //
      // toggle is dispatched as a queued task, so a panel torn down by
      // innerHTML = '' reports open: false *after* the replacement card is
      // already built — and would slam the state shut on a panel the reader is
      // looking at. A detached element's opinion no longer counts.
      details.addEventListener('toggle', function () {
        if (!details.isConnected) return;
        rawVisible = details.open;
      });
      card.appendChild(details);
    }
    details.open = rawVisible;
    return details;
  }

  function fallbackCopy(text, done) {
    var ta = el('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  function verdictPill(status) {
    if (status === 'registered') return el('span', 'pill registered', T.t('verdict.registered'));
    if (status === 'available') return el('span', 'pill available', T.t('verdict.available'));
    return el('span', 'pill unknown', T.t('verdict.unknown'));
  }

  function verdictSentence(d) {
    var key = 'sentence.' + (d.status === 'registered' ? 'registered'
      : d.status === 'available' ? 'available' : 'unknown');
    var c = typeof d.confidence === 'number' ? d.confidence : 0;
    return T.t(key, { c: c });
  }

  function expiry(iso, days) {
    if (!iso) return '';
    var text = fmtDate(iso);
    if (typeof days === 'number') {
      text += days >= 0 ? T.t('expiry.in', { n: days }) : T.t('expiry.ago', { n: Math.abs(days) });
    }
    return text;
  }

  function fmtDate(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate());
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  // Deep links: /?d=example.com or /#example.com opens straight on a lookup, so
  // a shared link shows the same answer instead of an empty form.
  var deepLink = new URLSearchParams(location.search).get('d') ||
    decodeURIComponent(location.hash.replace(/^#/, ''));
  if (deepLink) {
    input.value = deepLink;
    lookup(deepLink);
  }

  // Show the deployed version in the footer.
  fetch('/api/v1/status').then(function (r) {
    return r.ok ? r.json() : null;
  }).then(function (s) {
    if (s && s.version) versionEl.textContent = 'v' + s.version;
  }).catch(function () {});
})();
