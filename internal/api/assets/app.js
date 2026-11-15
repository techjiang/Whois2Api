/* Whois2Api UI. Vanilla JS, no build step, no dependencies. */
(function () {
  'use strict';

  var form = document.getElementById('lookup');
  var input = document.getElementById('domain');
  var output = document.getElementById('output');
  var versionEl = document.getElementById('version');
  var abort = null;
  // Last successful payload, so the "Copy JSON" and raw-payload actions do not
  // re-run the lookup.
  var lastResult = null;
  var lastName = '';

  // Fill in the host in the documentation examples.
  Array.prototype.forEach.call(document.querySelectorAll('.host'), function (el) {
    el.textContent = location.origin;
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
    lastName = name;

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
          renderError(result.body, name);
        }
      })
      .catch(function (err) {
        if (err.name === 'AbortError') return;
        renderError({ error: { message: 'Could not reach the API.', hint: 'Check your connection and try again.' } }, name);
      });
  }

  function statusCard(name) {
    var card = el('section', 'card');
    card.appendChild(el('h2', null, 'Looking up ' + name + '…'));
    var p = el('p', 'hint');
    p.appendChild(el('span', 'spinner'));
    p.appendChild(document.createTextNode('querying RDAP and WHOIS in parallel'));
    card.appendChild(p);
    return card;
  }

  function renderError(body, name) {
    output.innerHTML = '';
    var card = el('section', 'card error-card');
    card.appendChild(el('h2', null, 'Could not look up ' + name));
    var msg = (body && body.error && body.error.message) || 'Unknown error.';
    card.appendChild(el('p', null, msg));
    if (body && body.error && body.error.hint) card.appendChild(el('p', 'hint', body.error.hint));
    output.appendChild(card);
  }

  function render(result) {
    var d = result.domain || {};
    var meta = result.meta || {};
    output.innerHTML = '';

    var card = el('section', 'card');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, d.name || ''));
    if (d.unicode) head.appendChild(el('span', 'unicode', d.unicode));
    head.appendChild(verdictPill(d.status));
    card.appendChild(head);

    if (d.subdomain_of) {
      card.appendChild(el('p', 'verdict-line',
        'Queried via its registrable domain ' + d.subdomain_of + ' — registries do not answer for subdomains.'));
    } else {
      card.appendChild(el('p', 'verdict-line', verdictSentence(d)));
    }

    var fields = [
      ['Registrar', d.registrar],
      ['Registrar IANA ID', d.registrar_id],
      ['Registry domain ID', d.registry_id],
      ['Created', fmtDate(d.created_at)],
      ['Updated', fmtDate(d.updated_at)],
      ['Expires', expiry(d.expires_at, d.days_until_expiry)],
      ['DNSSEC', d.dnssec],
      ['Public suffix', d.suffix],
      ['DNS resolves', d.dns_resolves === undefined ? '' : (d.dns_resolves ? 'yes' : 'no')],
      ['Source', d.source]
    ];

    var dl = el('dl', 'fields');
    fields.forEach(function (pair) {
      if (!pair[1]) return;
      dl.appendChild(el('dt', null, pair[0]));
      var dd = el('dd');
      if (pair[0] === 'Registrar' && d.registrar_url) {
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
      dl.appendChild(el('dt', null, 'Name servers'));
      var nsDD = el('dd', 'tags');
      d.name_servers.slice(0, 8).forEach(function (ns) {
        nsDD.appendChild(el('span', 'pill neutral', ns));
      });
      if (d.name_servers.length > 8) {
        nsDD.appendChild(el('span', 'pill neutral', '+' + (d.name_servers.length - 8) + ' more'));
      }
      dl.appendChild(nsDD);
    }

    if (d.statuses && d.statuses.length) {
      dl.appendChild(el('dt', null, 'EPP status'));
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
        ul.appendChild(el('li', /not|expired|refus|rate/i.test(a) ? 'stop' : null, a));
      });
      card.appendChild(ul);
    }

    var metaLine = el('div', 'meta');
    metaLine.appendChild(el('div', null, 'Answered in ' + (meta.total_ms || 0) + ' ms' +
      (meta.cached ? (meta.stale ? ' (stale cache, refreshing)' : ' (cached)') : '')));
    if (meta.channels && meta.channels.length) {
      metaLine.appendChild(el('div', null, 'Channels: ' + meta.channels.map(function (c) {
        return c.channel + ' ' + c.ms + 'ms' + (c.ok ? '' : ' ✕');
      }).join(' · ')));
    }
    (meta.warnings || []).forEach(function (w) {
      // The "cached answers carry no raw payload" note is for API clients. The
      // raw button below already says the same thing, so repeating it as a
      // warning just adds noise to a perfectly fine answer.
      if (w.indexOf('?fresh=1') !== -1) return;
      metaLine.appendChild(el('div', null, w));
    });
    card.appendChild(metaLine);
    card.appendChild(actions(result));

    output.appendChild(card);
  }

  // actions renders the per-result toolbar: copy the JSON, or expand the raw
  // upstream payload that produced the verdict.
  function actions(result) {
    var bar = el('div', 'actions');

    var copy = el('button', 'ghost', 'Copy JSON');
    copy.type = 'button';
    copy.addEventListener('click', function () {
      // Copy the answer without the raw dump: people pasting a verdict into a
      // bug report want the structured part.
      var clone = JSON.parse(JSON.stringify(result));
      if (clone.domain) delete clone.domain.raw;
      var text = JSON.stringify(clone, null, 2);
      var ok = function () {
        copy.textContent = 'Copied';
        setTimeout(function () { copy.textContent = 'Copy JSON'; }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(ok, function () { fallbackCopy(text, ok); });
      } else {
        fallbackCopy(text, ok);
      }
    });
    bar.appendChild(copy);

    var raw = (result.domain && result.domain.raw) || '';
    var rawBtn = el('button', 'ghost', raw ? 'Raw response' : 'Raw response (re-query)');
    rawBtn.type = 'button';
    if (!raw) {
      rawBtn.title = 'Cached answers carry no upstream payload; this asks the registry again.';
    }
    rawBtn.addEventListener('click', function () {
      if (raw) {
        var open = toggleRaw(raw, (result.domain && result.domain.source) || 'upstream');
        rawBtn.textContent = open ? 'Hide raw' : 'Raw response';
        return;
      }
      rawBtn.disabled = true;
      rawBtn.textContent = 'Fetching…';
      // fresh=1 forces a registry round-trip: a cached entry has no payload,
      // and silently returning an empty one would look like a silent registry.
      fetch('/api/v1/domain/' + encodeURIComponent(lastName) + '?raw=1&fresh=1')
        .then(function (r) { return r.json(); })
        .then(function (body) {
          var payload = (body.domain && body.domain.raw) || '';
          if (!payload) {
            rawBtn.textContent = 'Raw unavailable';
            return;
          }
          raw = payload;
          toggleRaw(payload, (body.domain && body.domain.source) || 'upstream');
          rawBtn.disabled = false;
          rawBtn.textContent = 'Hide raw';
        })
        .catch(function () {
          rawBtn.disabled = false;
          rawBtn.textContent = 'Raw response (re-query)';
        });
    });
    bar.appendChild(rawBtn);

    return bar;
  }

  // toggleRaw shows the payload in place, under the card it belongs to.
  // It returns the resulting open state.
  function toggleRaw(raw, source) {
    var card = output.querySelector('.card');
    if (!card) return false;
    var existing = card.querySelector('details.raw');
    if (existing) {
      existing.open = !existing.open;
      return existing.open;
    }
    var details = el('details', 'raw');
    details.open = true;
    details.appendChild(el('summary', null, 'Raw ' + source + ' response'));
    var pre = el('pre');
    pre.textContent = raw;
    details.appendChild(pre);
    card.appendChild(details);
    return true;
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
    if (status === 'registered') return el('span', 'pill registered', 'registered');
    if (status === 'available') return el('span', 'pill available', 'available');
    return el('span', 'pill unknown', 'unknown');
  }

  function verdictSentence(d) {
    var conf = typeof d.confidence === 'number' ? ' (confidence ' + d.confidence + '%)' : '';
    if (d.status === 'registered') return 'An authoritative registry returned a record for this name' + conf + '.';
    if (d.status === 'available') return 'The registry explicitly reported this name as not registered' + conf + '.';
    return 'No registry gave a usable answer' + conf + '. This does not mean the name is free.';
  }

  function expiry(iso, days) {
    if (!iso) return '';
    var text = fmtDate(iso);
    if (typeof days === 'number') text += ' (' + (days >= 0 ? 'in ' + days + ' days' : Math.abs(days) + ' days ago') + ')';
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
  fetch('/api/v1/health').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  fetch('/api/v1/status').then(function (r) { return r.ok ? r.json() : null; }).then(function (s) {
    if (s && s.version) versionEl.textContent = 'v' + s.version;
  }).catch(function () {});
})();
