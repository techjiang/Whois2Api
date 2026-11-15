/* Whois2Api UI. Vanilla JS, no build step, no dependencies. */
(function () {
  'use strict';

  var form = document.getElementById('lookup');
  var input = document.getElementById('domain');
  var output = document.getElementById('output');
  var versionEl = document.getElementById('version');
  var abort = null;

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

    output.innerHTML = '';
    output.appendChild(statusCard(name));

    fetch('/api/v1/domain/' + encodeURIComponent(name), { signal: abort.signal })
      .then(function (res) {
        return res.json().then(function (body) { return { status: res.status, body: body }; });
      })
      .then(function (result) {
        if (result.status === 200) render(result.body);
        else renderError(result.body, name);
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
    (meta.warnings || []).forEach(function (w) { metaLine.appendChild(el('div', null, w)); });
    card.appendChild(metaLine);

    output.appendChild(card);
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

  // Show the deployed version in the footer.
  fetch('/api/v1/health').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  fetch('/api/v1/status').then(function (r) { return r.ok ? r.json() : null; }).then(function (s) {
    if (s && s.version) versionEl.textContent = 'v' + s.version;
  }).catch(function () {});
})();
