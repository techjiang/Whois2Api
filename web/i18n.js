/* Whois2Api UI translations and language switching.
 *
 * The API sends every caveat as {code, text}: the code is the contract, text is
 * the English fallback. Translating on the code means editing the English prose
 * can never silently leave a Chinese reader staring at English, and an unknown
 * code degrades to readable English instead of an empty line. */
(function (global) {
  'use strict';

  var STORAGE_KEY = 'w2a-lang';

  var DICT = {
    en: {
      'title': 'Whois2Api — domain lookup',
      'description': 'A fast, self-hosted WHOIS/RDAP lookup API with an honest three-state verdict.',
      'skip': 'Skip to content',
      'nav.api': 'API',
      'nav.status': 'Status',
      'lang.other': '中文',

      'hero.a': 'Look up any domain, ',
      'hero.em': 'honestly',
      'hero.b': '.',
      'lede.a': 'WHOIS and RDAP queried in parallel, cached on your own disk. When a registry refuses to answer, this tells you ',
      'lede.strong': 'unknown',
      'lede.b': ' — never a confident guess.',
      'form.label': 'Domain name',
      'form.submit': 'Look up',

      'docs.cli': 'Use it from the command line',
      'docs.batch': 'Batch lookups',
      'docs.verdicts': 'What the three verdicts mean',
      'verdicts.registered': 'An authoritative registry returned a record for the name.',
      'verdicts.available': 'A registry explicitly said the name does not exist. This is a positive statement, not the absence of one.',
      'verdicts.unknown': 'The registry was rate-limited, blocked us, timed out, or answered in a dialect this build does not model. We do not guess.',

      'status.looking': 'Looking up {name}…',
      'status.progress': 'querying RDAP and WHOIS in parallel',
      'error.looking': 'Could not look up {name}',
      'error.network': 'Could not reach the API.',
      'error.networkHint': 'Check your connection and try again.',
      'error.unknown': 'Unknown error.',

      'verdict.registered': 'registered',
      'verdict.available': 'available',
      'verdict.unknown': 'unknown',
      'sentence.registered': 'An authoritative registry returned a record for this name (confidence {c}%).',
      'sentence.available': 'The registry explicitly reported this name as not registered (confidence {c}%).',
      'sentence.unknown': 'No registry gave a usable answer (confidence {c}%). This does not mean the name is free.',
      'sentence.subdomain': 'Queried via its registrable domain {d} — registries do not answer for subdomains.',

      'field.registrar': 'Registrar',
      'field.registrar_id': 'Registrar IANA ID',
      'field.registry_id': 'Registry domain ID',
      'field.created': 'Created',
      'field.updated': 'Updated',
      'field.expires': 'Expires',
      'field.dnssec': 'DNSSEC',
      'field.suffix': 'Public suffix',
      'field.dns': 'DNS resolves',
      'field.source': 'Source',
      'field.nameservers': 'Name servers',
      'field.statuses': 'EPP status',
      'value.yes': 'yes',
      'value.no': 'no',
      'more': '+{n} more',

      'dur.seconds': '{n}s',
      'dur.minutes': '{n} min',
      'dur.hours': '{n} h',
      'expiry.in': ' (in {n} days)',
      'expiry.ago': ' ({n} days ago)',
      'meta.answered': 'Answered in {ms} ms',
      'meta.cached': 'From cache (written {age} ago)',
      'meta.stale': 'Stale cache served while a refresh runs (written {age} ago)',
      'meta.channels': 'Channels: ',

      'action.copy': 'Copy JSON',
      'action.copied': 'Copied',
      'action.raw': 'Raw response',
      'action.rawRequery': 'Raw response (re-query)',
      'action.rawTitle': 'Cached answers carry no upstream payload; this asks the registry again.',
      'action.hideRaw': 'Hide raw',
      'action.fetching': 'Fetching…',
      'action.rawUnavailable': 'Raw unavailable',
      'raw.summary': 'Raw {source} response',

      'notice.registry_withheld': 'Registry withholds this record (usage restrictions) but confirms the name exists.',
      'notice.rate_limited': 'Upstream registry rate-limited this query; retry shortly.',
      'notice.blocked': 'Upstream registry refused this query (access policy).',
      'notice.dns_resolves_but_available': 'The name resolves over DNS even though the registry reports it as available; usually wildcard DNS or a lagging registry.',
      'notice.registered_without_dns': 'Registered but currently has no address records (parked or not yet configured).',
      'notice.unknown_but_dns': 'No definitive registry answer, but the name resolves over DNS, so it is almost certainly registered.',
      'notice.no_answer_no_dns': 'No definitive registry answer and DNS has no records; availability is unconfirmed.',
      'notice.subdomain_parent_available': 'This is a subdomain; only its registrable domain can be registered.',
      'notice.expired': 'Registration has expired according to the registry.',
      'notice.expires_within_7_days': 'Expires within 7 days; renewal is urgent.',
      'notice.expires_within_30_days': 'Expires within 30 days.',
      'notice.stale_served': 'Served from cache while a background refresh runs.',
      'notice.cached_without_raw': 'Cached answers carry no raw payload; add ?fresh=1 to query the registry again.',
      'notice.no_upstream_payload': 'This answer carried no upstream payload.',

      'err.invalid_domain': 'That does not look like a valid domain name.',
      'err.unsupported_tld': 'This top-level domain cannot be looked up automatically.',
      'err.rate_limited': 'Rate limit exceeded.',
      'err.unauthorized': 'A valid API token is required.',
      'err.upstream_unavailable': 'The registries took too long to answer.',
      'err.internal_error': 'Something went wrong while handling the request.',
      'err.bad_request': 'The request could not be understood.',
      'err.too_many_items': 'Too many domains in one request.',
      'err.method_not_allowed': 'That HTTP method is not allowed on this endpoint.',
      'err.invalid_domain.hint': 'Send a registrable name such as example.com; IDNs are accepted.',
      'err.unsupported_tld.hint': 'Either the TLD publishes no public WHOIS/RDAP service, or it is not a real TLD. Start with W2A_REFRESH_TABLE=true to pick up newly delegated TLDs.',
      'err.rate_limited.hint': 'Wait for the Retry-After header, or raise W2A_RATE_LIMIT.',
      'err.unauthorized.hint': 'Send Authorization: Bearer <token>.',
      'err.upstream_unavailable.hint': 'Retry; results are cached once they succeed.',
      'err.internal_error.hint': 'If this persists, check the server logs.',
      'err.bad_request.hint': 'The error envelope names the field that was wrong.',
      'err.too_many_items.hint': 'Split the batch, or raise W2A_MAX_BATCH.',
      'err.method_not_allowed.hint': 'Check the method listed in the Allow header.',
    },

    zh: {
      'title': 'Whois2Api — 域名查询',
      'description': '自建的 WHOIS/RDAP 查询接口：判定只有三态，绝不给自信的猜测。',
      'skip': '跳到正文',
      'nav.api': '接口',
      'nav.status': '状态',
      'lang.other': 'EN',

      'hero.a': '查询任何域名，',
      'hero.em': '如实相告',
      'hero.b': '。',
      'lede.a': 'WHOIS 与 RDAP 并行查询，结果缓存在你自己的磁盘上。当注册局拒绝回答时，这里会说 ',
      'lede.strong': '未知',
      'lede.b': ' —— 而不是一个听起来很确定的猜测。',
      'form.label': '域名',
      'form.submit': '查询',

      'docs.cli': '用命令行调用',
      'docs.batch': '批量查询',
      'docs.verdicts': '三种判定分别意味着什么',
      'verdicts.registered': '权威注册局返回了该域名的记录。',
      'verdicts.available': '注册局明确表示这个域名不存在。这是一句肯定陈述，不是「没说话」。',
      'verdicts.unknown': '注册局限流、封禁、超时，或者用本版本还不认识的方言回答。我们不做猜测。',

      'status.looking': '正在查询 {name}…',
      'status.progress': '正在并行请求 RDAP 与 WHOIS',
      'error.looking': '无法查询 {name}',
      'error.network': '连不上接口。',
      'error.networkHint': '检查一下网络，然后重试。',
      'error.unknown': '未知错误。',

      'verdict.registered': '已注册',
      'verdict.available': '可注册',
      'verdict.unknown': '未知',
      'sentence.registered': '权威注册局返回了这个域名的记录（置信度 {c}%）。',
      'sentence.available': '注册局明确表示该域名尚未注册（置信度 {c}%）。',
      'sentence.unknown': '没有任何注册局给出可用答案（置信度 {c}%）。这不代表域名可以注册。',
      'sentence.subdomain': '通过它的可注册主域名 {d} 查询 —— 注册局不回答子域名。',

      'field.registrar': '注册商',
      'field.registrar_id': '注册商 IANA 编号',
      'field.registry_id': '注册局域名 ID',
      'field.created': '创建时间',
      'field.updated': '更新时间',
      'field.expires': '到期时间',
      'field.dnssec': 'DNSSEC',
      'field.suffix': '公共后缀',
      'field.dns': 'DNS 解析',
      'field.source': '来源',
      'field.nameservers': '域名服务器',
      'field.statuses': 'EPP 状态',
      'value.yes': '有',
      'value.no': '无',
      'more': '另有 {n} 个',

      'dur.seconds': '{n} 秒',
      'dur.minutes': '{n} 分钟',
      'dur.hours': '{n} 小时',
      'expiry.in': '（还有 {n} 天）',
      'expiry.ago': '（已过 {n} 天）',
      'meta.answered': '耗时 {ms} ms',
      'meta.cached': '缓存命中，{age}前写入',
      'meta.stale': '缓存已过期，先返回旧结果并在后台刷新（{age}前写入）',
      'meta.channels': '通道：',

      'action.copy': '复制 JSON',
      'action.copied': '已复制',
      'action.raw': '原始报文',
      'action.rawRequery': '原始报文（重新查询）',
      'action.rawTitle': '缓存里的答案不保存上游报文；点这里会重新问注册局一次。',
      'action.hideRaw': '收起原始报文',
      'action.fetching': '获取中…',
      'action.rawUnavailable': '拿不到原始报文',
      'raw.summary': '原始 {source} 响应',

      'notice.registry_withheld': '注册局拒绝公开这条记录（有使用限制），但确认该域名存在。',
      'notice.rate_limited': '上游注册局限流了这次查询，稍后重试。',
      'notice.blocked': '上游注册局拒绝了本次查询（访问策略）。',
      'notice.dns_resolves_but_available': '注册局说可注册，但这个域名在 DNS 上有解析；通常是泛解析，或者注册局数据滞后。',
      'notice.registered_without_dns': '已注册，但目前没有地址记录（可能被停放，或者还没配好）。',
      'notice.unknown_but_dns': '注册局没有给出确定答案，但域名在 DNS 上有解析，几乎可以确定已注册。',
      'notice.no_answer_no_dns': '注册局没有给出确定答案，DNS 也没有记录；是否可注册无法确认。',
      'notice.subdomain_parent_available': '这是子域名；只有它的可注册主域名才可能被注册。',
      'notice.expired': '按注册局记录，这个域名已经过期。',
      'notice.expires_within_7_days': '7 天内到期，需要马上续费。',
      'notice.expires_within_30_days': '30 天内到期。',
      'notice.stale_served': '缓存已过期，先返回缓存内容，同时正在后台刷新。',
      'notice.cached_without_raw': '缓存里的答案不保留原始报文；加 ?fresh=1 会重新查询注册局。',
      'notice.no_upstream_payload': '这次答案没有上游原始报文。',

      'err.invalid_domain': '这不像一个合法的域名。',
      'err.unsupported_tld': '这个顶级域没法自动查询。',
      'err.rate_limited': '超过速率限制。',
      'err.unauthorized': '需要有效的 API 令牌。',
      'err.upstream_unavailable': '注册局太久没回答。',
      'err.internal_error': '处理请求时出了点问题。',
      'err.bad_request': '这个请求没被看懂。',
      'err.too_many_items': '一次请求里的域名太多了。',
      'err.method_not_allowed': '这个接口不接受该 HTTP 方法。',
      'err.invalid_domain.hint': '请传可注册的域名，例如 example.com；支持中文等国际化域名。',
      'err.unsupported_tld.hint': '这个顶级域要么没有公开的 WHOIS/RDAP 服务，要么根本不是真实顶级域。可以用 W2A_REFRESH_TABLE=true 拉取新委派的顶级域。',
      'err.rate_limited.hint': '按 Retry-After 头等待，或调大 W2A_RATE_LIMIT。',
      'err.unauthorized.hint': '请带上 Authorization: Bearer <token>。',
      'err.upstream_unavailable.hint': '重试即可；成功一次之后会进缓存。',
      'err.internal_error.hint': '如果一直这样，请看服务端日志。',
      'err.bad_request.hint': '错误信息里会指出是哪个字段不对。',
      'err.too_many_items.hint': '拆成多个请求，或调大 W2A_MAX_BATCH。',
      'err.method_not_allowed.hint': '以 Allow 响应头里列出的方法为准。',
    }
  };

  function detect() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved && DICT[saved]) return saved;
    } catch (e) { /* private mode, file://, etc. */ }
    var langs = navigator.languages || [navigator.language || 'en'];
    for (var i = 0; i < langs.length; i++) {
      if (/^zh\b/i.test(langs[i])) return 'zh';
      if (/^en\b/i.test(langs[i])) return 'en';
    }
    return 'en';
  }

  var current = detect();
  var listeners = [];

  function raw(key) {
    var table = DICT[current] || {};
    return table[key] !== undefined ? table[key] : DICT.en[key];
  }

  // t translates a UI key, substituting {name} placeholders.
  function t(key, params) {
    var s = raw(key);
    if (s === undefined) return key;
    if (params) {
      for (var k in params) {
        if (Object.prototype.hasOwnProperty.call(params, k)) {
          s = s.split('{' + k + '}').join(String(params[k]));
        }
      }
    }
    return s;
  }

  // notice renders a server caveat ({code, text}) in the current language,
  // falling back to the server's own English when the code is unknown.
  function notice(n) {
    if (!n) return '';
    var key = 'notice.' + n.code;
    var s = raw(key);
    if (s !== undefined) return s;
    return n.text || n.code || '';
  }

  // errorText renders the message or the hint of an API error. Both are
  // translated on the error code, so a client never has to parse English to
  // decide what to say; an unknown code falls back to the server's wording.
  function errorText(body, field) {
    var err = (body && body.error) || {};
    if (err.code) {
      var key = field === 'hint' ? 'err.' + err.code + '.hint' : 'err.' + err.code;
      var s = raw(key);
      if (s !== undefined) return s;
    }
    return err[field] || '';
  }

  var ATTRS = [
    ['data-i18n', 'textContent'],
    ['data-i18n-ph', 'placeholder'],
    ['data-i18n-title', 'title'],
    ['data-i18n-aria', 'aria-label'],
    ['data-i18n-content', 'content']
  ];

  // apply rewrites the static markup in the current language.
  function apply(root) {
    root = root || document;
    ATTRS.forEach(function (pair) {
      var nodes = root.querySelectorAll('[' + pair[0] + ']');
      Array.prototype.forEach.call(nodes, function (node) {
        var key = node.getAttribute(pair[0]);
        if (pair[1] === 'content') node.setAttribute('content', t(key));
        else node[pair[1]] = t(key);
      });
    });
  }

  function setLang(lang) {
    if (!DICT[lang]) lang = 'en';
    current = lang;
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) { /* ignore */ }
    apply(document);
    listeners.forEach(function (fn) {
      try { fn(current); } catch (e) { /* a listener must not break the switch */ }
    });
  }

  document.documentElement.lang = current === 'zh' ? 'zh-CN' : 'en';

  // The static markup ships in English so the page is readable without JS; this
  // rewrites it before the first paint for everyone else.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { apply(document); });
  } else {
    apply(document);
  }

  global.W2A = {
    get lang() { return current; },
    t: t,
    notice: notice,
    errorText: errorText,
    apply: apply,
    setLang: setLang,
    other: function () { return current === 'zh' ? 'en' : 'zh'; },
    onChange: function (fn) { listeners.push(fn); }
  };
})(window);
