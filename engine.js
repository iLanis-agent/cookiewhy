(function (root) {
  'use strict';
  // RFC 6265 sections 5.1.3, 5.1.4, 5.2, 5.3 (rfc-editor.org/rfc/rfc6265). Notes marked "modern browsers" go beyond RFC 6265.
  function isIP(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') >= 0; }
  function domainMatch(host, domain) {
    host = host.toLowerCase(); domain = domain.toLowerCase();
    if (host === domain) return true;
    return host.length > domain.length && host.slice(-domain.length) === domain && host[host.length - domain.length - 1] === '.' && !isIP(host);
  }
  function defaultPath(uriPath) {
    if (!uriPath || uriPath[0] !== '/') return '/';
    var i = uriPath.lastIndexOf('/');
    return i === 0 ? '/' : uriPath.slice(0, i);
  }
  function pathMatch(reqPath, cookiePath) {
    if (cookiePath === reqPath) return true;
    if (reqPath.indexOf(cookiePath) === 0) {
      if (cookiePath[cookiePath.length - 1] === '/') return true;
      if (reqPath[cookiePath.length] === '/') return true;
    }
    return false;
  }
  function ws(s) { return s.replace(/^[ \t]+|[ \t]+$/g, ''); }
  function parseUrl(u) { try { var x = new URL(u); return x; } catch (e) { return null; } }
  function parse(header, url, nowMs) {
    var u = parseUrl(url);
    if (!u || !/^https?:$/.test(u.protocol)) return { ok: false, reason: 'Request URL must be a full http or https URL.' };
    var host = u.hostname.toLowerCase(), now = nowMs === undefined ? Date.now() : nowMs;
    var s = header.replace(/^\s*set-cookie:\s*/i, ''), issues = [];
    var semi = s.indexOf(';'), nv = semi >= 0 ? s.slice(0, semi) : s, rest = semi >= 0 ? s.slice(semi) : '';
    var eq = nv.indexOf('=');
    if (eq < 0) return { ok: false, reason: 'No "=" in the name-value pair, so the whole header is ignored (RFC 6265 5.2 step 2).' };
    var name = ws(nv.slice(0, eq)), value = ws(nv.slice(eq + 1));
    if (name === '') return { ok: false, reason: 'Empty cookie name, so the whole header is ignored (5.2 step 5).' };
    var attrs = [];
    while (rest) {
      rest = rest.slice(1); var j = rest.indexOf(';'), av = j >= 0 ? rest.slice(0, j) : rest; rest = j >= 0 ? rest.slice(j) : '';
      var k = av.indexOf('='), an = ws(k >= 0 ? av.slice(0, k) : av), avv = ws(k >= 0 ? av.slice(k + 1) : '');
      attrs.push([an.toLowerCase(), avv, an]);
    }
    var last = function (n) { var r; attrs.forEach(function (a) { if (a[0] === n) r = a; }); return r; };
    var c = { name: name, value: value, host: host, httpOnly: false, secure: false, sameSite: undefined };
    // 5.2.2 Max-Age, 5.2.1 Expires
    var ma = null, ex = null;
    attrs.forEach(function (a) {
      if (a[0] === 'max-age') { if (/^[0-9-][0-9]*$/.test(a[1]) && a[1] !== '') { var d = parseInt(a[1], 10); ma = d <= 0 ? -Infinity : now + d * 1000; } else issues.push('Max-Age="' + a[1] + '" is not an integer, so it is ignored.'); }
      if (a[0] === 'expires') { var t = Date.parse(a[1]); if (isNaN(t)) issues.push('Expires="' + a[1] + '" did not parse as a date, so it is ignored (approximate: this tool uses the JavaScript date parser, not the full 5.1.1 algorithm).'); else ex = t; }
    });
    if (ma !== null) { c.persistent = true; c.expiry = ma; if (ex !== null) issues.push('Both Max-Age and Expires are present: Max-Age wins (5.3 step 3).'); }
    else if (ex !== null) { c.persistent = true; c.expiry = ex; } else { c.persistent = false; c.expiry = Infinity; }
    // Domain
    var da = last('domain'), dom = '';
    if (da) { dom = da[1]; if (dom === '') { issues.push('Empty Domain attribute is ignored.'); } else { if (dom[0] === '.') dom = dom.slice(1); dom = dom.toLowerCase(); } }
    if (dom) {
      if (!domainMatch(host, dom)) return { ok: false, reason: 'Rejected: request host "' + host + '" does not domain-match Domain=' + dom + ' (5.3 step 6). A site cannot set cookies for a domain it is not in.', issues: issues };
      c.hostOnly = false; c.domain = dom;
      if (dom.indexOf('.') < 0) issues.push('Domain=' + dom + ' has a single label. Real browsers use the Public Suffix List to refuse suffixes like com or co.uk; this tool has no list, so check that yourself.');
    } else { c.hostOnly = true; c.domain = host; }
    var pa = last('path');
    c.path = pa && pa[1] && pa[1][0] === '/' ? pa[1] : defaultPath(u.pathname);
    if (pa && !(pa[1] && pa[1][0] === '/')) issues.push('Path="' + pa[1] + '" does not start with "/", so the default path ' + c.path + ' is used (5.2.4).');
    if (!pa) issues.push('No Path: default path is ' + c.path + ' (the directory of the request path ' + u.pathname + '), not "/".');
    c.secure = !!last('secure'); c.httpOnly = !!last('httponly');
    var ss = last('samesite'); if (ss) { var v = ss[1].toLowerCase(); c.sameSite = v === 'strict' ? 'Strict' : v === 'lax' ? 'Lax' : v === 'none' ? 'None' : undefined; if (!c.sameSite) issues.push('SameSite=' + ss[1] + ' is not Strict, Lax or None (modern browsers treat it as Lax or ignore it).'); }
    // modern browsers notes (beyond RFC 6265)
    if (c.sameSite === 'None' && !c.secure) issues.push('Modern browsers: SameSite=None without Secure is rejected.');
    if (/^__secure-/i.test(name) && !c.secure) issues.push('Modern browsers: a __Secure- cookie must have Secure (and come from https). It would be rejected.');
    if (/^__host-/i.test(name)) { if (!c.secure || c.path !== '/' || !c.hostOnly) issues.push('Modern browsers: a __Host- cookie needs Secure, Path=/ and no Domain. This one would be rejected.'); }
    if (c.secure && u.protocol === 'http:') issues.push('Modern browsers: a Secure cookie set over plain http is rejected. RFC 6265 itself allows it.');
    if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(header)) issues.push('Control characters in the header: browsers drop the cookie.');
    if (name.length + value.length > 4096) issues.push('Name plus value is over 4096 bytes: browsers drop it.');
    if (c.expiry <= now) issues.push('Already expired: the browser deletes any existing cookie with the same name, domain and path instead of storing this.');
    return { ok: true, cookie: c, issues: issues };
  }
  function willSend(c, url, nowMs) {
    var u = parseUrl(url); if (!u) return { send: false, why: ['Not a URL.'] };
    var host = u.hostname.toLowerCase(), now = nowMs === undefined ? Date.now() : nowMs, why = [];
    if (c.hostOnly ? host !== c.domain : !domainMatch(host, c.domain)) why.push(c.hostOnly ? 'host-only cookie: "' + host + '" is not exactly ' + c.domain : '"' + host + '" does not domain-match ' + c.domain);
    if (!pathMatch(u.pathname || '/', c.path)) why.push('path "' + (u.pathname || '/') + '" does not path-match ' + c.path);
    if (c.secure && u.protocol !== 'https:') why.push('Secure cookie, request is not https');
    if (c.expiry <= now) why.push('expired');
    return { send: why.length === 0, why: why };
  }
  var api = { parse: parse, willSend: willSend, domainMatch: domainMatch, defaultPath: defaultPath, pathMatch: pathMatch };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.CookieWhy = api;
})(typeof window !== 'undefined' ? window : this);
