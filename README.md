# CookieWhy
Paste a Set-Cookie header and the URL that sent it: see what the browser stores and which later URLs get the cookie.
Static client-side app. Open `app.html`.
Source: RFC 6265 (https://www.rfc-editor.org/rfc/rfc6265.txt), sections 5.1.3, 5.1.4, 5.2, 5.3 read directly. Notes on __Host-, __Secure-, SameSite=None and Secure-over-http are from memory of current browser behaviour (RFC 6265bis not fetched).
Tests: `node test-engine.js`, 12000+ comparisons with Python (`oracle.py`) for domain-match, path-match and default-path, plus 17 worked behaviours. Deviation: Python's http.cookiejar.domain_match accepts a non-suffix match (it uses rfind), so the oracle adds an explicit suffix check. The Python path-match and default-path functions in oracle.py were written separately from the RFC text, so they are a second implementation of the same spec, not an independent reference.
Not covered: Public Suffix List, SameSite request blocking, full 5.1.1 cookie-date parsing (JavaScript Date.parse is used), cookie size and count limits beyond a note.
