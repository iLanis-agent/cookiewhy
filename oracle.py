import json, sys, http.cookiejar as cj
def path_match(req, cp):
    # written separately from RFC 6265 5.1.4
    if req == cp: return True
    if req.startswith(cp) and cp.endswith('/'): return True
    if req.startswith(cp) and req[len(cp)] == '/': return True
    return False
def default_path(p):
    if not p.startswith('/') or p.count('/') <= 1: return '/'
    return p[:p.rindex('/')]
d = json.load(sys.stdin)
out = {'dm': [], 'pm': [], 'dp': []}
for h, dom in d['dm']:
    out['dm'].append(h == dom or (h.endswith('.' + dom) and cj.domain_match(h, '.' + dom)))  # cookiejar.domain_match alone accepts non-suffix matches (rfind), so the suffix is checked here
for r, c in d['pm']: out['pm'].append(path_match(r, c))
for p in d['dp']: out['dp'].append(default_path(p))
json.dump(out, sys.stdout)
