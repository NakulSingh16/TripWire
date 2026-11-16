"""Recon: HAR ingest, JS route extraction, gateway-log ingest, probing with soft-404 detection,
path normalisation, schema inference -> knowledge graph (dict of endpoints)."""
import json, os, re, glob, hashlib, random, string
from urllib.parse import urlsplit, parse_qsl
from collections import defaultdict

# ---------------------------------------------------------------- normalisation
SEG = [("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
       ("int", re.compile(r"^\d+$")), ("hex", re.compile(r"^[0-9a-f]{16,}$", re.I)),
       ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")), ("email", re.compile(r"^[^@/]+@[^@/]+$")),
       ("ref", re.compile(r"^[A-Z]{2,5}\d{5,}$"))]

def seg_type(s):
    for name, rx in SEG:
        if rx.match(s):
            return name
    return "static"

def template(path):
    """'/api/v3/bookings/1042/pay' -> ('/api/v3/bookings/{id}/pay', ['int'])"""
    out, types = [], []
    for s in path.split("/"):
        t = seg_type(s) if s else "static"
        if t == "static" or s.startswith("{"):
            out.append("{id}" if s.startswith("{") else s)
        else:
            out.append("{id}"); types.append(t)
    return "/".join(out) or "/", types

def ep_key(method, path):
    return f"{method.upper()} {template(path)[0]}"

def host_of(url):
    u = urlsplit(url); return f"{u.scheme}://{u.hostname}:{u.port or 80}"

# ---------------------------------------------------------------- knowledge graph
class KG:
    def __init__(self):
        self.eps = {}
    def ep(self, method, path, host):
        tpl, types = template(path); k = f"{method.upper()} {tpl}"
        e = self.eps.get(k)
        if not e:
            e = self.eps[k] = {"key": k, "method": method.upper(), "template": tpl, "host": host, "sources": set(), "accounts": set(),
                               "roles": set(), "query": {}, "body": {}, "headers": set(), "resp_keys": set(), "resp_samples": [],
                               "id_types": types, "examples": [], "statuses": defaultdict(int), "auth_required": None,
                               "label": None, "traffic": {}, "id_values": []}
        return e
    def observe(self, method, url, source, account=None, role=None, status=None, req_body=None, resp_text=None, headers=None):
        u = urlsplit(url); e = self.ep(method, u.path, host_of(url))
        e["sources"].add(source)
        if account: e["accounts"].add(account)
        if role: e["roles"].add(role)
        if status: e["statuses"][status] += 1
        for k, v in parse_qsl(u.query, keep_blank_values=True):
            e["query"].setdefault(k, v)
        if isinstance(req_body, dict):
            for k, v in req_body.items():
                e["body"].setdefault(k, v)
        for h in (headers or {}):
            if h.lower().startswith("x-") and h.lower() != "x-requested-with":
                e["headers"].add(h)
        ids = [s for s in u.path.split("/") if s and seg_type(s) != "static"]
        if ids and account and status and status < 300:
            e["id_values"].append((account, ids[0]))
        if len(e["examples"]) < 5:
            e["examples"].append({"url": url, "account": account, "body": req_body, "status": status})
        if resp_text and status and status < 300:
            try:
                j = json.loads(resp_text)
                keys = _keys(j)
                e["resp_keys"] |= keys
                if len(e["resp_samples"]) < 3: e["resp_samples"].append(j)
            except Exception:
                pass
        return e
    def by_key(self, k):
        return self.eps.get(k)
    def to_json(self):
        def conv(o):
            if isinstance(o, set): return sorted(o)
            if isinstance(o, defaultdict): return dict(o)
            return o
        return {k: {kk: conv(vv) for kk, vv in e.items() if kk != "resp_samples"} for k, e in self.eps.items()}

def _keys(j, prefix=""):
    out = set()
    if isinstance(j, list):
        for x in j[:3]:
            out |= _keys(x, prefix)
    elif isinstance(j, dict):
        for k, v in j.items():
            out.add(prefix + k); out |= _keys(v, prefix + k + ".")
    return out

# ---------------------------------------------------------------- HAR ingest
def ingest_har(kg: KG, har_dir, scope, accounts):
    """Account attribution: token from a login response in the same HAR -> the username that logged in."""
    n = 0
    for f in sorted(glob.glob(os.path.join(har_dir, "*.har"))):
        entries = json.load(open(f))["log"]["entries"]
        tok2acc = {}; produced = {}
        for en in entries:
            rq, rs = en["request"], en["response"]
            try:
                scope.check(rq["url"])
            except Exception:
                continue
            hd = {h["name"]: h["value"] for h in rq.get("headers", [])}
            body = None
            if rq.get("postData") and rq["postData"].get("text"):
                try: body = json.loads(rq["postData"]["text"])
                except Exception: body = None
            acc = None
            auth = hd.get("Authorization", hd.get("authorization", ""))
            if auth.startswith("Bearer "):
                acc = tok2acc.get(auth[7:])
            text = rs.get("content", {}).get("text")
            if "/login" in rq["url"] and rs["status"] == 200 and isinstance(body, dict):
                try:
                    tok = json.loads(text)["token"]; uname = body.get("username")
                    acc = next((a for a, v in accounts.items() if v["username"] == uname), None); tok2acc[tok] = acc
                except Exception: pass
            role = accounts[acc]["role"] if acc else None
            e = kg.observe(rq["method"], rq["url"], "har", acc, role, rs["status"], body, text, hd)
            for seg in urlsplit(rq["url"]).path.split("/"):  # which earlier response field produced this path id?
                if seg in produced and not e.get("id_field"):
                    e["id_field"] = produced[seg]
            try:
                for k, v in (json.loads(text) or {}).items():
                    if isinstance(v, (int, str)) and k.endswith("id") and len(str(v)) >= 3 and str(v) not in produced:
                        produced[str(v)] = k
            except Exception:
                pass
            n += 1
    return n

# ---------------------------------------------------------------- JS route extraction
JS_LIT = re.compile(r"""(["'`])((?:\\.|(?!\1).){1,200}?)\1""")
CONST = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(["'`])([^"'`]*)\2""")
API_RX = re.compile(r"^/(api|v\d|internal|admin|partner|gateway|graphql)\b")
CALL = re.compile(r"""(?:fetch|api\.(get|post|put|patch|delete)|axios\.(get|post|put|patch|delete))\s*\(\s*([^,)]+(?:\([^)]*\))?[^,)]*)(?:,\s*\{[^}]*method:\s*["'](\w+)["'])?""", re.I)

CONCAT = re.compile(r"""[A-Za-z_$][\w$]*\s*\+\s*(["'`])/[^"'`]*["'`]""")
def js_routes(js):
    """Resolve simple constant concatenation and template literals. Returns {(method, template): {query param names}}"""
    consts = {m.group(1): m.group(3) for m in CONST.finditer(js)}
    routes = {}
    def add(method, p):
        tpl = template(p.split("?")[0])[0].rstrip("/") or "/"
        q = set(re.findall(r"[?&]([A-Za-z_][\w.-]*)=", p))
        routes.setdefault((method, tpl), set()).update(q)
    for m in CALL.finditer(js):
        expr = m.group(3); method = (m.group(1) or m.group(2) or m.group(4) or "GET").upper()
        path = _resolve(expr, consts)
        if path and API_RX.match(path):
            add(method, path)
    # concatenations / bare literals outside fetch calls (router configs, location.href) -> GET
    bare = {}
    for m in list(CONCAT.finditer(js)) + list(JS_LIT.finditer(js)):
        p = _resolve(m.group(0), consts)
        if p and API_RX.match(p):
            bare.setdefault(template(p.split("?")[0])[0].rstrip("/") or "/", p)
    known = {r[1] for r in routes}
    for t, p in bare.items():
        if t not in known and not any(k.startswith(t + "/") for k in known | set(bare)):  # drop pure base-URL constants
            add("GET", p)
    return routes

def _resolve(expr, consts):
    expr = expr.strip()
    out = ""
    for part in re.split(r"\s*\+\s*", expr):
        part = part.strip()
        if not part: continue
        if part[0] in "\"'":
            out += part[1:-1]
        elif part[0] == "`":
            out += re.sub(r"\$\{([^}]*)\}", lambda m: consts.get(m.group(1).strip(), "{id}"), part.strip("`"))
        elif part in consts:
            out += consts[part]
        else:
            out += "{id}"
    return out if out.startswith("/") else None

async def fetch_bundles(gate, base):
    r = await gate.request("GET", base + "/", agent="recon")
    srcs = re.findall(r"""<script[^>]+src=["']([^"']+)""", r.text or "")
    out = {}
    for s in srcs:
        url = s if s.startswith("http") else base + s
        b = await gate.request("GET", url, agent="recon")
        if b.status_code == 200:
            out[url] = b.text
    return out

# ---------------------------------------------------------------- gateway logs
NGINX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')
def parse_log(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        m = NGINX.match(line)
        if m:
            ip, ts, meth, url, st, sz, ua = m.groups()
            yield {"ip": ip, "ts": ts, "method": meth, "path": urlsplit(url).path, "status": int(st), "ua": ua}

# ---------------------------------------------------------------- prober + soft404
VERSION_RX = re.compile(r"/v(\d+)/")
PREFIXES = ["internal", "old", "legacy", "test", "beta", "dev", "debug", "admin", "_"]
WORDLIST = ["swagger.json", "openapi.json", "api-docs", "v2/api-docs", "graphql", "actuator", "actuator/env", "actuator/health",
            "health", "metrics", "debug/vars", "debug/config", "debug/pprof", "internal/debug/config", "internal/config",
            "internal/health", "internal/metrics", ".git/HEAD", ".env", "server-status", "phpinfo.php", "console", "admin",
            "config.json", "env", "status", "version", "api/v3/admin", "api/v3/export", "api/v3/debug", "api/v3/users"]

def simhash(text):
    toks = re.findall(r"\w+", text.lower())[:400]; v = [0] * 64
    for t in toks:
        h = int(hashlib.md5(t.encode()).hexdigest()[:16], 16)
        for i in range(64):
            v[i] += 1 if h >> i & 1 else -1
    return sum(1 << i for i in range(64) if v[i] > 0)

def fp(resp):
    return (resp.status_code, (resp.headers.get("content-type") or "").split(";")[0], len(resp.text) // 50, simhash(resp.text))

def same_fp(a, b):
    return a[0] == b[0] and a[1] == b[1] and (abs(a[2] - b[2]) <= 1 or bin(a[3] ^ b[3]).count("1") <= 6)

class Prober:
    def __init__(self, gate, account):
        self.g = gate; self.acc = account; self.soft = {}
    async def baseline(self, host, prefix):
        k = (host, prefix)
        if k not in self.soft:
            fps = []
            for _ in range(2):
                rnd = "".join(random.choices(string.ascii_lowercase, k=12))
                r = await self.g.request("GET", f"{host}{prefix}/{rnd}", account=self.acc, agent="prober")
                fps.append(fp(r))
            self.soft[k] = fps
        return self.soft[k]
    async def real(self, host, path):
        """GET path; real if it differs from the soft-404 fingerprint of its parent prefix. Returns resp or None."""
        prefix = path.rsplit("/", 1)[0] if path.count("/") > 1 else ""
        base = await self.baseline(host, prefix)
        r = await self.g.request("GET", host + path.replace("{id}", "1"), account=self.acc, agent="prober")
        if r.status_code in (404, 410) or any(same_fp(fp(r), b) for b in base):
            return None
        return r
    def candidates(self, kg_templates):
        c = set()
        for t in kg_templates:
            m = VERSION_RX.search(t)
            if m:
                cur = int(m.group(1))
                for v in range(1, cur + 2):
                    if v != cur: c.add(t.replace(f"/v{cur}/", f"/v{v}/", 1))
            parts = t.strip("/").split("/")
            if len(parts) > 2:
                for p in PREFIXES:
                    c.add("/" + "/".join(parts[:2] + [p] + parts[2:]))
        c |= {"/" + w for w in WORDLIST}
        return sorted(c - set(kg_templates))

# ---------------------------------------------------------------- OpenAPI 3.1 export
def openapi(kg: KG, owners):
    paths = {}
    for e in kg.eps.values():
        p = e["template"].replace("{id}", "{id}")
        op = {"summary": e["key"], "responses": {str(s): {"description": "observed"} for s in sorted(e["statuses"]) or [200]},
              "x-tripwire-source": sorted(e["sources"]), "x-tripwire-status": e.get("label") or "unknown",
              "x-tripwire-roles-seen": sorted(e["roles"]), "x-tripwire-owner": owners(e["template"])["team"],
              "x-tripwire-last-legit": e.get("traffic", {}).get("last_legit")}
        params = [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer" if "int" in e["id_types"] else "string"}}] if "{id}" in p else []
        params += [{"name": k, "in": "query", "schema": {"type": "string"}, "example": v} for k, v in e["query"].items()]
        params += [{"name": h, "in": "header", "schema": {"type": "string"}} for h in sorted(e["headers"])]
        if params: op["parameters"] = params
        if e["body"]:
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": {k: {"type": _jt(v)} for k, v in e["body"].items()}}}}}
        if e["auth_required"] is not False and e["auth_required"] is not None:
            op["security"] = [{"bearer": []}]
        paths.setdefault(p, {})[e["method"].lower()] = op
    return {"openapi": "3.1.0", "info": {"title": "Inferred API (TripWire)", "version": "inferred"},
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}}, "paths": paths}

def _jt(v):
    return {bool: "boolean", int: "integer", float: "number", list: "array", dict: "object"}.get(type(v), "string")
