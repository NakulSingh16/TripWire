"""Safety layer: the ONLY HTTP egress. scope, kill switch, risk policy, credential vault, AIMD rate limit,
health monitor, response cap, ownership ledger, hash-chained audit log."""
import asyncio, hashlib, ipaddress, json, os, re, socket, sqlite3, time, random, string
from collections import deque
from urllib.parse import urlsplit
import httpx

class Blocked(Exception): ...
class Halted(Exception): ...

def sha(s) -> str:
    return hashlib.sha256(s if isinstance(s, bytes) else str(s).encode()).hexdigest()

# ---------------------------------------------------------------- store
class Store:
    """sqlite (WAL). One DB for audit, ledger, findings, events, approvals."""
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("pragma journal_mode=wal")
        self.db.executescript("""
        create table if not exists audit(id integer primary key, ts real, agent text, hyp text, account text, method text, url text,
            req_headers text, req_body text, status int, resp_headers text, resp_body text, resp_sha text, latency real,
            decision text, reason text, prev_hash text, hash text);
        create table if not exists ledger(id integer primary key, ts real, account text, rtype text, object_id text, marker text, cleanup text, cleaned int default 0);
        create table if not exists events(id integer primary key, ts real, type text, payload text);
        create table if not exists findings(id text primary key, ts real, data text);
        create table if not exists approvals(id text primary key, ts real, hyp text, risk int, preview text, decision text, expires real);
        create table if not exists kv(k text primary key, v text);
        """)
        self.lock = asyncio.Lock()
    def q(self, sql, *a):
        return self.db.execute(sql, a).fetchall()
    def event(self, type_, **payload):
        self.db.execute("insert into events(ts,type,payload) values(?,?,?)", (time.time(), type_, json.dumps(payload, default=str)))
    def kv_get(self, k, d=None):
        r = self.q("select v from kv where k=?", k); return json.loads(r[0][0]) if r else d
    def kv_set(self, k, v):
        self.db.execute("insert or replace into kv values(?,?)", (k, json.dumps(v, default=str)))

# ---------------------------------------------------------------- audit (hash chain)
SECRET_HDR = {"authorization", "cookie", "set-cookie", "x-api-key"}
def mask_headers(h):
    return {k: ("<sha:" + sha(v)[:12] + ">" if k.lower() in SECRET_HDR else v) for k, v in h.items()}

class Audit:
    def __init__(self, store: Store):
        self.s = store
        r = store.q("select hash from audit order by id desc limit 1")
        self.prev = r[0][0] if r else "GENESIS"
    def log(self, **e):
        row = dict(ts=time.time(), agent=e.get("agent", ""), hyp=e.get("hyp", ""), account=e.get("account", ""), method=e["method"],
                   url=e["url"], req_headers=json.dumps(mask_headers(e.get("req_headers", {}))), req_body=(e.get("req_body") or "")[:65536],
                   status=e.get("status"), resp_headers=json.dumps(e.get("resp_headers", {})), resp_body=(e.get("resp_body") or "")[:65536],
                   resp_sha=e.get("resp_sha", ""), latency=e.get("latency"), decision=e["decision"], reason=e.get("reason", ""))
        h = sha(self.prev + json.dumps(row, sort_keys=True, default=str))
        cur = self.s.db.execute("insert into audit(" + ",".join(row) + ",prev_hash,hash) values(" + ",".join("?" * (len(row) + 2)) + ")",
                                (*row.values(), self.prev, h))
        self.prev = h
        return cur.lastrowid
    def verify(self):
        prev = "GENESIS"; cols = None
        cur = self.s.db.execute("select * from audit order by id")
        cols = [c[0] for c in cur.description]
        for r in cur:
            d = dict(zip(cols, r)); h = d.pop("hash"); p = d.pop("prev_hash"); d.pop("id")
            if p != prev or sha(prev + json.dumps(d, sort_keys=True, default=str)) != h:
                return False, d
            prev = h
        return True, None

# ---------------------------------------------------------------- scope
class Scope:
    def __init__(self, cfg):
        self.schemes = set(cfg["schemes"]); self.hosts = set(cfg["hosts"])
        self.cidrs = [ipaddress.ip_network(c) for c in cfg["cidrs"]]
        self.deny = [re.compile(p) for p in cfg.get("path_denylist", [])]
    def check(self, url):
        u = urlsplit(url)
        if u.scheme not in self.schemes:
            raise Blocked(f"scheme {u.scheme} not allowed")
        hp = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
        if hp not in self.hosts:
            raise Blocked(f"host {hp} out of scope")
        try:  # re-resolve every request (DNS rebinding)
            ips = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, None)}
        except socket.gaierror:
            raise Blocked("unresolvable host")
        for ip in ips:
            if not any(ipaddress.ip_address(ip) in c for c in self.cidrs):
                raise Blocked(f"resolved ip {ip} out of scope")
        for d in self.deny:
            if d.search(u.path):
                raise Blocked(f"path denylisted ({d.pattern})")

# ---------------------------------------------------------------- rate limit (token buckets + AIMD)
class Bucket:
    def __init__(self, rps):
        self.rps = rps; self.cap = 1.0; self.tokens = 1.0; self.t = time.monotonic()  # no burst: <= rps+1 in any 1 s window
    async def take(self):
        while True:
            now = time.monotonic(); self.tokens = min(self.cap, self.tokens + (now - self.t) * self.rps); self.t = now
            if self.tokens >= 1:
                self.tokens -= 1; return
            await asyncio.sleep((1 - self.tokens) / self.rps)

class RateLimiter:
    def __init__(self, global_rps, ep_rps, concurrency):
        self.max_rps = global_rps; self.ep_rps = ep_rps
        self.g = Bucket(global_rps); self.eps = {}; self.sem = asyncio.Semaphore(concurrency); self.last_cut = 0
    async def acquire(self, key):
        await self.g.take()
        await self.eps.setdefault(key, Bucket(self.ep_rps)).take()
    def decrease(self):  # multiplicative decrease
        if time.monotonic() - self.last_cut > 5:
            self.g.rps = max(0.5, self.g.rps / 2); self.last_cut = time.monotonic()
    def increase(self):  # additive increase
        self.g.rps = min(self.max_rps, self.g.rps + 0.5)

# ---------------------------------------------------------------- health
class Health:
    def __init__(self, cfg):
        self.c = cfg; self.win = deque(); self.base_p95 = None; self.timeouts = 0; self.state = "OK"
    def record(self, latency, status, timeout=False):
        now = time.monotonic(); self.win.append((now, latency, status))
        while self.win and now - self.win[0][0] > self.c["window_s"]:
            self.win.popleft()
        self.timeouts = self.timeouts + 1 if timeout else 0
        lats = sorted(x[1] for x in self.win if x[1] is not None)
        if self.base_p95 is None and len(lats) >= 20:
            self.base_p95 = max(lats[int(len(lats) * .95) - 1], 0.02)
        p95 = lats[int(len(lats) * .95) - 1] if len(lats) >= 10 else 0
        err = sum(1 for x in self.win if x[2] is not None and x[2] >= 500 and x[2] != 501) / max(1, len(self.win))
        r429 = any(x[2] == 429 for x in self.win)
        b = self.base_p95 or 1e9
        if self.timeouts >= 3 or p95 > self.c["alarm_p95_x"] * b or (len(self.win) >= 20 and err > self.c["alarm_5xx"]):
            self.state = "ALARM"
        elif r429 or p95 > self.c["warn_p95_x"] * b or (len(self.win) >= 20 and err > self.c["warn_5xx"]):
            self.state = "WARN"
        else:
            self.state = "OK"
        return self.state

# ---------------------------------------------------------------- vault
class Vault:
    """Holds sessions for provided test accounts only. Passwords from env TW_PW_<ALIAS> or local secrets file."""
    def __init__(self, cfg, secrets: dict):
        self.accounts = cfg["accounts"]; self.login = cfg["login"]; self.secrets = secrets
        self.tokens = {}; self.throwaway = set(); self.failures = {}
    def known_token(self, tok):
        return tok in self.tokens.values()
    def info(self, alias):
        return self.accounts[alias.split("#")[0]]

# ---------------------------------------------------------------- the gate
class SafeClient:
    def __init__(self, cfg, store: Store, secrets: dict):
        self.cfg = cfg; self.s = store; self.audit = Audit(store); self.scope = Scope(cfg["scope"])
        sc = cfg["safety"]; self.sc = sc
        self.rl = RateLimiter(sc["global_rps"], sc["per_endpoint_rps"], sc["concurrency"])
        self.health = Health(sc["health"]); self.vault = Vault(cfg, secrets)
        self.http = httpx.AsyncClient(timeout=sc["timeout_s"], follow_redirects=False, verify=True, trust_env=False)
        self.stop_file = "STOP"; self.state = "RUNNING"; self.approved = set(); self.stats = {"sent": 0, "blocked": 0}
        self._healthy_since = time.monotonic(); self.paused_until = 0.0

    # -- kill switch / pause
    def halted(self):
        return os.path.exists(self.stop_file) or self.s.kv_get("halt", False)
    def halt(self, why="manual"):
        self.s.kv_set("halt", True); self.s.event("HALT", reason=why)

    # -- ledger (objects we created; only these may be mutated destructively)
    def ledger_add(self, account, rtype, oid, marker="", cleanup=""):
        self.s.db.execute("insert into ledger(ts,account,rtype,object_id,marker,cleanup) values(?,?,?,?,?,?)",
                          (time.time(), account, rtype, str(oid), marker, cleanup))
    def owned(self, oid):
        return bool(self.s.q("select 1 from ledger where object_id=?", str(oid)))

    # -- vault login (goes through the gate like everything else)
    async def session(self, alias, fresh=False):
        """alias 'a1_admin' -> cached token; 'a1_admin#throwaway' -> new token for destructive auth tests"""
        if alias in self.vault.tokens and not fresh:
            return self.vault.tokens[alias]
        base = alias.split("#")[0]
        if self.vault.failures.get(base, 0) >= 3:
            raise Blocked(f"account {base} locked out by vault policy")
        acc = self.vault.info(base); L = self.cfg["login"]
        r = await self.request("POST", L["host"] + L["path"], json={L["user_field"]: acc["username"], L["pass_field"]: self.vault.secrets[base]},
                               agent="vault", _login=True)
        if r.status_code != 200:
            self.vault.failures[base] = self.vault.failures.get(base, 0) + 1
            raise Blocked(f"login failed for {base}: {r.status_code}")
        tok = r.json()[L["token_jsonpath"]]
        self.vault.tokens[alias] = tok
        if "#" in alias:
            self.vault.throwaway.add(tok)
        return tok

    async def request(self, method, url, *, account=None, headers=None, json=None, params=None, content=None, risk=0,
                      agent="", hyp="", forged_token=None, object_id=None, _login=False):
        headers = dict(headers or {})
        meta = dict(agent=agent, hyp=hyp, account=account or ("forged" if forged_token else "anon"), method=method, url=url,
                    req_headers=headers, req_body=(_dumps(json) if json is not None else (content or "")))
        try:
            if self.halted():
                raise Halted("kill switch")
            while time.monotonic() < self.paused_until:  # health alarm: hold all traffic, auto-resume probe after cooldown
                if self.halted():
                    raise Halted("kill switch")
                await asyncio.sleep(0.5)
            if self.state == "PAUSED":
                self.state = "RUNNING"; self.health.win.clear(); self.health.state = "OK"
            self.scope.check(url)
            if any(k.lower() in SECRET_HDR for k in headers):
                raise Blocked("raw credential headers not allowed; use vault account or forged_token")
            if risk > self.sc["auto_approve_max_risk"]:
                if not (hyp in self.approved or (self.sc.get("approve_all") and risk == 3)):
                    raise Blocked(f"risk L{risk} requires human approval")
            if method == "DELETE" and not (object_id and self.owned(object_id)):
                raise Blocked("DELETE only allowed on ledger-owned objects")
            if "/logout" in url and not (account and "#" in account):
                raise Blocked("logout only on throwaway sessions")
            if account:
                headers["Authorization"] = "Bearer " + await self.session(account)
            elif forged_token:
                headers["Authorization"] = "Bearer " + forged_token
            meta["req_headers"] = headers
        except (Blocked, Halted) as e:
            self.stats["blocked"] += 1
            aid = self.audit.log(**meta, decision="BLOCKED", reason=str(e))
            raise type(e)(f"{e} [audit {aid}]")
        key = method + " " + _template_key(url)
        async with self.rl.sem:
            await self.rl.acquire(key)
            t0 = time.monotonic(); status = None; body = b""; rh = {}; timeout = False
            try:
                async with self.http.stream(method, url, headers=headers, json=json, params=params, content=content) as r:
                    status = r.status_code; rh = dict(r.headers)
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) > self.sc["max_body_bytes"]:
                            body = body[: self.sc["max_body_bytes"]]; break  # cap: no bulk extraction
            except httpx.TimeoutException:
                timeout = True
            except httpx.HTTPError as e:
                rh = {"x-tw-error": str(e)}
            lat = time.monotonic() - t0
        st = self.health.record(lat, status, timeout)
        if st == "WARN":
            self.rl.decrease(); self._healthy_since = time.monotonic()
        elif st == "ALARM":
            self.rl.decrease(); self.state = "PAUSED"; self.paused_until = time.monotonic() + self.sc.get("pause_s", 30)
            self.s.event("PAUSE", reason="health alarm", p95=self.health.base_p95)
        elif time.monotonic() - self._healthy_since > 30:
            self.rl.increase(); self._healthy_since = time.monotonic()
        self.stats["sent"] += 1
        text = body.decode("utf-8", "replace")
        aid = self.audit.log(**meta, status=status, resp_headers=rh, resp_body=text, resp_sha=sha(body), latency=lat,
                             decision="SENT", reason="timeout" if timeout else "")
        return Resp(status or 0, rh, text, aid, lat)

class Resp:
    def __init__(self, status, headers, text, audit_id, latency):
        self.status_code = status; self.headers = {k.lower(): v for k, v in headers.items()}; self.text = text
        self.audit_id = audit_id; self.latency = latency
    def json(self):
        try:
            return json.loads(self.text)
        except Exception:
            return None

def _dumps(o):
    return json.dumps(o, default=str)

_num = re.compile(r"/\d+(?=/|$)")
def _template_key(url):
    return _num.sub("/{id}", urlsplit(url).path)

def rand_marker():
    return "TW-CANARY-" + "".join(random.choices("0123456789abcdef", k=8))
