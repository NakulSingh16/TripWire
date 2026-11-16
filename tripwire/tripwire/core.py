"""Orchestrator: bootstrap, change handling (deploy webhook / bundle diff), execution, triage, reporting, retest."""
import asyncio, json, os, re, time, hashlib, yaml
from urllib.parse import urlsplit
from .safety import Store, SafeClient, Blocked, Halted
from .recon import KG, ingest_har, js_routes, fetch_bundles, parse_log, Prober, template, openapi
from .attacks import Ctx, plan, run_hypothesis, passive_scan, TECH, resource_of
from . import inventory

def load_cfg(path="config/tripwire.yaml"):
    cfg = yaml.safe_load(open(path))
    secrets = {a: os.environ.get("TW_PW_" + a.upper()) for a in cfg["accounts"]}
    if not all(secrets.values()) and os.path.exists("config/secrets.local.yaml"):
        secrets = {**yaml.safe_load(open("config/secrets.local.yaml")), **{k: v for k, v in secrets.items() if v}}
    return cfg, secrets

# ---------------------------------------------------------------- OOB listener (target -> us). Never contacted by the gate.
class OOB:
    def __init__(self, host="127.0.0.1", port=8199):
        self.host, self.port, self.hits = host, port, {}
    async def start(self):
        self.srv = await asyncio.start_server(self._h, self.host, self.port)
    async def _h(self, r, w):
        try:
            line = (await asyncio.wait_for(r.readline(), 3)).decode(errors="replace")
            tok = line.split(" ")[1].strip("/").split("/")[0] if " " in line else ""
            self.hits[tok] = time.time()
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); await w.drain()
        finally:
            w.close()
    def url(self, tok): return f"http://{self.host}:{self.port}/{tok}"
    def seen(self, tok): return tok in self.hits

# ---------------------------------------------------------------- triage
def owner_of(cfg):
    def f(path):
        best = max((o for o in cfg["owners"] if path.startswith(o["match"])), key=lambda o: len(o["match"]), default=None)
        return best or {"team": "security-triage", "channel": "#appsec"}
    return f

FIX = {
    "bola_read": "Enforce object ownership in the handler: load the object scoped by the caller's tenant (WHERE id=? AND agency_id=token.agency) and return 404 otherwise. Add an object-level authz middleware and a regression test with two agencies.",
    "collection_tenant_leak": "Scope the collection query by the caller's tenant from the verified token; never return rows across tenants. If a cross-tenant export is needed, gate it behind a platform role.",
    "tenant_header_switch": "Ignore tenant-selector headers from clients; derive tenant only from the verified token (or validate membership before honouring the header).",
    "privilege_grant": "Enforce function-level authz (only agency_admin may create users) and forbid granting a role above the caller's own.",
    "mass_assignment": "Bind request bodies to an explicit allowlist DTO (name, phone); ignore/reject privileged fields like role, credit_limit.",
    "unauth_access": "Require authentication at the gateway for this route, or remove it if it is not needed.",
    "price_tamper": "Never accept prices from the client: recompute the total server-side from the stored quote and reject mismatches.",
    "negative_quantity": "Validate quantities server-side (integer, 1..max) before pricing; reject <= 0.",
    "coupon_reuse": "Record coupon redemption atomically (unique constraint on coupon+tenant) and check before applying.",
    "double_refund": "Make refunds idempotent: unique refund per booking (DB constraint) + idempotency key; check-and-set inside a transaction.",
    "payment_reuse": "On confirm, verify payment.booking_id == booking.id, payment status settled, and amount == booking total.",
    "jwt_alg_none": "Pin accepted algorithms (algorithms=['HS256'/'RS256']) in the JWT verifier; reject 'none' and unsigned tokens.",
    "logout_invalidation": "Revoke tokens on logout (denylist by jti until expiry) or use short-lived access tokens with server-side refresh revocation.",
    "missing_step_up": "Require re-authentication (current password or OTP) for bank/payout changes and notify agency admins out-of-band.",
    "sqli_error": "Use parameterised queries; map sort fields through an allowlist (e.g. {'price','name'}) instead of concatenating.",
    "ssti_math": "Never render user input as a template; pass it as data to a sandboxed template with autoescape.",
    "ssrf_oob": "Validate webhook URLs against an allowlist of partner domains, resolve and block private/link-local ranges, fetch via an egress proxy.",
    "open_redirect": "Only allow relative paths (single leading '/', not '//') or an allowlist of hosts for `next`.",
    "secret_in_response": "Remove the debug route from production builds; rotate the exposed secret immediately.",
    "card_pan_in_response": "Mask PAN in API responses (last 4 only); do not store full PAN outside the PCI vault.",
}
IMPACT = {
    "access_control": "Any agency can read or act on another agency's {res} data, exposing PII/financial data across tenants.",
    "business_logic": "Direct revenue loss / financial integrity break in the {res} flow; exploitable by any logged-in agent.",
    "auth": "Account or session integrity is broken: an attacker can act as other users or keep access after logout.",
    "injection": "Attacker-controlled input reaches an interpreter in {res}; may lead to data theft or code execution.",
    "server_side": "Server can be steered to attacker-chosen destinations ({res}); internal network/phishing exposure.",
    "data_exposure": "Sensitive data ({data}) is returned to clients that should not see it.",
    "api_hygiene": "Endpoint is reachable without authentication.",
}

def severity(f, ep, cfg):
    base = f["base"]; why = [f"base {base} ({f['technique']})"]
    crit = max([cfg["business"]["criticality"].get(t.rstrip("s"), cfg["business"]["criticality"].get(t, 0.8))
                for t in re.split(r"[/_\-{}]+", f["endpoint"].split(" ", 1)[1]) if t] or [0.8])
    s = base
    if crit >= 1.4: s += 1.0; why.append(f"asset criticality {crit} (+1.0)")
    elif crit >= 1.2: s += 0.5; why.append(f"asset criticality {crit} (+0.5)")
    elif crit <= 0.8: s -= 1.0; why.append(f"low-criticality asset (-1.0)")
    if f["oracle"] in ("canary_leak", "differential", "tenant_field") and f["cls"] == "access_control": s += 0.7; why.append("cross-tenant (+0.7)")
    if f["technique"] in ("unauth_access", "secret_in_response", "jwt_alg_none", "open_redirect"): s += 0.5; why.append("no valid credentials needed (+0.5)")
    if ep and "int" in ep.get("id_types", []): s += 0.4; why.append("sequential/enumerable IDs (+0.4)")
    if f["oracle"] in ("ledger", "price_integrity", "flow_bypass"): s += 0.8; why.append("directly realisable financial loss (+0.8)")
    if ep and ep.get("label") == "zombie": s += 0.3; why.append("zombie endpoint, likely unmonitored (+0.3)")
    s = round(min(10.0, max(0.0, s)), 1)
    band = "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"
    return s, band, why

def make_finding(cfg, kg, owners, *, technique, endpoint, hit, args=None, ttf_from=None):
    t = TECH.get(technique, {"cls": "data_exposure", "owasp": "API3:2023 BOPLA", "cwe": "CWE-200", "base": 7.5 if "secret" in technique else 6.5})
    ep = kg.by_key(endpoint)
    fid = "F-" + hashlib.sha1(f"{technique}|{endpoint}|{json.dumps(args or {}, sort_keys=True)}".encode()).hexdigest()[:6]
    f = {"id": fid, "technique": technique, "cls": t["cls"], "endpoint": endpoint, "args": args or {}, "oracle": hit["oracle"],
         "explain": hit["explain"], "audit": hit["audit"], "poc": hit["poc"], "base": t["base"], "owasp": t["owasp"], "cwe": t["cwe"],
         "data": sorted(hit.get("meta", {}).get("fields", [])), "status": "OPEN", "children": [], "detected_at": time.time()}
    f["severity"], f["band"], f["severity_why"] = severity(f, ep, cfg)
    res = resource_of(endpoint.split(" ", 1)[1]) or "platform"
    f["impact"] = IMPACT[f["cls"]].format(res=res, data=", ".join(f["data"]) or "secrets")
    f["fix"] = FIX.get(technique, "")
    o = owners(endpoint.split(" ", 1)[1]); f["owner"], f["channel"] = o["team"], o["channel"]
    f["title"] = f"[{f['band']}] {TITLE.get(technique, technique)} on {endpoint}"
    f["needs_review"] = f["band"] in ("High", "Critical")
    if ttf_from: f["ttf_s"] = round(time.time() - ttf_from, 1)
    return f

TITLE = {"bola_read": "Cross-agency object read (BOLA)", "collection_tenant_leak": "Cross-tenant rows in collection",
         "tenant_header_switch": "Tenant switch via request header", "privilege_grant": "Low role can grant admin role (BFLA)",
         "mass_assignment": "Mass assignment of privileged field", "unauth_access": "Unauthenticated access",
         "price_tamper": "Client-controlled price accepted", "negative_quantity": "Negative quantity accepted",
         "coupon_reuse": "Single-use coupon reusable", "double_refund": "Refund can be replayed (double credit)",
         "payment_reuse": "Booking confirmed with another booking's payment", "jwt_alg_none": "JWT alg=none accepted",
         "logout_invalidation": "Token valid after logout", "missing_step_up": "No step-up auth on sensitive change",
         "sqli_error": "SQL injection", "ssti_math": "Server-side template injection", "ssrf_oob": "SSRF via user-supplied URL",
         "open_redirect": "Open redirect", "secret_in_response": "Secrets exposed in response", "card_pan_in_response": "Full card number in response"}

def dedup(findings):
    """Merge on the same endpoint when same technique, or when one is a hygiene/exposure symptom of the other.
    Distinct business-logic techniques on one endpoint stay separate (they are different root causes)."""
    by = {}
    SYMPTOM = {"unauth_access", "secret_in_response", "card_pan_in_response", "collection_tenant_leak"}
    out = []
    for f in sorted(findings, key=lambda f: -f["severity"]):
        k = f["endpoint"]
        parent = next((p for p in by.get(k, []) if p["technique"] == f["technique"] or f["technique"] in SYMPTOM or p["technique"] in SYMPTOM), None)
        if parent:
            parent["children"].append({"id": f["id"], "technique": f["technique"], "explain": f["explain"]})
            parent["data"] = sorted(set(parent["data"]) | set(f["data"]))
        else:
            by.setdefault(k, []).append(f); out.append(f)
    return out

def ticket_md(f):
    poc = "\n".join(f["poc"])
    return f"""# {f['title']}
**Severity:** {f['band']} ({f['severity']}) — {'; '.join(f['severity_why'])}
**Owner:** {f['owner']} ({f['channel']})  **Status:** {f['status']}  **OWASP:** {f['owasp']}  **CWE:** {f['cwe']}
{('**Time from deploy to verified finding:** ' + str(f['ttf_s']) + ' s') if f.get('ttf_s') else ''}

## Business impact
{f['impact']}

## Proof (oracle: `{f['oracle']}`)
{f['explain']}

```bash
{poc}
```
Evidence audit IDs: {', '.join(map(str, f['audit']))} — replay with `python -m tripwire replay <audit_id>`
{('Related symptoms merged: ' + '; '.join(c['technique'] for c in f['children'])) if f['children'] else ''}

## Suggested fix
{f['fix']}

## Retest
{f.get('retest', 'Automatic on next deploy of ' + f['owner'])}
"""

# ---------------------------------------------------------------- orchestrator
class TripWire:
    def __init__(self, cfg, secrets, db="runs/tripwire.db", out="runs/out"):
        self.cfg = cfg; self.store = Store(db); self.g = SafeClient(cfg, self.store, secrets)
        self.kg = KG(); self.out = out; os.makedirs(out, exist_ok=True); self.owners = owner_of(cfg)
        self.oob = OOB(); self.ctx = None; self.findings = {}; self.traffic = {}; self.bundle_hash = None; self.timeline = []
        self.pending = []; self.state = "IDLE"; self.har_bodies = []

    def log(self, msg, **kw):
        self.timeline.append({"t": time.time(), "msg": msg, **kw}); self.store.event("timeline", msg=msg, **kw)
        print(time.strftime("%H:%M:%S"), msg, flush=True)

    async def bootstrap(self):
        t0 = time.time(); self.state = "BOOTSTRAP"
        await self.oob.start()
        cfg = self.cfg
        n = ingest_har(self.kg, cfg["inputs"]["har_dir"], self.g.scope, cfg["accounts"]); self.log(f"HAR: {n} requests -> {len(self.kg.eps)} endpoints")
        self._har_responses()
        hosts = [f"{cfg['scope']['schemes'][0]}://{h}" for h in cfg["scope"]["hosts"]]
        await self.js_scan(hosts[0], initial=True)
        log_eps = self._log_candidates()
        await self.probe(hosts, log_eps)
        self.inventory()
        self.ctx = Ctx(self.g, cfg, self.kg, self.oob)
        H = plan(self.ctx); self.log(f"planner: {len(H)} hypotheses")
        await self.execute(H)
        self.passive()
        self.inventory(); self.write_reports()
        self.state = "RUNNING"; self.log(f"bootstrap done in {time.time() - t0:.0f}s: {len(self.findings)} findings")

    def _har_responses(self):
        import glob
        for f in glob.glob(os.path.join(self.cfg["inputs"]["har_dir"], "*.har")):
            for e in json.load(open(f))["log"]["entries"]:
                self.har_bodies.append((e["request"]["method"], e["request"]["url"], e["response"].get("content", {}).get("text") or "", f))

    async def js_scan(self, host, initial=False):
        bundles = await fetch_bundles(self.g, host)
        h = hashlib.sha256("".join(sorted(bundles)).encode() + "".join(bundles.values()).encode()).hexdigest()
        if h == self.bundle_hash:
            return set()
        self.bundle_hash = h; new = set()
        for routes in (js_routes(js) for js in bundles.values()):
            for (m, tpl), q in routes.items():
                k = f"{m} {tpl}"
                if k not in self.kg.eps: new.add(k)
                e = self.kg.ep(m, tpl, host); e["sources"].add("js")
                for p in q: e["query"].setdefault(p, "tw")
        if not initial and new:
            for k in new: self.kg.eps[k]["boost"] = 3.0
        self.log(f"JS bundle {h[:8]}: {sum(1 for e in self.kg.eps.values() if 'js' in e['sources'])} routes ({len(new)} new)")
        return new

    def _log_candidates(self):
        p = self.cfg["inputs"]["gateway_log"]
        if not os.path.exists(p): return {}
        c = {}
        for r in parse_log(p):
            c.setdefault(f"{r['method']} {template(r['path'])[0]}", r["path"])
        return c

    async def probe(self, hosts, log_eps):
        """Find hidden/legacy/log-only endpoints; confirm liveness with soft-404 fingerprinting."""
        pr = Prober(self.g, self.ctx_victim()); found = 0
        known_ids = {}
        try:  # prefer ids of objects WE just created (HAR ids may be stale)
            from .attacks import Ctx
            c = await Ctx(self.g, self.cfg, self.kg).canary(self.ctx_victim())
            for e in self.kg.eps.values():
                key = e.get("id_field") or resource_of(e["template"]) + "_id"
                if "{id}" in e["template"] and c.get(key): known_ids[e["template"]] = c[key]
        except Exception as ex:
            self.log(f"prober canary failed: {ex!r}")
        for e in self.kg.eps.values():
            if e["id_values"]: known_ids.setdefault(e["template"], e["id_values"][0][1])
        def id_for(tpl):
            for k, v in known_ids.items():
                if re.sub(r"/v\d+/", "/", k) == re.sub(r"/v\d+/", "/", tpl): return v
            return "1"
        tpls = sorted({e["template"] for e in self.kg.eps.values() if e["method"] == "GET"})
        cands = {("GET", t) for t in pr.candidates(tpls)}
        cands |= {tuple(k.split(" ", 1)) for k in log_eps if k.startswith("GET ") and k not in self.kg.eps}
        for m, t in sorted(cands):
            for host in hosts:
                path = t.replace("{id}", str(id_for(t)))
                try:
                    r = await pr.real(host, path)
                except Blocked:
                    continue
                if r:
                    src = "log" if f"GET {t}" in log_eps else "probe"
                    e = self.kg.observe("GET", host + path, src, self.ctx_victim(), None, r.status_code, None, r.text)
                    found += 1; break
        # non-GET endpoints seen only in logs: attach to host where a GET sibling lives (no write probing)
        for k in log_eps:
            if k in self.kg.eps: self.kg.eps[k]["sources"].add("log")
        # auth requirement: anonymous GET on each non-id GET endpoint (read-only)
        for e in list(self.kg.eps.values()):
            if e["method"] == "GET" and "{id}" not in e["template"] and not e["template"].startswith("/static"):
                r = await self.g.request("GET", e["host"] + e["template"], agent="recon")
                e["auth_required"] = r.status_code in (401, 403)
                if "log" in e["sources"] and not ({"har", "js", "probe"} & e["sources"]) and r.status_code == 404:
                    e["live"] = False
        self.log(f"prober: {len(cands)} candidates x {len(hosts)} hosts -> {found} hidden endpoints confirmed; KG now {len(self.kg.eps)}")

    def ctx_victim(self):
        return next(k for k, a in self.cfg["accounts"].items() if a["role"] == "agent")

    def inventory(self):
        p = self.cfg["inputs"]["gateway_log"]
        if not os.path.exists(p): return
        if not self.traffic:
            self.traffic = inventory.traffic_by_endpoint(p, self.cfg["inputs"]["log_window_days"])
        for e in self.kg.eps.values():
            e["traffic"] = self.traffic.get(e["key"], {})
            sib = re.sub(r"/v\d+/", "/v*/", e["template"])
            newer_active = any(o is not e and re.sub(r"/v\d+/", "/v*/", o["template"]) == sib and o["method"] == e["method"]
                               and _ver(o["template"]) > _ver(e["template"]) and ({"har", "js"} & o["sources"]) for o in self.kg.eps.values())
            e["label"] = inventory.label(e, self.traffic, newer_active)

    async def execute(self, H, ttf_from=None):
        sem = asyncio.Semaphore(self.cfg["safety"]["concurrency"])
        stats = {"CONFIRMED": 0, "NEGATIVE": 0, "SUPPRESSED": 0, "BLOCKED": 0}
        async def one(h):
            async with sem:
                try:
                    r = await run_hypothesis(self.ctx, h)
                except Halted:
                    return
                stats[r["status"]] = stats.get(r["status"], 0) + 1
                if r["status"] == "CONFIRMED":
                    f = make_finding(self.cfg, self.kg, self.owners, technique=r["tech"], endpoint=r["key"], hit=r["hit"], args=r["args"], ttf_from=ttf_from)
                    f["replays"] = r["replays"]; f["hyp"] = list(h)
                    self.add_finding(f)
                elif r["status"] == "BLOCKED" and "approval" in r["reason"]:
                    aid = hashlib.sha1(r["hyp"].encode()).hexdigest()[:8]
                    self.store.db.execute("insert or ignore into approvals values(?,?,?,?,?,?,?)",
                                          (aid, time.time(), r["hyp"], TECH[h[1]]["risk"], json.dumps(list(h)), None, time.time() + 1800))
                    self.pending.append(h)
                elif r["status"] == "SUPPRESSED":
                    self.store.event("suppressed", hyp=r["hyp"], reason=r["reason"])
        await asyncio.gather(*(one(h) for h in H))
        self.log(f"executed {len(H)} hypotheses: {stats}")
        return stats

    def add_finding(self, f):
        old = self.findings.get(f["id"])
        if old:
            old["last_reproduced"] = time.time(); old["status"] = "OPEN" if old["status"] != "OPEN" else old["status"]; return
        self.findings[f["id"]] = f
        self.store.db.execute("insert or replace into findings values(?,?,?)", (f["id"], time.time(), json.dumps(f, default=str)))
        self.log(f"FINDING {f['id']} {f['title']}", finding=f["id"], ttf=f.get("ttf_s"))

    def passive(self):
        audit_hits = passive_scan(self.store, self.kg)
        # HAR responses are provided traffic: scan them the same way (evidence = HAR file, no request sent)
        from .attacks import _flat, SECRET_KEYS, PAN, _luhn
        for m, u, body, src in self.har_bodies:
            try: j = json.loads(body)
            except Exception: continue
            key = f"{m} {template(urlsplit(u).path)[0]}"
            for k, v in _flat(j).items():
                leaf = k.split(".")[-1].split("[")[0]
                if isinstance(v, (str, int)) and PAN.fullmatch(str(v)) and _luhn(str(v)):
                    audit_hits.setdefault((key, "card_pan_in_response"), {"fields": set(), "audit": "HAR:" + os.path.basename(src)})["fields"].add(leaf)
        for (key, kind), ev in audit_hits.items():
            if key not in self.kg.eps: continue
            hit = {"oracle": "pii_present" if "pan" in kind else "secret_present",
                   "explain": f"Response of {key} contains {kind.replace('_', ' ')} in field(s) {sorted(ev['fields'])} (values not stored)",
                   "audit": [ev["audit"]], "poc": [f"curl -s '{self.kg.eps[key]['host']}{self.kg.eps[key]['template']}' -H 'Authorization: Bearer $TOKEN'"],
                   "meta": {"fields": ev["fields"]}}
            self.add_finding(make_finding(self.cfg, self.kg, self.owners, technique=kind, endpoint=key, hit=hit))

    def final_findings(self):
        return dedup([dict(f, children=[]) for f in self.findings.values()])

    def write_reports(self):
        ff = self.final_findings()
        os.makedirs(self.out + "/tickets", exist_ok=True)
        for f in ff:
            open(f"{self.out}/tickets/{f['id']}.md", "w", encoding="utf-8").write(ticket_md(f))
        json.dump(ff, open(f"{self.out}/findings.json", "w"), indent=1, default=str)
        json.dump(openapi(self.kg, self.owners), open(f"{self.out}/openapi.json", "w"), indent=1, default=str)
        json.dump(inventory.zombie_shadow_report(self.kg, self.traffic, ff, self.owners), open(f"{self.out}/zombie_shadow.json", "w"), indent=1, default=str)
        json.dump(self.kg.to_json(), open(f"{self.out}/kg.json", "w"), indent=1, default=str)

    # ------------------------------------------------ change handling
    async def on_change(self, event):
        """Deploy webhook or bundle diff -> re-scan JS, probe new routes, plan only impacted endpoints first, then retest."""
        t0 = event.get("detected_at", time.time()); self.log(f"CHANGE {event.get('type')} {event.get('service', '')} {event.get('version', '')}")
        host = f"{self.cfg['scope']['schemes'][0]}://{self.cfg['scope']['hosts'][0]}"
        self.ctx.canaries = {}  # data may have been migrated/reset by the deploy: re-create canaries
        new = await self.js_scan(host)
        for k in new:
            self.kg.eps[k]["sources"].add("deploy")
        self.inventory()
        if new:
            H = plan(self.ctx, keys=new); self.log(f"impact set {sorted(new)} -> {len(H)} hypotheses")
            await self.execute(H, ttf_from=t0)
        await self.retest(service=event.get("service"))
        self.write_reports()

    async def retest(self, service=None):
        """Re-run each open finding's hypothesis; 3 negative-or-blocked replays => RESOLVED."""
        for f in list(self.findings.values()):
            if f["status"] != "OPEN" or not f.get("hyp"): continue
            r = await run_hypothesis(self.ctx, tuple(f["hyp"]), replays=2, need=1)
            if r["status"] == "NEGATIVE" and not r.get("errors"):
                f["status"] = "RESOLVED"; f["retest"] = f"Resolved: proof no longer reproduces ({time.strftime('%Y-%m-%d %H:%M:%S')})"
                self.log(f"RETEST {f['id']} RESOLVED")
            else:
                f["retest"] = f"Still reproducible at {time.strftime('%H:%M:%S')}"
            self.store.db.execute("insert or replace into findings values(?,?,?)", (f["id"], time.time(), json.dumps(f, default=str)))

    async def watch(self, interval=15):
        """Bundle watcher (fallback when no deploy webhook arrives)."""
        host = f"{self.cfg['scope']['schemes'][0]}://{self.cfg['scope']['hosts'][0]}"
        while True:
            await asyncio.sleep(interval)
            try:
                bundles = await fetch_bundles(self.g, host)
                h = hashlib.sha256("".join(sorted(bundles)).encode() + "".join(bundles.values()).encode()).hexdigest()
                if h != self.bundle_hash:
                    await self.on_change({"type": "BundleChanged", "detected_at": time.time()})
            except (Blocked, Halted):
                return
            except Exception as e:
                self.log(f"watcher error {e!r}")

def _ver(t):
    m = re.search(r"/v(\d+)/", t); return int(m.group(1)) if m else 0
