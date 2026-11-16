"""Planner + techniques + oracles + verification.
Every technique is a `probe(ctx, ep, **args) -> Hit|None`. The verifier re-runs a probe until 2 of 3 runs agree
(probes create fresh state each run), so flaky/cached responses don't become findings."""
import asyncio, json, re, time, random, base64, hashlib, uuid
from urllib.parse import urlsplit, urlencode
from .safety import Blocked, Halted, rand_marker
from .semantics import rule_label
from .recon import template

TECH = {}
def technique(name, cls, risk, owasp, cwe, base):
    def deco(f):
        TECH[name] = dict(fn=f, cls=cls, risk=risk, owasp=owasp, cwe=cwe, base=base, name=name); return f
    return deco

class Hit(dict):
    pass

class Inconclusive(Exception):
    """Positive control failed (e.g. owner can't read own object) -> can't say vulnerable OR fixed."""

def hit(oracle, explain, audit, poc, **meta):
    return Hit(oracle=oracle, explain=explain, audit=[a for a in audit if a], poc=poc, meta=meta)

# ---------------------------------------------------------------- helpers
ROLE_RANK = {"sub_agent": 1, "agent": 2, "finance": 2, "agency_admin": 3, "platform_admin": 4}

def url(ctx, ep, path=None, query=None):
    p = path or ep["template"]
    return ep["host"] + p + (("?" + urlencode(query)) if query else "")

def sub_id(tpl, v):
    return tpl.replace("{id}", str(v), 1)

def poc_line(method, u, account=None, body=None, headers=None):
    h = "".join(f" -H '{k}: {v}'" for k, v in (headers or {}).items())
    a = f" -H 'Authorization: Bearer ${account.upper().replace('#', '_')}_TOKEN'" if account else ""
    b = f" -H 'Content-Type: application/json' -d '{json.dumps(body)}'" if body is not None else ""
    return f"curl -s -X {method} '{u}'{a}{h}{b}"

def jsim(a, b):
    """structural+value similarity of two JSON docs (0..1)"""
    fa, fb = _flat(a), _flat(b)
    if not fa or not fb:
        return 1.0 if a == b and a is not None else 0.0
    keys = set(fa) | set(fb); same = sum(1 for k in keys if fa.get(k) == fb.get(k))
    return same / len(keys)

def _flat(j, p=""):
    out = {}
    if isinstance(j, dict):
        for k, v in j.items(): out.update(_flat(v, p + "." + k))
    elif isinstance(j, list):
        for i, v in enumerate(j[:20]): out.update(_flat(v, f"{p}[{i}]"))
    else:
        out[p] = j
    return out

def ok(r):
    return r is not None and 200 <= r.status_code < 300

def resource_of(tpl):
    segs = [s for s in tpl.split("/") if s]
    for i, s in enumerate(segs):
        if s == "{id}" and i:
            return segs[i - 1].rstrip("s").replace("-", "_")
    return segs[-1].rstrip("s") if segs else ""

# ---------------------------------------------------------------- context
class Ctx:
    def __init__(self, gate, cfg, kg, oob=None):
        self.g = gate; self.cfg = cfg; self.kg = kg; self.oob = oob
        acc = cfg["accounts"]
        self.accounts = acc
        ags = sorted({a["agency"] for a in acc.values()})
        pick = lambda ag, roles: next((k for r in roles for k, a in acc.items() if a["agency"] == ag and a["role"] == r), None)
        self.victim = pick(ags[0], ["agent", "agency_admin"]); self.victim_admin = pick(ags[0], ["agency_admin"])
        self.attacker = pick(ags[1], ["agent", "agency_admin"]); self.attacker_admin = pick(ags[1], ["agency_admin"])
        self.low = min((k for k, a in acc.items() if a["agency"] == ags[0]), key=lambda k: ROLE_RANK.get(acc[k]["role"], 2))
        self.canaries = {}; self.locks = {}

    async def req(self, method, u, account=None, hyp="", **kw):
        return await self.g.request(method, u, account=account, hyp=hyp, agent=kw.pop("agent", "executor"), **kw)

    async def canary(self, owner, fresh=False):
        """Create (or reuse) a victim-owned object bundle via the configured create flow. Every text field carries a marker."""
        if owner in self.canaries and not fresh:
            return self.canaries[owner]
        flows = self.cfg["business"]["canary_flows"]["booking"]
        host = self.cfg["login"]["host"]; marker = rand_marker()
        vars_ = {"marker": marker, "rand7": str(random.randint(10**6, 10**7 - 1))}
        for step in flows:
            (method, path), = [(k, v) for k, v in step.items() if k.isupper()]
            body = json.loads(_fill(json.dumps(step.get("body", {})), vars_))
            r = await self.req(method, host + _fill(path, vars_), account=owner, json=body, agent="canary", risk=2)
            j = r.json() or {}
            if not ok(r):
                raise RuntimeError(f"canary step {method} {path} failed {r.status_code}")
            for k, src in step.get("save", {}).items():
                vars_[k] = j.get(src)
                if k.endswith("_id"):
                    self.g.ledger_add(owner, k[:-3], j.get(src), marker, cleanup=f"{method} {path}")
        self.canaries[owner] = vars_
        return vars_

def _fill(s, v):
    for k, val in v.items():
        s = s.replace("\"{" + k + "}\"", json.dumps(val)) if isinstance(val, (int, float)) else s
        s = s.replace("{" + k + "}", str(val))
    return s

async def victim_id(ctx, ep, owner):
    """Pick an ID of an object owned by `owner` usable in ep's {id}: canary key by resource name, dependency field,
    or harvest from owner's own collection listing."""
    c = await ctx.canary(owner)
    for key in (ep.get("id_field"), resource_of(ep["template"]) + "_id"):
        if key and c.get(key) is not None:
            return c[key], key
    coll = ctx.kg.by_key("GET " + ep["template"].rsplit("/{id}", 1)[0])
    if coll:
        r = await ctx.req("GET", url(ctx, coll), owner, agent="harvest")
        j = r.json()
        if isinstance(j, list) and j and isinstance(j[0], dict) and "id" in j[0]:
            return j[0]["id"], "harvested"
    return None, None

# ---------------------------------------------------------------- ACCESS CONTROL
@technique("bola_read", "access_control", 1, "API1:2023 BOLA", "CWE-639", 6.5)
async def bola_read(ctx, ep, hyp):
    oid, how = await victim_id(ctx, ep, ctx.victim)
    if oid is None:
        raise Inconclusive("no victim-owned id for " + ep["key"])
    u = url(ctx, ep, sub_id(ep["template"], oid))
    own_r = await ctx.req("GET", u, ctx.victim, hyp)
    if not ok(own_r):
        raise Inconclusive(f"owner control failed ({own_r.status_code})")
    att = await ctx.req("GET", u, ctx.attacker, hyp)
    base = await ctx.req("GET", url(ctx, ep, sub_id(ep["template"], _bogus(oid))), ctx.attacker, hyp)
    if not ok(att):
        return None
    marker = ctx.canaries[ctx.victim]["marker"]
    sim = jsim(own_r.json(), att.json()); bsim = jsim(own_r.json(), base.json()) if ok(base) else 0
    if marker in att.text or (sim >= 0.9 and bsim < 0.5):
        return hit("canary_leak" if marker in att.text else "differential",
                   f"{ctx.attacker} (agency {ctx.accounts[ctx.attacker]['agency']}) read {ctx.victim}'s object {oid} "
                   f"(owner/attacker similarity {sim:.2f}, denial-baseline similarity {bsim:.2f})",
                   [own_r.audit_id, att.audit_id, base.audit_id], [poc_line("GET", u, ctx.attacker)], object_id=oid, id_source=how)

def _bogus(oid):
    return int(oid) + 7_777_777 if str(oid).isdigit() else str(uuid.uuid4())

@technique("collection_tenant_leak", "access_control", 1, "API1:2023 BOLA", "CWE-639", 6.5)
async def collection_leak(ctx, ep, hyp):
    """GET collection as attacker; any row whose tenant field != attacker tenant, or that contains victim canary ids."""
    c = await ctx.canary(ctx.victim)
    r = await ctx.req("GET", url(ctx, ep), ctx.attacker, hyp)
    j = r.json()
    if not ok(r) or not isinstance(j, list):
        return None
    mine = ctx.accounts[ctx.attacker]["agency"]
    vic_ids = {c.get("booking_id"), c.get("traveller_id"), c.get("invoice_id")} - {None}
    foreign = [row for row in j if isinstance(row, dict) and (any(row.get(k) not in (None, mine) for k in ("agency_id", "tenant_id", "org_id"))
                                                         or row.get("id") in vic_ids)]
    if foreign:
        return hit("tenant_field", f"{ctx.attacker} (agency {mine}) received {len(foreign)} rows belonging to other tenants "
                   f"(only counts/ids kept as evidence)", [r.audit_id], [poc_line("GET", url(ctx, ep), ctx.attacker)], rows=len(foreign))

TENANT_HEADERS = ["X-Agency-Id", "X-Tenant-Id", "X-Org-Id", "X-Account-Id"]
@technique("tenant_header_switch", "access_control", 1, "API1:2023 BOLA", "CWE-639", 7.5)
async def tenant_switch(ctx, ep, hyp):
    vic_ag = ctx.accounts[ctx.victim]["agency"]
    own_r = await ctx.req("GET", url(ctx, ep), ctx.victim, hyp)
    for h in sorted(ep["headers"]) or TENANT_HEADERS:
        r = await ctx.req("GET", url(ctx, ep), ctx.attacker, hyp, headers={h: str(vic_ag)})
        j = r.json()
        if ok(r) and isinstance(j, dict) and any(j.get(k) == vic_ag for k in ("agency_id", "tenant_id", "org_id")) and jsim(own_r.json(), j) >= 0.9:
            return hit("differential", f"Setting {h}: {vic_ag} as {ctx.attacker} returns agency {vic_ag}'s data (identical to the owner's view)",
                       [own_r.audit_id, r.audit_id], [poc_line("GET", url(ctx, ep), ctx.attacker, headers={h: vic_ag})], header=h)

@technique("privilege_grant", "access_control", 2, "API5:2023 BFLA", "CWE-269", 8.0)
async def privilege_grant(ctx, ep, hyp, field):
    """Low role asks the endpoint to create a principal with a role above its own. Proof: admin read-back shows it."""
    low = ctx.low; top = max(ROLE_RANK, key=lambda r: ROLE_RANK[r] if r != "platform_admin" else 0)
    name = "tw_" + uuid.uuid4().hex[:8]
    body = {"username": name, field: top, "password": "Tw#" + uuid.uuid4().hex[:10]}
    r = await ctx.req(ep["method"], url(ctx, ep), low, hyp, json=body, risk=2)
    if not ok(r):
        return None
    ctx.g.ledger_add(low, "user", name, cleanup=f"DELETE {ep['template']}/{name}")
    admin = next(k for k, a in ctx.accounts.items() if a["agency"] == ctx.accounts[low]["agency"] and a["role"] == "agency_admin")
    rb = await ctx.req("GET", url(ctx, ep), admin, hyp)
    rows = rb.json() if isinstance(rb.json(), list) else []
    if any(isinstance(x, dict) and x.get("username") == name and x.get(field) == top for x in rows):
        d = await ctx.req("DELETE", url(ctx, ep) + "/" + name, admin, hyp, object_id=name, risk=2)  # cleanup
        return hit("privilege", f"{low} (role {ctx.accounts[low]['role']}) created user {name} with {field}={top}; admin read-back confirms",
                   [r.audit_id, rb.audit_id, d.audit_id], [poc_line(ep["method"], url(ctx, ep), low, body)])

@technique("mass_assignment", "access_control", 2, "API3:2023 BOPLA", "CWE-915", 6.5)
async def mass_assign(ctx, ep, hyp, field):
    """Add a response-only privileged field to an update of OUR OWN object, then read back; restore after."""
    acct = ctx.low
    get_ep = ctx.kg.by_key("GET " + ep["template"])
    before = await ctx.req("GET", url(ctx, get_ep), acct, hyp)
    old = (before.json() or {}).get(field)
    if old is None:
        return None
    new = (old + 777777) if isinstance(old, (int, float)) else ("agency_admin" if field == "role" else str(old) + "_tw")
    w = await ctx.req(ep["method"], url(ctx, ep), acct, hyp, json={field: new}, risk=2)
    after = await ctx.req("GET", url(ctx, get_ep), acct, hyp)
    if ok(w) and (after.json() or {}).get(field) == new:
        await ctx.req(ep["method"], url(ctx, ep), acct, hyp, json={field: old}, risk=2)  # restore
        return hit("state_change", f"{ep['key']} accepted client field '{field}' ({old} -> {new}); GET read-back confirms persistence",
                   [before.audit_id, w.audit_id, after.audit_id], [poc_line(ep["method"], url(ctx, ep), acct, {field: new})], field=field)

@technique("unauth_access", "api_hygiene", 0, "API2:2023 Broken Authentication", "CWE-306", 5.3)
async def unauth(ctx, ep, hyp):
    oid = None
    u = url(ctx, ep)
    if "{id}" in ep["template"]:
        oid, _ = await victim_id(ctx, ep, ctx.victim)
        if oid is None: return None
        u = url(ctx, ep, sub_id(ep["template"], oid))
    authed = await ctx.req("GET", u, ctx.victim, hyp)
    anon = await ctx.req("GET", u, None, hyp)
    if ok(anon) and ok(authed) and jsim(authed.json(), anon.json()) >= 0.9 and anon.json() is not None:
        # noise control: only a finding if the route is used WITH auth in normal traffic, or the anonymous data is sensitive
        sensitive = sorted(sensitive_fields(anon.json()))
        used_authed = "har" in ep["sources"] and bool(ep["accounts"])
        if used_authed or sensitive:
            return hit("differential", f"{ep['key']} returns the same data without any token" + (f"; sensitive fields: {sensitive}" if sensitive else ""),
                       [authed.audit_id, anon.audit_id], [poc_line("GET", u)], fields=set(sensitive))

# ---------------------------------------------------------------- BUSINESS LOGIC (driven by configured flow)
def flow(ctx):
    return ctx.cfg["business"]["flows"]["book"]

def F(ctx, name, bid=None):
    m, p = flow(ctx)[name].split(" ", 1)
    return m, ctx.cfg["login"]["host"] + (p.replace("{id}", str(bid)) if bid is not None else p)

async def new_booking(ctx, acct, hyp, extra=None, quote_body=None):
    c = await ctx.canary(acct)
    m, u = F(ctx, "quote"); q = await ctx.req(m, u, acct, hyp, json=quote_body or flow(ctx)["quote_body"], risk=2)
    if not ok(q): return None, None, q
    qj = q.json(); m, u = F(ctx, "book")
    b = await ctx.req(m, u, acct, hyp, json={"quote_id": qj["quote_id"], "traveller_id": c["traveller_id"], **(extra or {})}, risk=2)
    if ok(b): ctx.g.ledger_add(acct, "booking", b.json()["booking_id"], cleanup="cancel")
    return qj, (b.json() if ok(b) else None), b

@technique("price_tamper", "business_logic", 2, "API6:2023 Unrestricted Business Flow", "CWE-602", 8.1)
async def price_tamper(ctx, ep, hyp, field):
    qj, bj, r = await new_booking(ctx, ctx.victim, hyp, extra={field: 1})
    if bj and abs(float(bj.get("total", qj["total"])) - qj["total"]) > 0.01:
        return hit("price_integrity", f"Server quoted {qj['total']} but booking was created with total {bj['total']} after sending {field}=1",
                   [r.audit_id], [poc_line("POST", F(ctx, "book")[1], ctx.victim, {"quote_id": "<QUOTE_ID>", "traveller_id": "<ID>", field: 1})])

@technique("negative_quantity", "business_logic", 2, "API6:2023 Unrestricted Business Flow", "CWE-20", 7.1)
async def negative_qty(ctx, ep, hyp, field):
    body = dict(ep["body"]); body[field] = -2
    r = await ctx.req(ep["method"], url(ctx, ep), ctx.victim, hyp, json=body, risk=2)
    j = r.json() or {}
    money = [k for k, v in j.items() if isinstance(v, (int, float)) and rule_label(k)[0] == "money"]
    if ok(r) and money and any(j[k] <= 0 for k in money):
        return hit("price_integrity", f"{field}=-2 accepted; server computed {money[0]}={j[money[0]]}", [r.audit_id],
                   [poc_line(ep["method"], url(ctx, ep), ctx.victim, body)])

@technique("coupon_reuse", "business_logic", 2, "API6:2023 Unrestricted Business Flow", "CWE-837", 6.5)
async def coupon_reuse(ctx, ep, hyp, field):
    code = flow(ctx).get("coupon"); acct = ctx.attacker_admin  # an account in a tenant that already used it in normal traffic
    res = []
    for _ in range(2):
        qj, bj, r = await new_booking(ctx, acct, hyp, extra={field: code})
        res.append((qj, bj, r))
    (q1, b1, r1), (q2, b2, r2) = res
    if b1 and b2 and b2["total"] < q2["total"]:
        return hit("business_rule", f"Single-use coupon {code} applied twice by {acct}: totals {b1['total']} and {b2['total']} (quotes {q1['total']}, {q2['total']})",
                   [r1.audit_id, r2.audit_id], [poc_line("POST", F(ctx, "book")[1], acct, {"quote_id": "<QUOTE_ID>", field: code})] * 2)

@technique("double_refund", "business_logic", 3, "API6:2023 Unrestricted Business Flow", "CWE-841", 8.6)
async def double_refund(ctx, ep, hyp):
    acct = ctx.victim
    qj, bj, _ = await new_booking(ctx, acct, hyp)
    if not bj: return None
    bid = bj["booking_id"]
    m, u = F(ctx, "pay", bid); await ctx.req(m, u, acct, hyp, json={"method": "wallet"}, risk=3)
    m, u = F(ctx, "cancel", bid); await ctx.req(m, u, acct, hyp, json={}, risk=3)
    mb, ub = F(ctx, "balance"); b0 = (await ctx.req(mb, ub, acct, hyp)).json()["balance"]
    m, u = F(ctx, "refund"); r1 = await ctx.req(m, u, acct, hyp, json={"booking_id": bid}, risk=3)
    r2 = await ctx.req(m, u, acct, hyp, json={"booking_id": bid}, risk=3)
    b1r = await ctx.req(mb, ub, acct, hyp); b1 = b1r.json()["balance"]
    if ok(r1) and ok(r2) and b1 - b0 > bj["total"] + 0.01:
        return hit("ledger", f"Refund replayed: wallet rose by {b1 - b0} for a booking of {bj['total']} (expected +{bj['total']})",
                   [r1.audit_id, r2.audit_id, b1r.audit_id], [poc_line(m, u, acct, {"booking_id": "<CANCELLED_BOOKING>"})] * 2)

@technique("payment_reuse", "business_logic", 2, "API6:2023 Unrestricted Business Flow", "CWE-841", 8.6)
async def payment_reuse(ctx, ep, hyp):
    acct = ctx.victim
    _, A, _ = await new_booking(ctx, acct, hyp); _, B, _ = await new_booking(ctx, acct, hyp)
    if not (A and B): return None
    m, u = F(ctx, "pay", A["booking_id"]); p = await ctx.req(m, u, acct, hyp, json={"method": "card", "card_number": "4111111111111111"}, risk=2)
    pid = (p.json() or {}).get("payment_id")
    m, u = F(ctx, "confirm", B["booking_id"]); c = await ctx.req(m, u, acct, hyp, json={"payment_id": pid}, risk=2)
    mr, ur = F(ctx, "read", B["booking_id"]); rb = await ctx.req(mr, ur, acct, hyp)
    if ok(c) and (rb.json() or {}).get("status") not in ("PENDING_PAYMENT", None):
        return hit("flow_bypass", f"Unpaid booking {B['booking_id']} reached {rb.json()['status']} using payment {pid} of booking {A['booking_id']}",
                   [p.audit_id, c.audit_id, rb.audit_id], [poc_line(m, u, acct, {"payment_id": "<PAYMENT_ID_OF_OTHER_BOOKING>"})])

# ---------------------------------------------------------------- AUTH
def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

@technique("jwt_alg_none", "auth", 1, "API2:2023 Broken Authentication", "CWE-347", 9.1)
async def jwt_none(ctx, ep, hyp):
    tok = await ctx.g.session(ctx.attacker)
    claims = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    vic = ctx.accounts[ctx.victim]
    forged_claims = {**claims, "sub": vic["username"], "agency": vic["agency"], "role": vic["role"]}
    forged = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64(forged_claims) + "."
    bad_sig = tok.rsplit(".", 1)[0] + "." + _b64({"x": 1})  # control: tampered signature must be rejected
    ctrl = await ctx.req("GET", url(ctx, ep), None, hyp, forged_token=bad_sig)
    r = await ctx.req("GET", url(ctx, ep), None, hyp, forged_token=forged)
    if ok(r) and not ok(ctrl) and r.json() is not None:
        return hit("jwt_accepted", f"alg=none token impersonating {ctx.victim} accepted (bad-signature control rejected with {ctrl.status_code})",
                   [ctrl.audit_id, r.audit_id], [f"# forged header {{\"alg\":\"none\"}}, payload sub={vic['username']}", poc_line("GET", url(ctx, ep), headers={"Authorization": "Bearer <FORGED>"})])

@technique("logout_invalidation", "auth", 2, "API2:2023 Broken Authentication", "CWE-613", 5.4)
async def logout_inval(ctx, ep, hyp):
    me = ctx.kg.by_key("GET /api/v3/me") or next((e for e in ctx.kg.eps.values() if e["method"] == "GET" and e["template"].endswith("/me")), None)
    if not me: return None
    alias = ctx.victim + "#throwaway"
    await ctx.g.session(alias, fresh=True)
    pre = await ctx.req("GET", url(ctx, me), alias, hyp)
    lo = await ctx.req(ep["method"], url(ctx, ep), alias, hyp, json={})
    post = await ctx.req("GET", url(ctx, me), alias, hyp)
    if ok(pre) and ok(lo) and ok(post):
        return hit("jwt_accepted", "Session token still accepted after successful logout", [pre.audit_id, lo.audit_id, post.audit_id],
                   [poc_line(ep["method"], url(ctx, ep), "SESSION", {}), poc_line("GET", url(ctx, me), "SESSION")])

@technique("missing_step_up", "auth", 2, "API2:2023 Broken Authentication", "CWE-306", 6.8)
async def step_up(ctx, ep, hyp):
    """Re-submit the CURRENT value (no real change) without any password/OTP field."""
    acct = ctx.victim_admin
    prof = ctx.kg.by_key("GET /api/v3/agency/profile")
    field = next((k for k in ep["body"] if rule_label(k)[0] != "credential"), None) or ep["template"].rsplit("/", 1)[-1].replace("-", "_")
    cur = (await ctx.req("GET", url(ctx, prof), acct, hyp)).json() if prof else {}
    val = (cur or {}).get(field)
    if val is None: return None
    r = await ctx.req(ep["method"], url(ctx, ep), acct, hyp, json={field: val}, risk=2)
    if ok(r):
        return hit("business_rule", f"Sensitive action {ep['key']} succeeded with session token only (no current_password/OTP)",
                   [r.audit_id], [poc_line(ep["method"], url(ctx, ep), acct, {field: "<NEW_VALUE>"})])

# ---------------------------------------------------------------- INJECTION
SQL_ERR = re.compile(r"sql|sqlite|syntax error|mysql|postgres|ORA-\d+|near \"|unterminated|unrecognized token", re.I)

async def _get_with(ctx, ep, acct, hyp, param, val):
    q = dict(ep["query"]); q[param] = val
    path = ep["template"]
    if "{id}" in path:
        oid, _ = await victim_id(ctx, ep, acct); path = sub_id(path, oid)
    return await ctx.req("GET", url(ctx, ep, path, q), acct, hyp)

@technique("sqli_error", "injection", 1, "API8:2023 Security Misconfiguration", "CWE-89", 8.6)
async def sqli(ctx, ep, hyp, param):
    acct = ctx.victim; orig = ep["query"].get(param, "a")
    base = await _get_with(ctx, ep, acct, hyp, param, orig)
    bad = await _get_with(ctx, ep, acct, hyp, param, orig + "'")
    fixed = await _get_with(ctx, ep, acct, hyp, param, orig + "--")  # comment-terminated: valid SQL if injected raw
    if SQL_ERR.search(bad.text) and not SQL_ERR.search(base.text) and not SQL_ERR.search(fixed.text) and ok(fixed):
        return hit("injection_error", f"Param '{param}': quote causes DB error ({bad.status_code}); comment-terminated payload is valid SQL ({fixed.status_code}) -> raw SQL concatenation",
                   [base.audit_id, bad.audit_id, fixed.audit_id], [poc_line("GET", url(ctx, ep, None, {param: orig + "'"}), acct)])

@technique("ssti_math", "injection", 1, "API8:2023 Security Misconfiguration", "CWE-1336", 8.8)
async def ssti(ctx, ep, hyp, param):
    acct = ctx.victim
    for p in ("{{1337*7}}", "${1337*7}", "<%= 1337*7 %>"):
        r = await _get_with(ctx, ep, acct, hyp, param, "tw" + p)
        if "tw9359" in r.text:
            return hit("ssti_math", f"Param '{param}': template expression {p} evaluated to 9359", [r.audit_id],
                       [poc_line("GET", url(ctx, ep, None, {param: p}), acct)])

# ---------------------------------------------------------------- SERVER SIDE
@technique("ssrf_oob", "server_side", 2, "API7:2023 SSRF", "CWE-918", 8.2)
async def ssrf(ctx, ep, hyp, param):
    if not ctx.oob: return None
    acct = ctx.victim_admin; tok = uuid.uuid4().hex[:12]
    body = dict(ep["body"]); body[param] = ctx.oob.url(tok)
    r = await ctx.req(ep["method"], url(ctx, ep), acct, hyp, json=body, risk=2)
    await asyncio.sleep(1.0)
    if ctx.oob.seen(tok):
        return hit("oob_callback", f"Server fetched our out-of-band URL supplied in '{param}' (callback token {tok})", [r.audit_id],
                   [poc_line(ep["method"], url(ctx, ep), acct, {param: "http://<OOB-HOST>/<token>"})])

@technique("open_redirect", "server_side", 0, "API8:2023 Security Misconfiguration", "CWE-601", 4.7)
async def open_redirect(ctx, ep, hyp, param):
    for p in ("https://tw-redirect.example/x", "//tw-redirect.example/x"):
        r = await ctx.req("GET", url(ctx, ep, None, {param: p}), None, hyp)
        loc = r.headers.get("location", "")
        if 300 <= r.status_code < 400 and urlsplit(loc if "://" in loc else "https:" + loc).hostname == "tw-redirect.example":
            return hit("redirect_location", f"'{param}' redirects to arbitrary external host ({loc})", [r.audit_id], [poc_line("GET", url(ctx, ep, None, {param: p}))])

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
def sensitive_fields(j):
    """Value-validated: a key name alone is not enough (API specs contain 'name', 'password' as metadata)."""
    out = set()
    for k, v in _flat(j).items():
        leaf = k.split(".")[-1].split("[")[0]
        if not isinstance(v, (str, int)) or isinstance(v, bool): continue
        sv = str(v)
        if rule_label(leaf)[0] == "credential" and isinstance(v, str) and len(v) >= 8 and " " not in v: out.add(leaf)
        elif SECRET_KEYS.search(leaf) and isinstance(v, str) and len(v) >= 8 and " " not in v: out.add(leaf)
        elif EMAIL.match(sv) or (PAN.fullmatch(sv) and _luhn(sv)): out.add(leaf)
    return out

# ---------------------------------------------------------------- passive DATA EXPOSURE (over audited responses)
SECRET_KEYS = re.compile(r"(secret|private_key|api_key|password|passwd|aws_access)", re.I)
PAN = re.compile(r"(?<!\d)(\d{13,19})(?!\d)")
def _luhn(d):
    s = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch) * (2 if i % 2 else 1); s += n - 9 if n > 9 else n
    return s % 10 == 0

def passive_scan(store, kg):
    """Scan every SENT response once. Returns {(key, kind): evidence}. Only field names / counts kept."""
    out = {}
    for aid, method, u, body, status in store.q("select id,method,url,resp_body,status from audit where decision='SENT' and status between 200 and 299"):
        try:
            j = json.loads(body)
        except Exception:
            continue
        key = f"{method} {template(urlsplit(u).path)[0]}"
        flat = _flat(j)
        for k, v in flat.items():
            leaf = k.split(".")[-1].split("[")[0]
            if isinstance(v, str) and SECRET_KEYS.search(leaf) and len(v) >= 8:
                out.setdefault((key, "secret_in_response"), {"fields": set(), "audit": aid})["fields"].add(leaf)
            if isinstance(v, (str, int)) and PAN.fullmatch(str(v)) and _luhn(str(v)):
                out.setdefault((key, "card_pan_in_response"), {"fields": set(), "audit": aid})["fields"].add(leaf)
    return out

# ---------------------------------------------------------------- PLANNER
def plan(ctx, keys=None):
    """Rule matrix over KG endpoints -> hypotheses [(priority, tech, ep_key, args)]"""
    cfg = ctx.cfg; pub = cfg["business"]["public_endpoints"]; crit = cfg["business"]["criticality"]; H = []
    fl = flow(ctx); flow_eps = {v for v in fl.values() if isinstance(v, str)}
    def add(t, e, **a):
        tokens = re.split(r"[/_\-{}]+", e["template"])
        c = max([crit.get(x.rstrip("s"), crit.get(x, 0.8)) for x in tokens if x] or [0.8])
        H.append((round(c * TECH[t]["base"] * e.get("boost", 1), 2), t, e["key"], a))
    for e in ctx.kg.eps.values():
        if keys is not None and e["key"] not in keys: continue
        if e.get("label") == "retired" or not e.get("live", True): continue
        m, tpl = e["method"], e["template"]
        public = any(_glob(p, e["key"]) for p in pub)
        sem = {k: rule_label(k, v)[0] for k, v in {**e["query"], **e["body"]}.items()}
        hsem = {h: rule_label(h)[0] for h in e["headers"]}
        if m == "GET" and "{id}" in tpl and not public:
            add("bola_read", e)
        if m == "GET" and "{id}" not in tpl and not public and e["template"] not in ("/",):
            add("collection_tenant_leak", e)
            if any(k.split(".")[-1] in ("agency_id", "tenant_id", "org_id") for k in e["resp_keys"]) or "tenant_id" in hsem.values():
                add("tenant_header_switch", e)
        if m == "GET" and not public and e.get("auth_required") is not True:
            add("unauth_access", e)
        if m in ("POST", "PUT") and any(s == "privilege" for s in sem.values()) is False:
            pass
        # privilege grant: create-principal endpoints (collection POST whose GET lists principals with a privilege field)
        if m == "POST" and "{id}" not in tpl:
            g = ctx.kg.by_key("GET " + tpl)
            pf = next((k for k in (g or {}).get("resp_keys", []) if rule_label(k)[0] == "privilege" and "." not in k), None)
            if pf and "user" in tpl:
                add("privilege_grant", e, field=pf)
        if m in ("PATCH", "PUT") and "{id}" not in tpl and ctx.kg.by_key("GET " + tpl):
            g = ctx.kg.by_key("GET " + tpl)
            for f in sorted(g["resp_keys"]):
                if "." not in f and f not in e["body"] and rule_label(f)[0] in ("privilege",):
                    add("mass_assignment", e, field=f)
        if e["key"] == fl.get("book"):
            for f in sorted(ctx.kg.eps[e["key"]]["resp_keys"]):
                if "." not in f and f not in e["body"] and rule_label(f)[0] == "money":
                    add("price_tamper", e, field=f)
            cf = next((k for k in e["body"] if sem.get(k) == "coupon"), None) or ("coupon" if fl.get("coupon") else None)
            if cf: add("coupon_reuse", e, field=cf)
        if m in ("POST", "PUT", "PATCH"):
            for k, s in sem.items():
                if s == "quantity" and isinstance(e["body"].get(k), int):
                    add("negative_quantity", e, field=k)
                if s == "url" and k in e["body"]:
                    add("ssrf_oob", e, param=k)
        if e["key"] == fl.get("refund"):
            add("double_refund", e)
        if e["key"] == fl.get("confirm"):
            add("payment_reuse", e)
        if m == "POST" and tpl.endswith("/logout"):
            add("logout_invalidation", e)
        if e["key"] in cfg["business"].get("sensitive_actions", []):
            add("missing_step_up", e)
        if m == "GET":
            for k, s in sem.items():
                if k in e["query"] and s in ("sort", "search", "other"):
                    add("sqli_error", e, param=k)
                if k in e["query"] and s in ("other", "search"):
                    add("ssti_math", e, param=k)
                if k in e["query"] and s == "redirect":
                    add("open_redirect", e, param=k)
    # JWT alg-none: one authenticated GET collection per host
    by_host = {}
    for e in ctx.kg.eps.values():
        if (keys is None or e["key"] in keys) and e["method"] == "GET" and "{id}" not in e["template"] and not any(_glob(p, e["key"]) for p in pub) \
                and e["template"] not in ("/",) and not e["template"].startswith(("/static", "/internal")) and e.get("auth_required") is not False:
            by_host.setdefault(e["host"], e)
    for e in by_host.values():
        add("jwt_alg_none", e)
    H.sort(key=lambda h: -h[0])
    return H

def _glob(pat, key):
    return re.fullmatch(re.escape(pat).replace(r"\*", ".*"), key) is not None

# ---------------------------------------------------------------- VERIFY + RUN
async def run_hypothesis(ctx, h, replays=3, need=2):
    prio, t, key, args = h
    ep = ctx.kg.by_key(key); spec = TECH[t]
    hyp = f"{t}:{key}:{json.dumps(args, sort_keys=True)}"
    hits, errors = [], []
    lock = ctx.locks.setdefault(key, asyncio.Lock())
    async with lock:
        for i in range(replays):
            try:
                r = await spec["fn"](ctx, ep, hyp, **args)
            except Blocked as e:
                return {"status": "BLOCKED", "hyp": hyp, "reason": str(e)}
            except Halted:
                raise
            except Exception as e:  # Inconclusive / flow errors
                errors.append(repr(e)); r = None
            if r: hits.append(r)
            if len(hits) >= need or (i - len(hits)) >= replays - need:  # decided
                break
    if len(hits) >= need:
        return {"status": "CONFIRMED", "hyp": hyp, "tech": t, "key": key, "args": args, "hit": hits[0], "replays": f"{len(hits)}/{i + 1}"}
    if hits:
        return {"status": "SUPPRESSED", "hyp": hyp, "reason": f"only {len(hits)}/{i + 1} replays positive (flaky)"}
    if errors and len(errors) >= i + 1:
        return {"status": "INCONCLUSIVE", "hyp": hyp, "errors": errors[:1]}
    return {"status": "NEGATIVE", "hyp": hyp, "errors": errors[:1]}
