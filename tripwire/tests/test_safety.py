"""Safety gate guarantees (rules of engagement). Network is mocked: httpx.MockTransport."""
import asyncio, json, os, sys, time, copy, pytest, httpx, yaml
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tripwire.safety import SafeClient, Store, Audit, Blocked, Halted
from tripwire.recon import template, js_routes, same_fp, fp
from tripwire.semantics import rule_label

CFG = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "config", "tripwire.yaml")))
SECRETS = {a: "x" for a in CFG["accounts"]}
SENT = []

def handler(req: httpx.Request):
    SENT.append(str(req.url))
    if req.url.path.endswith("/login"):
        return httpx.Response(200, json={"token": "tok-" + json.loads(req.content)["username"]})
    if req.url.path == "/big":
        return httpx.Response(200, content=b"x" * 5_000_000)
    if req.url.path == "/slow":
        time.sleep(0.05); return httpx.Response(503)
    return httpx.Response(200, json={"ok": True})

def gate(tmp_path, **safety):
    cfg = copy.deepcopy(CFG); cfg["safety"].update(safety)
    g = SafeClient(cfg, Store(str(tmp_path / "t.db")), SECRETS)
    g.http = httpx.AsyncClient(transport=httpx.MockTransport(handler)); g.stop_file = str(tmp_path / "STOP")
    return g

def run(c): return asyncio.run(c)
H = "http://127.0.0.1:8100"

@pytest.mark.parametrize("u", ["http://example.com/", "http://127.0.0.1:9999/", "https://127.0.0.1:8100/", "http://localhost.evil.com:8100/",
                               "http://127.0.0.1:8199/oob", H + "/admin/purge/all", H + "/x/payments/live"])
def test_out_of_scope_blocked_and_audited(tmp_path, u):
    g = gate(tmp_path); SENT.clear()
    with pytest.raises(Blocked): run(g.request("GET", u))
    assert SENT == []
    assert g.s.q("select decision from audit")[-1][0] == "BLOCKED"

def test_raw_credentials_rejected(tmp_path):
    g = gate(tmp_path)
    with pytest.raises(Blocked): run(g.request("GET", H + "/api", headers={"Authorization": "Bearer stolen"}))
    with pytest.raises(Blocked): run(g.request("GET", H + "/api", headers={"Cookie": "s=1"}))

def test_risk_needs_approval_and_l4_never_auto(tmp_path):
    g = gate(tmp_path, approve_all=True)
    run(g.request("POST", H + "/a", risk=3, hyp="h3"))          # L3 auto-approved in eval mode
    with pytest.raises(Blocked): run(g.request("POST", H + "/a", risk=4, hyp="h4"))
    g2 = gate(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path)
    with pytest.raises(Blocked): run(g2.request("POST", H + "/a", risk=3, hyp="h5"))
    g2.approved.add("h5"); run(g2.request("POST", H + "/a", risk=3, hyp="h5"))

def test_delete_only_ledger_objects(tmp_path):
    g = gate(tmp_path)
    with pytest.raises(Blocked): run(g.request("DELETE", H + "/api/x/123", object_id="123"))
    g.ledger_add("a1_agent", "x", "123"); run(g.request("DELETE", H + "/api/x/123", object_id="123"))

def test_logout_only_throwaway(tmp_path):
    g = gate(tmp_path)
    with pytest.raises(Blocked): run(g.request("POST", H + "/api/v3/auth/logout", account="a1_agent"))
    run(g.request("POST", H + "/api/v3/auth/logout", account="a1_agent#throwaway"))

def test_vault_injects_token_and_masks_in_audit(tmp_path):
    g = gate(tmp_path); run(g.request("GET", H + "/api/v3/me", account="a1_agent"))
    hdr = g.s.q("select req_headers from audit where url like '%/me'")[0][0]
    assert "tok-a1_agent" not in hdr and "<sha:" in hdr

def test_kill_switch(tmp_path):
    g = gate(tmp_path); open(g.stop_file, "w").close()
    with pytest.raises(Halted): run(g.request("GET", H + "/"))

def test_response_cap(tmp_path):
    g = gate(tmp_path); r = run(g.request("GET", H + "/big"))
    assert len(r.text) <= CFG["safety"]["max_body_bytes"]

def test_rate_limit(tmp_path):
    g = gate(tmp_path, global_rps=5, per_endpoint_rps=5)
    async def burst():
        t = time.monotonic(); await asyncio.gather(*(g.request("GET", H + f"/r{i}") for i in range(15))); return time.monotonic() - t
    assert run(burst()) >= 1.8   # 15 req at 5 rps with burst 5 => >= 2s

def test_health_alarm_pauses(tmp_path):
    g = gate(tmp_path, pause_s=0.5)
    async def go():
        for _ in range(25): await g.request("GET", H + "/slow")
    run(go())
    assert any(r[0] == "PAUSE" for r in g.s.q("select type from events")) and g.rl.g.rps < CFG["safety"]["global_rps"]

def test_audit_chain_detects_tamper(tmp_path):
    g = gate(tmp_path); [run(g.request("GET", H + f"/p{i}")) for i in range(3)]
    assert Audit(g.s).verify()[0]
    g.s.db.execute("update audit set status=500 where id=2")
    assert not Audit(g.s).verify()[0]

def test_template_and_js():
    assert template("/api/v3/bookings/1042/pay")[0] == "/api/v3/bookings/{id}/pay"
    assert template("/x/3fa85f64-5717-4562-b3fc-2c963f66afa6")[0] == "/x/{id}"
    r = js_routes('const API="/api/v3"; fetch(API + "/a/" + id); api.post(`${API}/b`, {}); location.href = API + "/c?next=" + n;')
    assert ("GET", "/api/v3/a/{id}") in r and ("POST", "/api/v3/b") in r and r[("GET", "/api/v3/c")] == {"next"}

def test_semantics_value_heuristics():
    assert rule_label("x", "4111111111111111")[0] == "pii" and rule_label("cb", "https://a.b")[0] == "url"
    assert rule_label("X-Agency-Id")[0] == "tenant_id" and rule_label("passport")[0] == "pii"
