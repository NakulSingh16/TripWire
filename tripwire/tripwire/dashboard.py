"""Dashboard + deploy webhook (FastAPI, same process). Single HTML page polling /api/state every 2 s."""
import asyncio, hmac, hashlib, json, os, time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

def build(tw):
    app = FastAPI(title="TripWire")
    secret = os.environ.get("TW_WEBHOOK_SECRET", "")

    @app.post("/hooks/deploy")
    async def deploy(req: Request):
        raw = await req.body()
        if secret and not hmac.compare_digest(req.headers.get("x-signature", ""), hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()):
            raise HTTPException(401, "bad signature")
        ev = json.loads(raw or b"{}"); ev.update(type="DeployEvent", detected_at=time.time())
        tw.store.event("deploy", **ev)
        asyncio.get_running_loop().create_task(tw.on_change(ev))
        return {"accepted": True}

    @app.get("/api/state")
    async def state():
        ff = tw.final_findings()
        sc = {r[0]: r[1] for r in tw.store.q("select decision, count(*) from audit group by decision")}
        appr = [dict(zip(("id", "hyp", "risk", "decision"), r)) for r in tw.store.q("select id,hyp,risk,decision from approvals order by ts desc")]
        return JSONResponse(json.loads(json.dumps({
            "state": "HALTED" if tw.g.halted() else tw.g.state if tw.g.state == "PAUSED" else tw.state,
            "health": tw.g.health.state, "rps_cap": tw.g.rl.g.rps, "audit": sc, "timeline": tw.timeline[-40:],
            "findings": [{k: f.get(k) for k in ("id", "title", "band", "severity", "owner", "status", "endpoint", "explain", "poc", "ttf_s", "replays", "children", "oracle")} for f in ff],
            "inventory": [{"key": e["key"], "label": e.get("label"), "sources": sorted(e["sources"]), "last_legit": e.get("traffic", {}).get("last_legit"),
                           "legit_window": e.get("traffic", {}).get("legit_window", 0)} for e in tw.kg.eps.values()],
            "approvals": appr, "blocked": [dict(zip(("id", "url", "reason"), r)) for r in tw.store.q("select id,url,reason from audit where decision='BLOCKED' order by id desc limit 20")],
        }, default=str)))

    @app.post("/api/kill")
    async def kill():
        tw.g.halt("dashboard"); return {"halted": True}

    @app.post("/api/approve/{aid}")
    async def approve(aid: str):
        r = tw.store.q("select hyp, preview from approvals where id=?", aid)
        if not r: raise HTTPException(404)
        tw.store.db.execute("update approvals set decision='APPROVED' where id=?", (aid,))
        tw.g.approved.add(r[0][0]); h = tuple(json.loads(r[0][1]))
        asyncio.get_running_loop().create_task(tw.execute([h]))
        return {"approved": aid}

    @app.get("/openapi-inferred.json")
    async def oas():
        from .recon import openapi
        return openapi(tw.kg, tw.owners)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return PAGE
    return app

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TripWire</title>
<style>:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8a8f98;--card:#171a21;--line:#262b36;--crit:#ff4d4f;--high:#ff8c1a;--med:#f5c518;--low:#5cb85c}
body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif}header{display:flex;gap:16px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
h1{font-size:18px;margin:0}main{display:grid;grid-template-columns:2fr 1fr;gap:16px;padding:16px}section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
table{width:100%;border-collapse:collapse}td,th{padding:4px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.b{padding:1px 6px;border-radius:4px;font-weight:600;color:#000}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}.mut{color:var(--mut)}button{background:#b00020;color:#fff;border:0;border-radius:6px;padding:6px 12px;cursor:pointer}
pre{white-space:pre-wrap;font-size:12px;margin:4px 0}@media(max-width:800px){main{grid-template-columns:1fr}}</style></head><body>
<header><h1>TripWire</h1><span id="st"></span><span id="au" class="mut"></span><span style="flex:1"></span><button onclick="fetch('/api/kill',{method:'POST'})">KILL SWITCH</button></header>
<main><div><section><h3>Findings</h3><table id="f"></table></section><section><h3>API inventory</h3><table id="inv"></table></section></div>
<div><section><h3>Approvals (L3/L4)</h3><div id="ap" class="mut">none</div></section><section><h3>Timeline</h3><div id="tl"></div></section><section><h3>Blocked by safety gate</h3><div id="bl"></div></section></div></main>
<script>const e=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function tick(){try{const s=await (await fetch('/api/state')).json();
st.innerHTML=`state <b>${e(s.state)}</b> · health <b>${e(s.health)}</b> · rate cap ${(+s.rps_cap).toFixed(1)} rps`;au.textContent='audit: '+JSON.stringify(s.audit);
f.innerHTML='<tr><th>Sev</th><th>Finding</th><th>Owner</th><th>Status</th><th>TTF</th></tr>'+s.findings.map(x=>`<tr><td><span class="b ${x.band}">${x.band}</span> ${x.severity}</td><td><b>${e(x.title)}</b><div class="mut">${e(x.explain)}</div><details><summary>PoC</summary><pre>${e((x.poc||[]).join('\\n'))}</pre></details></td><td>${e(x.owner)}</td><td>${e(x.status)}</td><td>${x.ttf_s?x.ttf_s+'s':''}</td></tr>`).join('');
inv.innerHTML='<tr><th>Endpoint</th><th>Label</th><th>Sources</th><th>Legit req (window)</th><th>Last legit</th></tr>'+s.inventory.sort((a,b)=>(a.label||'').localeCompare(b.label||'')).map(x=>`<tr><td>${e(x.key)}</td><td>${e(x.label)}</td><td class="mut">${e(x.sources.join(','))}</td><td>${x.legit_window}</td><td class="mut">${e(x.last_legit||'')}</td></tr>`).join('');
ap.innerHTML=s.approvals.length?s.approvals.map(a=>`<div>L${a.risk} ${e(a.hyp)} ${a.decision?e(a.decision):`<button onclick="fetch('/api/approve/${a.id}',{method:'POST'})">approve</button>`}</div>`).join(''):'none';
tl.innerHTML=s.timeline.slice().reverse().map(t=>`<div><span class="mut">${new Date(t.t*1000).toLocaleTimeString()}</span> ${e(t.msg)}</div>`).join('');
bl.innerHTML=s.blocked.map(b=>`<div class="mut">#${b.id} ${e(b.url)} — ${e(b.reason)}</div>`).join('')||'none';}catch(err){st.textContent='dashboard offline'}}
tick();setInterval(tick,2000)</script></body></html>"""
