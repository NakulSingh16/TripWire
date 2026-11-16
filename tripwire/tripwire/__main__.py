"""CLI.
  python -m tripwire run [--watch] [--port 8300]   bootstrap, then serve dashboard + deploy webhook + bundle watcher
  python -m tripwire verify-audit                   check the audit hash chain
  python -m tripwire replay <audit_id>              re-send an audited request through the safety gate
  python -m tripwire stop                           kill switch (creates ./STOP)
"""
import argparse, asyncio, json, sys
from .core import TripWire, load_cfg
from .safety import Store, Audit, SafeClient

async def run(a):
    import uvicorn
    from .dashboard import build
    cfg, secrets = load_cfg(a.config)
    tw = TripWire(cfg, secrets, db=a.db, out=a.out)
    server = uvicorn.Server(uvicorn.Config(build(tw), host="127.0.0.1", port=a.port, log_level="warning"))
    srv = asyncio.create_task(server.serve())
    await tw.bootstrap()
    if a.watch:
        asyncio.create_task(tw.watch())
        await srv
    else:
        server.should_exit = True; await srv
    return tw

async def replay(a):
    cfg, secrets = load_cfg(a.config); st = Store(a.db)
    r = st.q("select method,url,account,req_body,req_headers from audit where id=?", a.audit_id)
    if not r: sys.exit("no such audit id")
    m, u, acct, body, hdrs = r[0]
    g = SafeClient(cfg, st, secrets)
    h = {k: v for k, v in json.loads(hdrs).items() if k.lower() not in ("authorization", "content-length", "host")}
    if body: h.setdefault("Content-Type", "application/json")
    resp = await g.request(m, u, account=None if acct in ("anon", "forged", "") else acct, headers=h,
                           content=body or None, agent="replay")
    print(resp.status_code, resp.text[:2000])

def main():
    ap = argparse.ArgumentParser(prog="tripwire"); ap.add_argument("cmd"); ap.add_argument("audit_id", nargs="?", type=int)
    ap.add_argument("--config", default="config/tripwire.yaml"); ap.add_argument("--db", default="runs/tripwire.db")
    ap.add_argument("--out", default="runs/out"); ap.add_argument("--port", type=int, default=8300); ap.add_argument("--watch", action="store_true")
    a = ap.parse_args()
    if a.cmd == "run": asyncio.run(run(a))
    elif a.cmd == "replay": asyncio.run(replay(a))
    elif a.cmd == "verify-audit":
        ok, bad = Audit(Store(a.db)).verify(); print("audit chain OK" if ok else f"TAMPERED at {bad}")
    elif a.cmd == "stop": open("STOP", "w").write("stop"); print("kill switch engaged")

if __name__ == "__main__":
    main()
