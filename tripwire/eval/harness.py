"""End-to-end evaluation against TripVuln ground truth.
  python eval/harness.py [--no-deploy] [--seed N]
Fresh target -> record HAR -> TripWire bootstrap -> score -> live deploy (v2 adds bug 21, fixes bug 1) -> TTF + retest -> score.
L3 tests are auto-approved here to simulate the human reviewer (logged as approvals); L4 never."""
import asyncio, json, os, sys, time, subprocess, shutil, argparse, yaml
from urllib.parse import urlsplit
from collections import Counter
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); os.chdir(ROOT)
from tripwire.core import TripWire, load_cfg

PY = sys.executable; SIM = [PY, "practice_target/sim.py"]
GT = yaml.safe_load(open("practice_target/ground_truth.yaml"))

def sim(*a):
    return subprocess.run(SIM + list(a), capture_output=True, text=True, cwd=ROOT, stdin=subprocess.DEVNULL, timeout=120)

def score(findings, deploy_phase, fixed=()):
    bugs = [b for b in GT["bugs"] if b.get("deploy", 1) <= deploy_phase and b["id"] not in fixed]
    matched, extra = {}, []
    for f in findings:
        b = next((b for b in bugs if b["endpoint"] == f["endpoint"] and
                  (f["technique"] == b["technique"] if b.get("technique") else b["class"] == f["cls"])), None)
        if b: matched.setdefault(b["id"], f["id"])
        else: extra.append(f)
    decoy_hits = [f for f in findings if any(f["endpoint"] == d.split(" unauth")[0] and (not d.endswith(" unauth") or f["technique"] == "unauth_access")
                                             for d in GT["decoys"])]
    tp = len(set(matched)); fp = len(extra)
    return {"bugs_in_scope": len(bugs), "found": tp, "recall": round(tp / len(bugs), 3), "findings": len(findings),
            "precision": round(tp / max(1, tp + fp), 3), "false_positives": [f["title"] for f in extra],
            "decoy_hits": [f["title"] for f in decoy_hits], "missed": [f"{b['id']} {b['name']}" for b in bugs if b["id"] not in matched],
            "by_class": dict(Counter(b["class"] for b in bugs if b["id"] in matched))}

def safety(tw):
    q = tw.store.q
    sent = q("select url, ts, method from audit where decision='SENT'")
    hosts = set(tw.cfg["scope"]["hosts"])
    oos = [u for u, _, _ in sent if f"{urlsplit(u).hostname}:{urlsplit(u).port}" not in hosts]
    ts = sorted(t for _, t, _ in sent); j = 0; mx = 0
    for i, t in enumerate(ts):
        while ts[j] < t - 1.0: j += 1
        mx = max(mx, i - j + 1)
    deletes = [u for u, _, m in sent if m == "DELETE"]
    bad_del = [u for u in deletes if not tw.g.owned(u.rstrip("/").rsplit("/", 1)[-1])]
    ok, _ = tw.store and __import__("tripwire.safety", fromlist=["Audit"]).Audit(tw.store).verify()
    return {"requests_sent": len(sent), "blocked": q("select count(*) from audit where decision='BLOCKED'")[0][0],
            "block_reasons": dict(Counter(r[0].split(" [")[0][:60] for r in q("select reason from audit where decision='BLOCKED'"))),
            "out_of_scope_sent": len(oos), "max_requests_in_any_1s": mx, "deletes": len(deletes), "deletes_on_non_ledger": len(bad_del),
            "audit_chain_valid": ok}

def inventory_score(tw):
    lab = {k: e.get("label") for k, e in tw.kg.eps.items()}
    exp = {**{k: "zombie" for k in GT["inventory"]["zombie"]}, **{k: "shadow" for k in GT["inventory"]["shadow"]}}
    got = {k: v for k, v in lab.items() if v in ("zombie", "shadow")}
    return {"expected": exp, "labelled_zombie_or_shadow": got, "correct": sum(lab.get(k) == v for k, v in exp.items()), "of": len(exp),
            "extra": {k: v for k, v in got.items() if k not in exp}, "endpoints_in_kg": len(lab),
            "label_counts": dict(Counter(lab.values()))}

async def main(a):
    for p in ("runs/eval", "STOP"):
        shutil.rmtree(p, ignore_errors=True) if p != "STOP" else (os.path.exists(p) and os.remove(p))
    sim("stop")
    subprocess.Popen(SIM + ["serve"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(5)
    print(sim("har", "data/har").stdout.strip())
    if not os.path.exists("data/gateway.log"): print(sim("logs", "data/gateway.log").stdout.strip())
    cfg, secrets = load_cfg(); cfg["safety"]["approve_all"] = True
    tw = TripWire(cfg, secrets, db="runs/eval/tripwire.db", out="runs/eval/out")
    import uvicorn
    from tripwire.dashboard import build
    server = uvicorn.Server(uvicorn.Config(build(tw), host="127.0.0.1", port=8300, log_level="warning")); st = asyncio.create_task(server.serve())
    t0 = time.time(); await tw.bootstrap(); boot_s = time.time() - t0
    res = {"bootstrap_seconds": round(boot_s, 1), "phase1": score(tw.final_findings(), 1), "inventory": inventory_score(tw)}
    print(json.dumps(res["phase1"], indent=1))
    if not a.no_deploy:
        n_before = len(tw.timeline)
        proc = await asyncio.create_subprocess_exec(*SIM, "deploy", "--version", "2", "--fix", "1", cwd=ROOT,
                                                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
        for _ in range(240):  # wait for change handling to finish (retest logs come last)
            await asyncio.sleep(1)
            if any("RETEST" in t["msg"] for t in tw.timeline[n_before:]) and not any(
                    t["msg"].startswith("CHANGE") for t in tw.timeline[-1:]):
                await asyncio.sleep(3); break
        ff = tw.final_findings()
        new = [f for f in ff if f.get("ttf_s")]
        res["phase2"] = score([f for f in ff if f["status"] == "OPEN"], 2, fixed={1})
        res["deploy"] = {"new_findings_with_ttf": [(f["title"], f["ttf_s"]) for f in new],
                         "resolved_by_retest": [f["title"] for f in ff if f["status"] == "RESOLVED"]}
        print(json.dumps(res["deploy"], indent=1))
    res["safety"] = safety(tw)
    res["planner_stats"] = [t["msg"] for t in tw.timeline if t["msg"].startswith(("executed", "planner", "prober", "HAR", "JS"))]
    tw.write_reports()
    json.dump(res, open(a.out, "w"), indent=1, default=str)
    print(json.dumps({k: res[k] for k in ("safety", "inventory")}, indent=1, default=str))
    server.should_exit = True; await st; sim("stop")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--no-deploy", action="store_true"); ap.add_argument("--out", default="eval/results.json")
    asyncio.run(main(ap.parse_args()))
