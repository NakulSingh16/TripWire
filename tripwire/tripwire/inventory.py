"""Inventory agent: classify gateway-log clients as legitimate vs automated, then label endpoints
active / zombie / shadow / dormant. `compare_classifiers()` benchmarks rules vs IsolationForest vs LogisticRegression."""
import re, datetime as dt, ipaddress, statistics, json
from collections import defaultdict
from .recon import parse_log, template

BOT_UA = re.compile(r"bot|crawl|spider|scan|nuclei|sqlmap|zgrab|masscan|nikto|nmap|health|probe|curl/|wget|go-http|httpx", re.I)
BROWSER_UA = re.compile(r"mozilla/5\.0", re.I)

def _ts(s):
    return dt.datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")

def client_features(rows):
    """rows: parsed log rows of ONE client (ip+ua). -> feature vector + names"""
    ts = sorted(_ts(r["ts"]).timestamp() for r in rows)
    gaps = [b - a for a, b in zip(ts, ts[1:])] or [0]
    n = len(rows); paths = {template(r["path"])[0] for r in rows}
    s4 = sum(r["status"] >= 400 for r in rows) / n; s404 = sum(r["status"] == 404 for r in rows) / n
    ua = rows[0]["ua"]; ip = rows[0]["ip"]
    try: private = ipaddress.ip_address(ip).is_private
    except ValueError: private = False
    days = len({_ts(r["ts"]).date() for r in rows})
    return {"n": n, "log_n": __import__("math").log1p(n), "path_div": len(paths) / n, "paths": len(paths), "r4xx": s4, "r404": s404,
            "bot_ua": float(bool(BOT_UA.search(ua))), "browser_ua": float(bool(BROWSER_UA.search(ua))), "private_ip": float(private),
            "gap_med": statistics.median(gaps), "gap_cv": (statistics.pstdev(gaps) / (statistics.mean(gaps) or 1)), "days": days,
            "burst": float(statistics.median(gaps) < 2.0 and n >= 5)}

FEATS = ["log_n", "path_div", "r4xx", "r404", "bot_ua", "browser_ua", "private_ip", "gap_med", "gap_cv", "days", "burst"]

def rule_legit(f):
    if f["bot_ua"]: return 0
    if f["r404"] > 0.3: return 0            # path guessing
    if f["burst"] and f["paths"] >= 5 and f["r4xx"] > 0.2: return 0
    return 1

def group_clients(rows):
    g = defaultdict(list)
    for r in rows:
        g[(r["ip"], r["ua"])].append(r)
    return g

def compare_classifiers(log_path, labels_path, out="eval/legit_traffic_results.json"):
    """Client-level labels = majority of line labels. Temporal split: train first half of days, test second half."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score
    rows = list(parse_log(log_path)); labs = [int(l.split(",")[1]) for l in open(labels_path).read().splitlines()[1:]]
    for r, l in zip(rows, labs): r["legit"] = l
    t_mid = _ts(rows[len(rows) // 2]["ts"])
    halves = {"train": [r for r in rows if _ts(r["ts"]) < t_mid], "test": [r for r in rows if _ts(r["ts"]) >= t_mid]}
    data = {}
    for h, rs in halves.items():
        g = group_clients(rs); X, y = [], []
        for k, cr in g.items():
            f = client_features(cr); X.append(f); y.append(round(sum(r["legit"] for r in cr) / len(cr)))
        data[h] = (X, np.array(y))
    def mat(X): return np.array([[x[k] for k in FEATS] for x in X])
    Xtr, ytr = data["train"]; Xte, yte = data["test"]
    preds = {"rules": np.array([rule_legit(f) for f in Xte])}
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(mat(Xtr))
    preds["isolation_forest"] = (iso.predict(mat(Xte)) == 1).astype(int)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced").fit(mat(Xtr), ytr)
    preds["logreg_supervised"] = lr.predict(mat(Xte))
    preds["hybrid_rules_then_iforest"] = np.array([0 if rule_legit(f) == 0 else int(p) for f, p in zip(Xte, preds["isolation_forest"])])
    res = {k: {"acc": round(accuracy_score(yte, p), 4), "f1_legit": round(f1_score(yte, p), 4), "precision_legit": round(precision_score(yte, p), 4),
               "recall_legit": round(recall_score(yte, p), 4)} for k, p in preds.items()}
    res["_n_test_clients"] = int(len(yte)); res["_legit_share"] = round(float(yte.mean()), 3)
    json.dump(res, open(out, "w"), indent=1)
    return res

# ---------------------------------------------------------------- endpoint traffic + labels
def _private(ip):
    try: return ipaddress.ip_address(ip).is_private
    except ValueError: return False

def traffic_by_endpoint(log_path, window_days, classifier=rule_legit):
    rows = list(parse_log(log_path))
    if not rows: return {}
    end = max(_ts(r["ts"]) for r in rows); start = end - dt.timedelta(days=window_days)
    legit_client = {k: classifier(client_features(cr)) for k, cr in group_clients(rows).items()}
    out = defaultdict(lambda: {"legit_window": 0, "total_window": 0, "legit_all": 0, "last_legit": None, "clients": set(), "infra_window": 0})
    for r in rows:
        k = f"{r['method']} {template(r['path'])[0]}"; t = _ts(r["ts"]); legit = legit_client[(r["ip"], r["ua"])]
        o = out[k]
        if t >= start:
            o["total_window"] += 1; o["legit_window"] += legit
            if not legit and _private(r["ip"]) and r["status"] < 400:
                o["infra_window"] += 1   # load-balancer / monitoring use from inside the network
        if legit:
            o["legit_all"] += 1; o["clients"].add(r["ua"][:40])
            if r["status"] < 400 and (o["last_legit"] is None or t > o["last_legit"]): o["last_legit"] = t
    return {k: {**v, "last_legit": v["last_legit"].isoformat() if v["last_legit"] else None, "clients": sorted(v["clients"])[:5]} for k, v in out.items()}

def label(e, traffic, siblings_active):
    """mapped = seen in current UI traffic (HAR) or current JS bundle."""
    mapped = bool({"har", "js"} & e["sources"])
    t = traffic.get(e["key"], {}); legit = t.get("legit_window", 0)
    responds = e.get("live", True)
    if not responds:
        return "retired"
    if not legit and t.get("infra_window", 0) > 0: return "infra"
    if mapped and legit: return "active"
    if not mapped and legit: return "shadow"
    if not mapped and not legit: return "zombie"
    if siblings_active: return "zombie"
    return "dormant"

def recommend(lbl, e, findings):
    vulns = [f for f in findings if f["endpoint"] == e["key"]]
    if lbl == "zombie":
        return "Decommission now" if (vulns or e.get("auth_required") is False) else "Restrict (allowlist/auth) and plan decommission"
    if lbl == "shadow":
        return "Document in gateway spec and apply current authz middleware" + (" — has open findings" if vulns else "")
    return ""

def zombie_shadow_report(kg, traffic, findings, owners):
    out = []
    for e in kg.eps.values():
        if e.get("label") in ("zombie", "shadow"):
            t = traffic.get(e["key"], {})
            sib = re.sub(r"/v\d+/", "/v*/", e["template"])
            out.append({"endpoint": e["key"], "label": e["label"], "host": e["host"], "sources": sorted(e["sources"]),
                        "last_legit_traffic_at": t.get("last_legit"), "legit_requests_window": t.get("legit_window", 0),
                        "legit_requests_total": t.get("legit_all", 0), "legit_clients": t.get("clients", []),
                        "reachable_without_auth": e.get("auth_required") is False,
                        "data_exposed": sorted({x for f in findings if f["endpoint"] == e["key"] for x in f.get("data", [])}),
                        "vulns": [f["id"] + " " + f["title"] for f in findings if f["endpoint"] == e["key"]],
                        "current_version_sibling": next((k for k, o in kg.eps.items() if o is not e and re.sub(r"/v\d+/", "/v*/", o["template"]) == sib
                                                         and o["method"] == e["method"] and o.get("label") == "active"), None),
                        "likely_owner": owners(e["template"])["team"], "recommendation": recommend(e["label"], e, findings)})
    return out
