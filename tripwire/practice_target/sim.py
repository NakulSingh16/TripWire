"""TripVuln simulator: serve | har | logs | deploy.

  python sim.py serve [--version N] [--fix 1,2]   start main (8100) + partner (8101)
  python sim.py har  OUTDIR                        record per-role HAR files of normal journeys
  python sim.py logs OUT.log [--days 90]           90 days of nginx logs + OUT.labels.csv ground truth
  python sim.py deploy --version 2 [--fix 1]       restart target with new version, fire deploy webhook
"""
import sys, os, json, time, random, subprocess, argparse, datetime as dt
import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN, PARTNER = "http://127.0.0.1:8100", "http://127.0.0.1:8101"
PIDFILE = os.path.join(HERE, ".serve.pids")
ROLES = {"a1_admin": "Pass#1", "a1_agent": "Pass#2", "a1_sub": "Pass#3", "a2_admin": "Pass#4", "a2_agent": "Pass#5"}

def serve(version=1, fix="", wait=True):
    stop()
    env = dict(os.environ, TRIPVULN_VERSION=str(version), TRIPVULN_FIXED=fix)
    py = sys.executable
    procs = [subprocess.Popen([py, "-m", "uvicorn", f"app:{n}", "--port", str(p), "--log-level", "warning"], cwd=HERE, env=env)
             for n, p in (("app", 8100), ("partner", 8101))]
    open(PIDFILE, "w").write(",".join(str(p.pid) for p in procs))
    for _ in range(50):
        try:
            httpx.get(MAIN + "/health", timeout=1); httpx.get(PARTNER + "/partner/v1/ping", timeout=1); break
        except Exception:
            time.sleep(0.2)
    if wait:
        try:
            [p.wait() for p in procs]
        except KeyboardInterrupt:
            stop()

def stop():
    if os.path.exists(PIDFILE):
        for pid in open(PIDFILE).read().split(","):
            subprocess.run(["taskkill", "/F", "/T", "/PID", pid] if os.name == "nt" else ["kill", pid], capture_output=True)
        os.remove(PIDFILE)

# ---------------- HAR ----------------
def har(outdir):
    os.makedirs(outdir, exist_ok=True)
    for user, pw in ROLES.items():
        entries = []
        c = httpx.Client(base_url=MAIN, timeout=10)
        def call(method, path, body=None, token=None):
            h = {"Content-Type": "application/json"} | ({"Authorization": "Bearer " + token} if token else {})
            r = c.request(method, path, json=body, headers=h)
            entries.append({"startedDateTime": dt.datetime.now(dt.timezone.utc).isoformat(),
                "request": {"method": method, "url": MAIN + path, "headers": [{"name": k, "value": v} for k, v in h.items()],
                            "postData": {"mimeType": "application/json", "text": json.dumps(body)} if body is not None else None},
                "response": {"status": r.status_code, "headers": [{"name": k, "value": v} for k, v in r.headers.items()],
                             "content": {"mimeType": r.headers.get("content-type", ""), "text": r.text}}})
            return r
        call("GET", "/")
        t = call("POST", "/api/v3/auth/login", {"username": user, "password": pw}).json()["token"]
        call("GET", "/api/v3/me", token=t)
        call("GET", "/api/v3/hotels/search?city=DEL&sort=price", token=t)
        call("GET", "/api/v3/hotels/2", token=t)
        tid = call("POST", "/api/v3/travellers", {"name": "Test Traveller", "passport": "Z1234567", "dob": "1990-01-01"}, t).json()["traveller_id"]
        call("GET", f"/api/v3/travellers/{tid}", token=t)
        q = call("POST", "/api/v3/quotes", {"hotel_id": 2, "nights": 2, "rooms": 1}, t).json()
        b = call("POST", "/api/v3/bookings", {"quote_id": q["quote_id"], "traveller_id": tid}, t).json()
        call("GET", f"/api/v3/bookings/{b['booking_id']}", token=t)
        p = call("POST", f"/api/v3/bookings/{b['booking_id']}/pay", {"method": "card", "card_number": "4111111111111111"}, t).json()
        call("POST", f"/api/v3/bookings/{b['booking_id']}/confirm", {"payment_id": p["payment_id"]}, t)
        call("GET", "/api/v3/bookings", token=t)
        call("GET", f"/api/v3/invoices/{b['invoice_id']}", token=t)
        call("GET", f"/api/v3/vouchers/{b['booking_id']}?note=Late%20checkin", token=t)
        call("GET", "/api/v3/wallet", token=t)
        call("GET", "/api/v3/agency/profile", token=t)
        if user.endswith("admin"):
            call("GET", "/api/v3/agency/users", token=t)
            call("PUT", "/api/v3/agency/email", {"email": f"ops{user[1]}@agency.test", "current_password": pw}, t)
            call("POST", "/api/v3/supplier/webhooks", {"url": "https://hooks.tbo-partners.test/booking"}, t)
        if user == "a2_agent":  # cancel + refund journey
            q2 = call("POST", "/api/v3/quotes", {"hotel_id": 1, "nights": 1, "rooms": 1}, t).json()
            b2 = call("POST", "/api/v3/bookings", {"quote_id": q2["quote_id"], "traveller_id": tid, "coupon": "WELCOME10"}, t).json()
            call("POST", f"/api/v3/bookings/{b2['booking_id']}/pay", {"method": "wallet"}, t)
            call("POST", f"/api/v3/bookings/{b2['booking_id']}/cancel", None, t)
            call("POST", "/api/v3/refunds", {"booking_id": b2["booking_id"]}, t)
        call("POST", "/api/v3/auth/logout", {}, t)
        json.dump({"log": {"version": "1.2", "creator": {"name": "sim"}, "entries": entries}}, open(os.path.join(outdir, f"{user}.har"), "w"), indent=1)
    print("HAR written to", outdir)

# ---------------- gateway logs ----------------
UI_PATHS = ["GET /api/v3/me", "GET /api/v3/hotels/search?city=DEL&sort=price", "POST /api/v3/quotes", "POST /api/v3/bookings",
            "GET /api/v3/bookings", "GET /api/v3/bookings/{n}", "POST /api/v3/bookings/{n}/pay", "POST /api/v3/bookings/{n}/confirm",
            "GET /api/v3/invoices/{n}", "GET /api/v3/wallet", "GET /api/v3/agency/profile", "POST /api/v3/travellers",
            "GET /api/v3/travellers/{n}", "GET /api/v3/vouchers/{n}?note=x", "POST /api/v3/auth/login", "POST /api/v3/auth/logout",
            "GET /api/v3/hotels/{h}", "POST /api/v3/bookings/{n}/cancel", "POST /api/v3/refunds", "GET /api/v3/agency/users"]
SCAN_PATHS = ["GET /internal/debug/config", "GET /.git/HEAD", "GET /wp-login.php", "GET /api/v1/travellers/{n}", "GET /actuator/env",
              "GET /api/v3/admin", "GET /swagger.json", "GET /server-status", "GET /api/v2/bookings", "GET /phpinfo.php", "GET /.env"]
BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"]

def logs(out, days=90, seed=7):
    rnd = random.Random(seed)
    end = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc); start = end - dt.timedelta(days=days)
    rows = []  # (ts, ip, method, path, status, size, ua, legit, client_kind)
    def add(ts, ip, mp, status, ua, legit, kind):
        m, p = mp.split(" ", 1)
        p = p.replace("{n}", str(rnd.randint(1001, 1500))).replace("{h}", str(rnd.randint(1, 4)))
        rows.append((ts, ip, m, p, status, rnd.randint(80, 4000), ua, legit, kind))
    for d in range(days):
        day = start + dt.timedelta(days=d)
        # human sessions: diurnal (IST business hours ~ 03:30-13:30 UTC)
        for s in range(rnd.randint(25, 45)):
            ip = f"49.{rnd.randint(32,63)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}"; ua = rnd.choice(BROWSER)
            ts = day + dt.timedelta(hours=rnd.gauss(8.5, 2.5) % 24)
            for mp in ["POST /api/v3/auth/login"] + rnd.sample(UI_PATHS, rnd.randint(4, 12)):
                ts += dt.timedelta(seconds=rnd.expovariate(1 / 25))
                add(ts, ip, mp, rnd.choices([200, 201, 400, 404], [85, 8, 4, 3])[0], ua, 1, "human")
        # mobile app still calling v1 travellers until day 20 (then decommissioned build)
        if d < 20:
            for _ in range(rnd.randint(10, 30)):
                add(day + dt.timedelta(seconds=rnd.randint(0, 86399)), f"106.{rnd.randint(0,255)}.{rnd.randint(0,255)}.9",
                    "GET /api/v1/travellers/{n}", 200, "TripVulnApp/1.2 (Android 11)", 1, "mobile")
        # finance cron: legit, python UA, internal IP, nightly -> shadow export
        add(day + dt.timedelta(hours=2, seconds=rnd.randint(0, 30)), "10.20.0.15", "GET /api/v3/bookings/export", 200, "python-requests/2.31", 1, "cron")
        # partner integration: legit API client with non-browser UA
        for _ in range(rnd.randint(30, 60)):
            add(day + dt.timedelta(seconds=rnd.randint(0, 86399)), "52.66.10.20", "GET /partner/v1/bookings", 200, "okhttp/4.12 partner-sync", 1, "partner")
        # health checks (not legit usage)
        for h in range(0, 24 * 60, 10):
            add(day + dt.timedelta(minutes=h), "10.0.0.2", "GET /health", 200, "ELB-HealthChecker/2.0", 0, "health")
        # scanners: some with honest UA, some spoofing browsers (burst, high 404, many paths)
        for _ in range(rnd.randint(1, 3)):
            ip = f"185.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}"
            ua = rnd.choice(["Nuclei - Open-source project", "sqlmap/1.8", "zgrab/0.x"] + BROWSER)
            ts = day + dt.timedelta(seconds=rnd.randint(0, 86399))
            for mp in rnd.sample(SCAN_PATHS, rnd.randint(5, len(SCAN_PATHS))):
                ts += dt.timedelta(seconds=rnd.uniform(0.2, 1.5))
                st = 200 if mp.startswith(("GET /internal", "GET /api/v1")) else 404
                add(ts, ip, mp, st, ua, 0, "scanner")
    rows.sort(key=lambda r: r[0])
    with open(out, "w") as f, open(out.rsplit(".", 1)[0] + ".labels.csv", "w") as g:
        g.write("line,legit,kind\n")
        for i, (ts, ip, m, p, st, sz, ua, legit, kind) in enumerate(rows):
            f.write(f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{m} {p} HTTP/1.1" {st} {sz} "-" "{ua}"\n')
            g.write(f"{i},{legit},{kind}\n")
    print(f"{len(rows)} log lines -> {out}")

def deploy(version, fix, hook):
    t0 = time.time()
    serve(version, fix, wait=False)
    try:
        httpx.post(hook, json={"service": "booking-svc", "version": f"2.{version}.0", "commit": f"c0ffee{version}",
                               "release_notes": f"v{version}: agency statements" + (f"; fix bugs {fix}" if fix else ""), "ts": t0}, timeout=5)
    except Exception as e:
        print("webhook failed:", e)
    print(f"deployed v{version} fix={fix!r} at {t0:.0f}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("cmd"); ap.add_argument("arg", nargs="?")
    ap.add_argument("--version", type=int, default=1); ap.add_argument("--fix", default=""); ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--hook", default="http://127.0.0.1:8300/hooks/deploy")
    a = ap.parse_args()
    {"serve": lambda: serve(a.version, a.fix), "stop": stop, "har": lambda: har(a.arg or "data/har"),
     "logs": lambda: logs(a.arg or "data/gateway.log", a.days), "deploy": lambda: deploy(a.version, a.fix, a.hook)}[a.cmd]()
