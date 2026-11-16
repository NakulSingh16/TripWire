"""TripVuln: deliberately vulnerable B2B travel API used as TripWire's practice target.

Bugs are numbered to match ground_truth.yaml. Bugs listed in env TRIPVULN_FIXED (comma list)
are fixed; TRIPVULN_VERSION selects features added by simulated deploys (deploy_sim.py).
LOCAL USE ONLY.
"""
import os, re, json, sqlite3, time, itertools, threading
import jwt, httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, PlainTextResponse

SECRET = "tripvuln-dev-secret-0123456789abcdef"
FIXED = set(filter(None, os.environ.get("TRIPVULN_FIXED", "").split(",")))
VERSION = int(os.environ.get("TRIPVULN_VERSION", "1"))
HERE = os.path.dirname(__file__)

def bug(n):  # bug n is live unless fixed
    return str(n) not in FIXED

lock = threading.Lock()
ids = itertools.count(1001)
nid = lambda: next(ids)

AGENCIES = {1: {"id": 1, "name": "Sunrise Travels", "bank": "HDFC-000111", "email": "ops@sunrise.test"},
            2: {"id": 2, "name": "Blue Ocean Trips", "bank": "ICICI-000222", "email": "ops@blueocean.test"}}
USERS = {
    "a1_admin": {"pw": "Pass#1", "agency": 1, "role": "agency_admin", "name": "A1 Admin", "credit_limit": 50000},
    "a1_agent": {"pw": "Pass#2", "agency": 1, "role": "agent", "name": "A1 Agent", "credit_limit": 20000},
    "a1_sub":   {"pw": "Pass#3", "agency": 1, "role": "sub_agent", "name": "A1 Sub", "credit_limit": 5000},
    "a2_admin": {"pw": "Pass#4", "agency": 2, "role": "agency_admin", "name": "A2 Admin", "credit_limit": 50000},
    "a2_agent": {"pw": "Pass#5", "agency": 2, "role": "agent", "name": "A2 Agent", "credit_limit": 20000},
}
WALLET = {1: 100000.0, 2: 100000.0}
REVOKED = set()
TRAVELLERS, QUOTES, BOOKINGS, PAYMENTS, INVOICES, REFUNDS, WEBHOOKS, STATEMENTS = ({} for _ in range(8))
COUPONS = {"WELCOME10": {"pct": 10, "single_use": True, "used_by": set()}}

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""create table hotels(id int, name text, city text, price real);
insert into hotels values (1,'Taj Palace','DEL',9000),(2,'Lemon Tree','DEL',4000),(3,'Oberoi','BOM',12000),(4,'Ibis','BOM',3500);""")

app = FastAPI(title="TripVuln")
partner = FastAPI(title="TripVuln Partner")

def auth(req: Request, allow_none_alg=False):
    h = req.headers.get("authorization", "")
    if not h.lower().startswith("bearer "):
        raise HTTPException(401, "missing token")
    tok = h[7:]
    try:
        if allow_none_alg and jwt.get_unverified_header(tok).get("alg", "").lower() == "none":
            claims = jwt.decode(tok, options={"verify_signature": False})  # BUG 11
        else:
            claims = jwt.decode(tok, SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "invalid token")
    if tok in REVOKED and not bug(12):
        raise HTTPException(401, "revoked")
    u = USERS.get(claims.get("sub"))
    if not u:
        raise HTTPException(401, "unknown user")
    return {"user": claims["sub"], **u, "token": tok}

def own(obj, me):
    if not obj or obj["agency"] != me["agency"]:
        raise HTTPException(404, "not found")
    return obj

def mask(p):
    return "XXXX" + p[-4:]

# ---------------- auth ----------------
@app.post("/api/v3/auth/login")
async def login(req: Request):
    b = await req.json()
    u = USERS.get(b.get("username"))
    if not u or u["pw"] != b.get("password"):
        raise HTTPException(401, "bad credentials")
    tok = jwt.encode({"sub": b["username"], "agency": u["agency"], "role": u["role"], "iat": int(time.time()), "jti": str(nid())}, SECRET, algorithm="HS256")
    return {"token": tok, "role": u["role"], "agency_id": u["agency"]}

@app.post("/api/v3/auth/logout")
async def logout(req: Request):
    me = auth(req); REVOKED.add(me["token"]); return {"ok": True}

@app.get("/api/v3/auth/callback")
async def callback(next: str = "/"):
    if bug(17) or next.startswith("/") and not next.startswith("//"):
        return RedirectResponse(next, 302)  # BUG 17 open redirect
    return RedirectResponse("/", 302)

# ---------------- profile ----------------
@app.get("/api/v3/me")
async def me_get(req: Request):
    me = auth(req)
    return {"username": me["user"], "name": me["name"], "role": me["role"], "agency_id": me["agency"], "credit_limit": me["credit_limit"]}

@app.patch("/api/v3/me")
async def me_patch(req: Request):
    me = auth(req); b = await req.json()
    allowed = {"name", "phone"} | ({"credit_limit", "role"} if bug(4) else set())  # BUG 4 mass assignment
    for k, v in b.items():
        if k in allowed:
            USERS[me["user"]][k] = v
    return await me_get(req)

# ---------------- agency ----------------
@app.get("/api/v3/agency/profile")
async def agency_profile(req: Request, x_agency_id: str | None = Header(None)):
    me = auth(req)
    aid = int(x_agency_id) if (x_agency_id and bug(5)) else me["agency"]  # BUG 5 tenant header
    a = AGENCIES.get(aid) or {}
    return {"agency_id": a.get("id"), "name": a.get("name"), "bank_account": a.get("bank"), "email": a.get("email")}

@app.put("/api/v3/agency/bank-account")
async def bank(req: Request):
    me = auth(req); b = await req.json()
    if me["role"] != "agency_admin":
        raise HTTPException(403, "forbidden")
    if not bug(13) and not b.get("current_password"):
        raise HTTPException(403, "step-up required")  # BUG 13 when missing
    AGENCIES[me["agency"]]["bank"] = b.get("bank_account", AGENCIES[me["agency"]]["bank"])
    return {"ok": True, "bank_account": AGENCIES[me["agency"]]["bank"]}

@app.put("/api/v3/agency/email")
async def agency_email(req: Request):  # decoy: step-up present
    me = auth(req); b = await req.json()
    if me["role"] != "agency_admin":
        raise HTTPException(403, "forbidden")
    if b.get("current_password") != me["pw"]:
        raise HTTPException(403, "step-up required")
    AGENCIES[me["agency"]]["email"] = b.get("email"); return {"ok": True}

@app.get("/api/v3/agency/users")
async def list_users(req: Request):
    me = auth(req)
    return [{"username": k, "role": v["role"]} for k, v in USERS.items() if v["agency"] == me["agency"]]

@app.post("/api/v3/agency/users")
async def add_user(req: Request):
    me = auth(req); b = await req.json()
    if me["role"] != "agency_admin" and not bug(3):  # BUG 3 BFLA
        raise HTTPException(403, "forbidden")
    name = str(b.get("username", ""))[:40]
    if not name or name in USERS:
        raise HTTPException(400, "bad username")
    USERS[name] = {"pw": b.get("password", "Tmp#Pass1"), "agency": me["agency"], "role": b.get("role", "agent"), "name": name, "credit_limit": 0}
    return JSONResponse({"username": name, "role": USERS[name]["role"]}, 201)

@app.delete("/api/v3/agency/users/{username}")
async def del_user(username: str, req: Request):
    me = auth(req)
    u = USERS.get(username)
    if me["role"] != "agency_admin" or not u or u["agency"] != me["agency"] or username in ("a1_admin", "a1_agent", "a1_sub", "a2_admin", "a2_agent"):
        raise HTTPException(403, "forbidden")
    del USERS[username]; return {"ok": True}

# ---------------- catalogue ----------------
@app.get("/api/v3/hotels/search")
async def search(city: str = "DEL", sort: str = "price"):
    q = f"select id,name,city,price from hotels where city=? order by {sort if bug(14) else ('price' if sort not in ('price','name') else sort)}"  # BUG 14
    try:
        rows = db.execute(q, (city,)).fetchall()
    except sqlite3.Error as e:
        return JSONResponse({"error": "database error", "detail": str(e)}, 500)
    return [{"id": r[0], "name": r[1], "city": r[2], "price": r[3]} for r in rows]

@app.get("/api/v3/hotels/{hid}")
async def hotel(hid: int):  # decoy: soft-404 style 200
    r = db.execute("select id,name,city,price from hotels where id=?", (hid,)).fetchone()
    return {"id": r[0], "name": r[1], "city": r[2], "price": r[3]} if r else {"error": "hotel not found"}

# ---------------- travellers ----------------
@app.post("/api/v3/travellers")
async def add_traveller(req: Request):
    me = auth(req); b = await req.json(); i = nid()
    TRAVELLERS[i] = {"id": i, "agency": me["agency"], "name": b.get("name"), "passport": b.get("passport", "P0000000"), "dob": b.get("dob")}
    return {"traveller_id": i}

@app.get("/api/v3/travellers/{tid}")
async def get_traveller(tid: int, req: Request):  # decoy: secure + masked
    me = auth(req); t = own(TRAVELLERS.get(tid), me)
    return {"id": t["id"], "name": t["name"], "passport": mask(t["passport"])}

@app.get("/api/v1/travellers/{tid}")
async def get_traveller_v1(tid: int, req: Request):
    me = auth(req); t = TRAVELLERS.get(tid)
    if not t:
        raise HTTPException(404, "not found")
    if not bug(2):
        own(t, me)
    return {"id": t["id"], "name": t["name"], "passport": t["passport"], "dob": t["dob"], "agency_id": t["agency"]}  # BUG 2

# ---------------- booking flow ----------------
@app.post("/api/v3/quotes")
async def quote(req: Request):
    me = auth(req); b = await req.json()
    r = db.execute("select price from hotels where id=?", (b.get("hotel_id"),)).fetchone()
    if not r:
        raise HTTPException(404, "hotel not found")
    nights, rooms = int(b.get("nights", 1)), int(b.get("rooms", 1))
    if rooms < 1 or rooms > 9:
        raise HTTPException(400, "invalid rooms")  # decoy: validated
    if not bug(7) and nights < 1:
        raise HTTPException(400, "invalid nights")  # BUG 7
    i = nid(); QUOTES[i] = {"id": i, "agency": me["agency"], "total": r[0] * nights * rooms, "hotel_id": b.get("hotel_id")}
    return {"quote_id": i, "total": QUOTES[i]["total"]}

@app.post("/api/v3/bookings")
async def book(req: Request):
    me = auth(req); b = await req.json()
    q = own(QUOTES.get(b.get("quote_id")), me)
    total = q["total"]
    if "total" in b and bug(6):
        total = float(b["total"])  # BUG 6 client total trusted
    c = b.get("coupon")
    if c:
        cp = COUPONS.get(c)
        if not cp:
            raise HTTPException(400, "bad coupon")
        if cp["single_use"] and me["agency"] in cp["used_by"] and not bug(8):
            raise HTTPException(400, "coupon already used")  # BUG 8 when missing
        cp["used_by"].add(me["agency"]); total = round(total * (100 - cp["pct"]) / 100, 2)
    i = nid(); inv = nid()
    BOOKINGS[i] = {"id": i, "agency": me["agency"], "quote_id": q["id"], "traveller_id": b.get("traveller_id"), "total": total,
                   "status": "PENDING_PAYMENT", "created_by": me["user"], "card": None, "invoice_id": inv}
    INVOICES[inv] = {"id": inv, "agency": me["agency"], "booking_id": i, "amount": total, "billing_email": AGENCIES[me["agency"]]["email"]}
    return {"booking_id": i, "status": "PENDING_PAYMENT", "total": total, "invoice_id": inv}

@app.get("/api/v3/bookings")
async def list_bookings(req: Request):
    me = auth(req)
    out = []
    for b in BOOKINGS.values():
        if b["agency"] == me["agency"]:
            d = {k: b[k] for k in ("id", "status", "total", "invoice_id", "traveller_id")}
            d["card_number"] = b["card"] if bug(18) else (mask(b["card"]) if b["card"] else None)  # BUG 18
            out.append(d)
    return out

@app.get("/api/v3/bookings/export")
async def export(req: Request):  # shadow: used by finance cron, not in UI/JS
    me = auth(req)
    rows = [b for b in BOOKINGS.values() if bug(20) or b["agency"] == me["agency"]]  # BUG 20
    return [{"id": b["id"], "agency_id": b["agency"], "total": b["total"], "status": b["status"]} for b in rows]

@app.get("/api/v3/bookings/{bid}")
async def get_booking(bid: int, req: Request):  # decoy: secure
    me = auth(req); b = own(BOOKINGS.get(bid), me)
    return {k: b[k] for k in ("id", "status", "total", "invoice_id", "traveller_id")}

@app.post("/api/v3/bookings/{bid}/pay")
async def pay(bid: int, req: Request):
    me = auth(req); b = own(BOOKINGS.get(bid), me); body = await req.json()
    if b["status"] != "PENDING_PAYMENT":
        raise HTTPException(409, "not payable")
    with lock:
        if body.get("method") == "wallet":
            WALLET[me["agency"]] -= b["total"]
        else:
            b["card"] = body.get("card_number", "4111111111111111")
        p = nid(); PAYMENTS[p] = {"id": p, "booking_id": bid, "amount": b["total"], "agency": me["agency"]}
        b["status"] = "PAID"
    return {"payment_id": p, "status": "PAID"}

@app.post("/api/v3/bookings/{bid}/confirm")
async def confirm(bid: int, req: Request):
    me = auth(req); b = own(BOOKINGS.get(bid), me); body = await req.json()
    p = PAYMENTS.get(body.get("payment_id"))
    if not p:
        raise HTTPException(402, "payment required")
    if not bug(10) and (p["booking_id"] != bid or b["status"] != "PAID"):
        raise HTTPException(402, "payment does not match booking")  # BUG 10
    b["status"] = "TICKETED"; return {"booking_id": bid, "status": "TICKETED"}

@app.post("/api/v3/bookings/{bid}/cancel")
async def cancel(bid: int, req: Request):
    me = auth(req); b = own(BOOKINGS.get(bid), me)
    b["was_paid"] = b["status"] in ("PAID", "TICKETED"); b["status"] = "CANCELLED"
    return {"booking_id": bid, "status": "CANCELLED"}

@app.post("/api/v3/refunds")
async def refund(req: Request):
    me = auth(req); body = await req.json(); b = own(BOOKINGS.get(body.get("booking_id")), me)
    if b["status"] != "CANCELLED" or not b.get("was_paid"):
        raise HTTPException(409, "not refundable")
    with lock:
        if b.get("refunded") and not bug(9):
            raise HTTPException(409, "already refunded")  # BUG 9 when missing
        b["refunded"] = True; WALLET[me["agency"]] += b["total"]
        r = nid(); REFUNDS[r] = {"id": r, "booking_id": b["id"], "amount": b["total"]}
    return {"refund_id": r, "amount": b["total"]}

@app.get("/api/v3/wallet")
async def wallet(req: Request):
    me = auth(req); return {"agency_id": me["agency"], "balance": WALLET[me["agency"]]}

@app.get("/api/v3/invoices/{iid}")
async def invoice(iid: int, req: Request):
    me = auth(req); inv = INVOICES.get(iid)
    if not inv:
        raise HTTPException(404, "not found")
    if not bug(1):
        own(inv, me)  # BUG 1 when missing
    return {"id": inv["id"], "booking_id": inv["booking_id"], "amount": inv["amount"], "billing_email": inv["billing_email"], "agency_id": inv["agency"]}

@app.get("/api/v3/vouchers/{bid}")
async def voucher(bid: int, req: Request, note: str = ""):
    me = auth(req); b = own(BOOKINGS.get(bid), me)
    if bug(15):  # BUG 15 SSTI: naive template engine evaluating {{ expr }}
        note = re.sub(r"\{\{(.{1,40}?)\}\}", lambda m: str(eval(m.group(1), {"__builtins__": {}}, {})), note)
    return PlainTextResponse(f"VOUCHER #{bid} status={b['status']} note={note}")

@app.post("/api/v3/supplier/webhooks")
async def webhook(req: Request):
    me = auth(req); body = await req.json(); url = str(body.get("url", ""))
    if me["role"] != "agency_admin":
        raise HTTPException(403, "forbidden")
    ok = None
    if bug(16) or url.startswith("https://hooks.tbo-partners.test/"):  # BUG 16 SSRF: server-side fetch of arbitrary URL
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                ok = (await c.get(url)).status_code
        except Exception:
            ok = "unreachable"
    i = nid(); WEBHOOKS[i] = {"id": i, "url": url, "agency": me["agency"]}
    return {"webhook_id": i, "verify_status": ok}

# ---------------- deploy v2: statements (BUG 21) ----------------
if VERSION >= 2:
    @app.get("/api/v3/agency/statements")
    async def statements(req: Request):
        me = auth(req)
        if not [s for s in STATEMENTS.values() if s["agency"] == me["agency"]]:
            i = nid(); STATEMENTS[i] = {"id": i, "agency": me["agency"], "balance": WALLET[me["agency"]], "bank": AGENCIES[me["agency"]]["bank"]}
        return [{"id": s["id"]} for s in STATEMENTS.values() if s["agency"] == me["agency"]]

    @app.get("/api/v3/agency/statements/{sid}")
    async def statement(sid: int, req: Request):
        me = auth(req); s = STATEMENTS.get(sid)
        if not s:
            raise HTTPException(404, "not found")
        if not bug(21):
            own(s, me)
        return {"id": s["id"], "agency_id": s["agency"], "balance": s["balance"], "bank_account": s["bank"]}

# ---------------- internal / zombie ----------------
@app.get("/internal/debug/config")
async def debug_config():
    if not bug(19):
        raise HTTPException(404, "not found")
    return {"jwt_secret": SECRET, "db": "sqlite://memory", "debug": True}  # BUG 19

@app.get("/health")
async def health():
    return {"ok": True}

# ---------------- SPA ----------------
@app.get("/", response_class=HTMLResponse)
async def index():
    return f'<html><head><title>TripVuln</title></head><body><div id="root"></div><script src="/static/app.v{VERSION}.js"></script></body></html>'

@app.get("/static/app.v{v}.js")
async def bundle(v: int):
    with open(os.path.join(HERE, "app.js")) as f:
        js = f.read()
    if VERSION >= 2:
        js += '\nexport const getStatements = () => api.get(API + "/agency/statements");\nexport const getStatement = (id) => api.get(API + "/agency/statements/" + id);\n'
    return PlainTextResponse(js, media_type="application/javascript")

# 404 for everything else is FastAPI default JSON {"detail":"Not Found"}

# ---------------- partner API (second host) ----------------
@partner.get("/partner/v1/bookings")
async def partner_bookings(req: Request):
    me = auth(req, allow_none_alg=bug(11))
    return [{"id": b["id"], "total": b["total"], "status": b["status"], "agency_id": b["agency"]} for b in BOOKINGS.values() if b["agency"] == me["agency"]]

@partner.get("/partner/v1/ping")
async def ping():
    return {"ok": True}
