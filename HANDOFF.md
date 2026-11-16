# TripWire — Project Handoff

Read this top to bottom once. By the end you will know what the project is, how every part works, what is finished, what is left, and exactly how to run it. No prior context needed.

Everything lives in the `tripwire/` subfolder. The five PDFs in this directory are the hackathon problem statements; we chose **`Fraud Prevention & Security.pdf`** (titled "Agentic Real-Time DAST"). Read that PDF once — this document assumes you have.

---

## 1. What we are building (in plain words)

The hackathon gives us a **live B2B travel booking website and API with no documentation**. Hidden inside it are deliberately planted security bugs. During the event the organisers will also **deploy changes** (new features, new endpoints) and watch whose tool catches the newly introduced bugs first.

**TripWire** is an autonomous tool that:

1. **Learns the API by itself** — from recorded traffic, the website's JavaScript, and server logs — because there is no API documentation.
2. **Labels every endpoint** as *active*, *zombie* (still alive but nobody uses it), or *shadow* (used but undocumented).
3. **Attacks each endpoint in a targeted way** — especially for business-logic bugs (e.g. "pay ₹1 for a ₹9000 booking", "refund the same booking twice") and access-control bugs (e.g. "agency A reads agency B's bookings").
4. **Proves each bug** with a concrete test so there are almost no false alarms.
5. **Writes a ready-to-file ticket** with severity, business impact, the owning team, a copy-paste proof, and a suggested fix.
6. **Reacts to deploys within seconds**, re-testing only what changed, and **auto-closes** a bug once it is fixed.
7. **Never breaks the rules of engagement** — one single safety "gate" in the code enforces scope, rate limits, no destructive actions, etc. Breaking a rule = instant disqualification, so this is the most important part.

### How the hackathon scores us (and our main lever for each)
| Criterion | Weight | How TripWire wins points |
|---|---|---|
| Valid findings & severity | 30% | 20 attack techniques + oracles that *prove* each bug |
| Precision (few false positives) | 20% | owner/denial controls + 2-of-3 replay before anything is reported |
| Safety & scope discipline | 20% | one safety gate, hash-chained audit log; **a breach disqualifies us** |
| Speed after a change | 10% | deploy webhook → test only changed endpoints → finding in seconds |
| Report quality | 10% | Markdown tickets: impact, owner, curl proof, fix, OWASP/CWE |
| Discovery & inventory | 10% | API map from traffic/JS/logs + zombie/shadow labels + OpenAPI export |

---

## 2. The core design idea (why it works)

Three principles drive every design choice. Keep them when you extend the code:

1. **"The LLM proposes, the code disposes."** No AI model ever sends an HTTP request. Deterministic Python does. (Right now there is no LLM at all — see §6.)
2. **Oracles, not guesses.** A bug is only reported if a concrete *oracle* proves it. Examples: our planted marker string leaked into another agency's response; a wallet balance went up twice for one refund; a forged token was accepted. This is why precision is ~100%.
3. **Canaries, not real data.** Before testing cross-tenant reads, we create our *own* marked objects (bookings, travellers) owned by a "victim" test account. If attacker account B can read them, B's response contains **our** marker — proof of a leak with zero real-customer data touched.

---

## 3. How the whole thing flows (the pipeline)

```
                    ┌─────────────────────────────────────────────────────────┐
  Recorded traffic  │                                                         │
  (HAR files)  ─────┤                                                         │
  Website JS   ─────┤  RECON  ─►  Knowledge Graph (every endpoint we found)   │
  Gateway logs ─────┤  (recon.py)        │                                    │
  Live probing ─────┘                    │                                    │
                                         ▼                                    │
                    INVENTORY (inventory.py): label active/zombie/shadow      │
                                         │                                    │
                                         ▼                                    │
                    PLANNER (attacks.py plan()): pick targeted tests per      │
                    endpoint based on its parameters & role                   │
                                         │                                    │
                                         ▼                                    │
                    EXECUTE each test ──► SAFETY GATE (safety.py) ──► target  │
                    (attacks.py)          every request passes through here   │
                                         │                                    │
                                         ▼                                    │
                    VERIFY: run 2–3 times, check owner control + denial       │
                    baseline, require an oracle to fire                       │
                                         │                                    │
                                         ▼                                    │
                    TRIAGE + REPORT (core.py): severity, owner, dedup,        │
                    Markdown ticket, OpenAPI export, zombie/shadow report     │
                                         │                                    │
   Deploy webhook ──► ON CHANGE (core.py): re-scan JS, test only changed      │
   or JS change        endpoints, retest open findings, auto-close fixed ones │
                                                                              │
   DASHBOARD (dashboard.py) shows all of this live + a KILL SWITCH ──────────┘
```

---

## 4. The files — what each one does

All paths are under `tripwire/`. Total ~1,900 lines of Python. Read them in this order.

### The engine (`tripwire/` package)

- **`safety.py`** — *the most important file.* Defines `SafeClient`, the **only** thing in the whole project allowed to make an HTTP request. Every request first passes, in order: kill-switch check → scope check (right scheme/host/port, the resolved IP is inside the allowed range, path not on a denylist) → risk policy (dangerous tests need approval; `DELETE` only on objects we created) → credential rules (tokens come only from the vault; logout only on throwaway sessions) → rate limiter (token buckets + "slow down when the server strains") → send (15 s timeout, response capped at 2 MB so we can't bulk-extract data) → health monitor → **append to a SHA-256 hash-chained audit log** (tamper-evident; every request replayable). Also holds the `Store` class (SQLite database wrapper) and the `Vault` (logs test accounts in, hands out tokens, locks an account after repeated failures).

- **`recon.py`** — learns the API. Parses HAR files (recorded browser traffic) and attributes each request to the account that made it; extracts API routes from the website's JavaScript (handles `const API="/api/v3"` + `fetch(API+"/x")` style code); reads gateway logs for endpoints; **probes** for hidden/legacy paths (`/v1/`, `/internal/`, `/debug/`, a 400-word list) and uses **soft-404 fingerprinting** so it doesn't invent fake endpoints; normalises paths (`/bookings/1042` → `/bookings/{id}`); builds the **Knowledge Graph** (a dict of every endpoint with its parameters, roles seen, response fields); exports **OpenAPI 3.1** with custom `x-tripwire-*` labels.

- **`semantics.py`** — decides what each parameter *means* (is `total` money? is `X-Agency-Id` a tenant id? is `passport` PII?). The planner uses these tags to choose attacks. Uses **rules + value validators** (e.g. Luhn check → card number). Also contains `compare()`, the experiment that proved rules beat ML here (see §7).

- **`attacks.py`** — the brain. Three parts:
  - `plan()` — the **rule matrix**: looks at each endpoint's method, parameters and semantics, and emits a prioritised list of hypotheses ("this endpoint takes a resource id → try cross-agency read").
  - **20 techniques** (functions marked `@technique`): `bola_read`, `collection_tenant_leak`, `tenant_header_switch`, `privilege_grant`, `mass_assignment`, `unauth_access`, `price_tamper`, `negative_quantity`, `coupon_reuse`, `double_refund`, `payment_reuse`, `jwt_alg_none`, `logout_invalidation`, `missing_step_up`, `sqli_error`, `ssti_math`, `ssrf_oob`, `open_redirect`, plus 2 passive scans (`secret_in_response`, `card_pan_in_response`).
  - `run_hypothesis()` — the **verifier**: runs a technique up to 3 times, needs 2 positive to confirm, checks the owner *can* do it (positive control) and that a random id is *denied* (negative baseline). If the positive control fails it returns **INCONCLUSIVE**, never "fixed".

- **`inventory.py`** — classifies each gateway-log client as a real user vs a bot/scanner (rules, chosen by experiment), then labels each endpoint **active / zombie / shadow / dormant / infra / retired**, and builds the zombie-shadow report (last legit traffic, reachable without auth, data exposed, likely owner, recommendation).

- **`core.py`** — the orchestrator `TripWire`. Runs `bootstrap()` (the full first pass), `on_change()` (deploy/JS-change handling), `retest()`, triage (severity scoring with explanation, owner resolution, dedup), and writes all reports (`runs/out/`). Contains the fix-suggestion text per bug class.

- **`dashboard.py`** — FastAPI web page at `http://127.0.0.1:8300`: live findings, API inventory, approval queue, timeline, blocked-request list, and a **KILL SWITCH** button. Also receives the deploy webhook at `/hooks/deploy`.

- **`__main__.py`** — the command-line interface (`python -m tripwire run|replay|verify-audit|stop`).

### The practice target (`practice_target/`) — our own vulnerable app

We get no access to the real staging app before the event, so we built a realistic one to develop and measure against.

- **`app.py`** — a deliberately vulnerable FastAPI travel API (agencies, bookings, payments, refunds, wallets, coupons, travellers with passports). Each bug can be toggled off via an env var, which is how we simulate "the organiser fixed it".
- **`app.js`** — the website's JavaScript bundle (so recon has something to read).
- **`ground_truth.yaml`** — the answer key: the 21 planted bugs, the expected zombie/shadow endpoints, and the **decoys** (things that look vulnerable but are not — used to measure false positives).
- **`sim.py`** — utility: `serve` (run the app), `har` (record normal user journeys → HAR), `logs` (generate 90 days of fake gateway logs with labels), `deploy` (swap to a new version and fire the webhook).

### Evaluation & tests

- **`eval/harness.py`** — the scorer. Starts a fresh target, records traffic, runs TripWire's bootstrap, scores recall/precision against `ground_truth.yaml`, fires a live deploy, measures time-to-finding and auto-retest, checks safety, and writes `eval/results.json`.
- **`eval/*.json`** — saved experiment results (keep these; they are evidence for the pitch).
- **`tests/test_safety.py`** — 19 unit tests that lock down every safety guarantee. **Run these after any change to `safety.py`.**

---

## 5. What is DONE (and proven)

Measured by `eval/harness.py` against our practice target. Numbers are in `eval/results.json`.

- ✅ **Safety gate** — all 19 unit tests pass. In a full run: **1,117 requests, 0 outside scope, max 9 requests in any 1 second** (cap is 8/s), 3 deletes all on our own objects, audit hash-chain valid.
- ✅ **Recon** — recovers all 26 UI routes + 4 hidden endpoints from HAR/JS/logs/probing.
- ✅ **Inventory** — all **3/3** planted zombie/shadow endpoints labelled correctly.
- ✅ **Attacks + verify** — **20/20 planted bugs found at bootstrap, precision 1.0, zero decoy hits.**
- ✅ **Change detection + speed** — after a simulated deploy that adds a new buggy endpoint, the finding appears **1.4–3.7 seconds** later; a bug we marked "fixed" is **auto-closed by retest**.
- ✅ **Reports** — Markdown tickets with severity + explanation, business impact, owner, curl proof, suggested fix, OWASP/CWE; plus OpenAPI 3.1 export and zombie/shadow JSON.
- ✅ **Dashboard** with kill switch, approvals, timeline, blocked list.
- ✅ **Two model-vs-rules experiments** done honestly (see §7) — we chose rules, with data to justify it.

**The big caveat:** *we wrote the practice target ourselves.* Its bugs, decoys and logs reflect our own assumptions. On the organisers' unknown app, recall **will be lower**. Closing that gap is the main remaining work.

---

## 6. What is NOT done yet (your work, roughly in priority order)

1. **Test against real public vulnerable apps — DO THIS FIRST.** Run TripWire against **OWASP crAPI**, **VAmPI**, and **OWASP Juice Shop** (all free, Docker). This is the only honest measure of whether our tool generalises beyond the app we wrote. Expect things to break; fix what breaks. This single task is worth more than any new feature.
2. **A real browser crawler (Playwright).** Right now recon relies on recorded traffic (HAR). If the organisers give thin recordings, we miss endpoints. A crawler that logs in as each role and clicks through the UI would fill gaps. This is the biggest coverage risk.
3. **LLM planner & judge (optional, needs an API key).** The plan was for Claude to (a) propose extra business-logic test ideas the rules miss, and (b) judge ambiguous findings ("is a sub-agent *supposed* to see parent bookings?"). Not built because this environment has **no `ANTHROPIC_API_KEY`**. The code has a clean slot for it (`core.py` triage + planner). Add a key, build it behind the existing interface, and keep the rule planner as the always-works fallback.
4. **More attack techniques / harden existing ones** against real-world quirks: login flows with CSRF tokens or OTP (our vault assumes a simple bearer-token login), GraphQL, pagination, rate-limit/lockout tests (keep these L4 = human-approval-only).
5. **Event-day config.** On the day, fill `config/tripwire.yaml` with the organisers' real scope, test accounts, business flows, and canary recipes. The business-logic tests depend on `business.flows` and `business.canary_flows` being correct for the real app — budget ~45 min at the start for this.
6. **Independent code review.** We tried to run an automated reviewer twice; both times Anthropic's cyber safeguards stopped it before it reported. Get a human teammate to review, or request access to Anthropic's Cyber Verification Program so reviewer agents aren't blocked.
7. **Minor polish:** the eval harness scoring was last tweaked and not re-run after that specific change (re-run it once to confirm); consider speeding up bootstrap (the prober takes ~100 of the ~140 s — it could run its probes more concurrently).

---

## 7. Why we used rules instead of ML (don't undo this without data)

The brief and our original plan leaned on ML. We **ran the experiments** and the data said rules win *for this problem*:

- **Parameter meaning:** tested on held-out parameter names from two *other* APIs. Rules scored **0.735** accuracy; the best ML model **0.653**; the originally-planned MiniLM-kNN **0.633**. Reason: only ~159 training examples exist — far too few for a model to generalise. (`eval/semantics_results_preregistered.json`)
- **Real-user vs bot traffic:** tested on 90 days of logs with a time-based split. Rules **0.9988**; a supervised model **0.9994** but it needs labelled traffic that **won't exist at the event**; IsolationForest only **0.9185**. (`eval/legit_traffic_results.json`)
- **False-positive model:** not needed — the verifier's controls already give precision 1.0, so there are no false positives for a model to learn from.

If you add ML later, justify it the same way: with a held-out measurement, not a hunch. **Caveat to keep in mind:** the traffic logs were generated by us, so the 0.99 traffic numbers are optimistic. The parameter-semantics external test is more trustworthy because those names came from real third-party APIs.

---

## 8. How to run everything

From inside the `tripwire/` folder. Windows; the virtual environment is already created at `.venv`.

```bash
# 1. (once) install dependencies if .venv is missing
uv venv -p 3.12 .venv
uv pip install -p .venv fastapi uvicorn httpx pyyaml pydantic scikit-learn numpy pyjwt pytest pytest-asyncio

# 2. run the safety unit tests — do this after ANY change to safety.py
.venv/Scripts/python -m pytest -q tests

# 3. the one command that proves everything works (starts target, scores, deploys, re-tests)
.venv/Scripts/python eval/harness.py          # writes eval/results.json, takes ~3 min

# 4. run it "for real" with the live dashboard
.venv/Scripts/python practice_target/sim.py serve &        # target on :8100 / :8101
.venv/Scripts/python practice_target/sim.py har  data/har  # record "provided" traffic
.venv/Scripts/python practice_target/sim.py logs data/gateway.log
.venv/Scripts/python -m tripwire run --watch               # bootstrap + dashboard http://127.0.0.1:8300
#   then, in another terminal, simulate a deploy and watch the dashboard react:
.venv/Scripts/python practice_target/sim.py deploy --version 2 --fix 1

# 5. safety / audit utilities
.venv/Scripts/python -m tripwire verify-audit   # confirm the audit log wasn't tampered with
.venv/Scripts/python -m tripwire replay <id>    # re-send an exact audited request
.venv/Scripts/python -m tripwire stop           # engage the kill switch (creates ./STOP)
```

**Tip:** if a port is stuck in use, run `python practice_target/sim.py stop` to kill leftover server processes, or `taskkill //F //IM python.exe` as a last resort.

Outputs land in `tripwire/runs/out/`: `findings.json`, Markdown tickets under `tickets/`, `openapi.json`, `zombie_shadow.json`, `kg.json` (the knowledge graph).

---

## 9. Ground rules for the teammate (please keep these)

- **Never let any code make an HTTP request except through `SafeClient.request` in `safety.py`.** That is what keeps us from being disqualified. If you add a tool (sqlmap, nuclei, a crawler), force its traffic through the gate.
- **Run `pytest -q tests` after touching `safety.py`.** All 19 must pass.
- **When you change an attack or oracle, re-run `eval/harness.py`** and check precision stays at 1.0 and no decoys are hit.
- **Prove decisions with numbers, not opinions.** If two approaches are possible, test both and keep the result file (that is what the `eval/*.json` files are).
- **Keep per-event settings in `config/tripwire.yaml`,** never hard-coded in the Python.

---

## 10. Quick glossary

- **DAST** — Dynamic Application Security Testing: testing a *running* app by sending it requests (vs reading source code).
- **BOLA / IDOR** — Broken Object Level Authorization: reading/changing an object (booking, invoice) that belongs to someone else by changing its id.
- **BFLA** — Broken Function Level Authorization: calling an admin-only action as a low-privilege user.
- **Mass assignment** — sending extra fields (e.g. `role=admin`, `credit_limit=99999`) that the server wrongly accepts.
- **SSRF** — Server-Side Request Forgery: making the server fetch a URL we control (via a webhook field).
- **SSTI** — Server-Side Template Injection: our input is rendered as a template, so `{{1337*7}}` comes back as `9359`.
- **Zombie endpoint** — still responds, but no real users call it (old version, debug route left in prod).
- **Shadow endpoint** — real clients use it, but it's not in the docs/UI/JS (e.g. a cron job's API).
- **Oracle** — a concrete check that *proves* a bug is real (marker leaked, balance doubled, forged token accepted).
- **Canary** — a marked object we create so a leak shows our own marker instead of real data.
- **HAR** — a file format holding recorded browser network traffic.

---

*Questions for the original author should reference the file and function name. Start with §8 step 3 — if `eval/harness.py` prints recall 20/20 and precision 1.0, your environment is working and you can begin on §6 item 1.*
