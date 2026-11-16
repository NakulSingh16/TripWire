# TripWire — agentic real-time DAST (VoyageHack 4.0 / TBO Security Hackathon)

Agents that discover an undocumented B2B travel API, label it active / zombie / shadow, plan targeted access-control and business-logic attacks, prove each hit with an oracle, and ticket it. Every request goes through one safety gate. The loop re-runs on every deploy.

## Run
```bash
uv venv -p 3.12 .venv && uv pip install -p .venv fastapi uvicorn httpx pyyaml pydantic scikit-learn numpy pyjwt pytest pytest-asyncio
.venv/Scripts/python practice_target/sim.py serve &           # practice target on :8100 / :8101
.venv/Scripts/python practice_target/sim.py har data/har      # "provided" recorded traffic
.venv/Scripts/python practice_target/sim.py logs data/gateway.log
.venv/Scripts/python -m tripwire run --watch                  # bootstrap + dashboard http://127.0.0.1:8300 + deploy webhook + bundle watcher
.venv/Scripts/python practice_target/sim.py deploy --version 2 --fix 1   # simulated deploy -> TripWire reacts
.venv/Scripts/python eval/harness.py                          # full scored evaluation -> eval/results.json
.venv/Scripts/python -m pytest -q tests                       # safety-gate guarantees
.venv/Scripts/python -m tripwire verify-audit | replay <id> | stop
```
For the event, edit `config/tripwire.yaml` (scope, accounts, flows, owners). Passwords come from `TW_PW_<ALIAS>` env vars and never go in config.

## Results (practice target, see `eval/results.json`)
| Metric | Value |
|---|---|
| Bootstrap recall / precision (20 planted bugs) | **20/20**, **1.0** — 0 decoy hits |
| Live deploy (v2 adds a new endpoint with a bug, fixes bug 1) | new bug found **1.4–3.7 s** after the webhook; bug 1 closed by auto-retest |
| Safety | 1,117 requests, **0 out of scope**, max 9 requests in any 1 s (cap 8 rps), 3 DELETEs, all on our own objects, audit hash chain valid |
| Inventory | 3/3 planted zombie/shadow endpoints labelled correctly; 2 extra labels (`/openapi.json` zombie, `/partner/v1/bookings` shadow) fit the definitions but were not planted |
| Bootstrap time | ~130–150 s (the prober takes ~100 s) |
| Unit tests | 19 pass |

## Architecture (as built)
| Stage | Module | Notes |
|---|---|---|
| Safety gate (only egress) | `safety.py` | Kill switch; scope check (scheme/host:port, re-resolved IP in CIDR, path denylist); no auto-redirects; risk policy (L3+ needs approval, L4 never auto); DELETE only on ledger-owned IDs; logout only on throwaway sessions; vault-only credentials (raw auth headers rejected); token-bucket rate limit with AIMD; health monitor → pause; 2 MB response cap; SHA-256 hash-chained audit log |
| Recon | `recon.py` | HAR ingest with account attribution and response→path-ID dependency inference; JS route extraction (constant folding, template literals, query names); gateway-log candidates; prober (version/prefix mutation + wordlist) with soft-404 fingerprinting; OpenAPI 3.1 export with `x-tripwire-*` labels |
| Param semantics | `semantics.py` | Rules plus value validators (Luhn, URL), chosen by experiment |
| Inventory | `inventory.py` | Legit-vs-automated client classifier (rules, chosen by experiment); labels active / zombie / shadow / dormant / infra / retired; zombie-shadow report with every field the brief requires |
| Planner + executors + oracles | `attacks.py` | Rule matrix → 20 techniques. Oracles: canary leak, differential (with denial baseline), state change, price integrity, ledger, flow bypass, privilege read-back, JWT accepted (with bad-signature control), OOB callback, SQL error pair, SSTI math, redirect location |
| Verifier | `attacks.run_hypothesis` | Each probe re-runs on fresh state; a hit needs 2 of 3 positive replays; a failed positive control makes the result INCONCLUSIVE, never "fixed" |
| Triage / report / retest | `core.py` | Business-context severity with an explained score; dedup (symptoms merge into the root cause, distinct logic bugs stay separate); owner by longest prefix; Markdown tickets with minimal curl PoC; retest on every deploy |
| Change detection | `core.on_change`, `dashboard.py` | HMAC-able deploy webhook and bundle-hash watcher → JS diff → impact set boosted ×3 → plan only impacted endpoints → retest open findings |
| Dashboard | `dashboard.py` | Findings, inventory, approvals, timeline, blocked-request list, kill switch |

## Decision log (deviations from the plan, with evidence)
| Plan said | Built | Why (measured) |
|---|---|---|
| MiniLM-kNN param-semantics model | **Rules + value validators** | Leave-one-API-family-out CV and a held-out external set (TripVuln + crAPI params, 49 rows). External accuracy: rules **0.735**, TF-IDF+LR 0.571, hybrid 0.653, MiniLM-kNN 0.633, MiniLM-LR 0.612 (`eval/semantics_results_preregistered.json`). After fixing two rule bugs the errors exposed (`pass` matched "passport"; hyphenated header names), rules score 0.796. That number is no longer held-out, so the pre-fix figure is the honest comparison. Also: 159 seed rows can't train a generalising model. |
| IsolationForest + logistic legit-traffic model | **Rules** | Temporal split on 90 days of logs (1,694 test clients): rules 0.9988 accuracy, supervised LogReg 0.9994, IsolationForest 0.9185, hybrid 0.9185 (`eval/legit_traffic_results.json`). LogReg's 0.0006 gain needs labels that won't exist at the event. IsolationForest flags rare-but-legit clients (cron, partner) as anomalies. Caveat: the logs are synthetic and authored by us. |
| FP model (gradient boosting) | **Not built** | The rule-based verifier (controls + 2/3 replay + denial baseline) already scores precision 1.0 with zero decoy hits. A model trained on one target's attempts would have no negatives to learn from. Revisit if a real target produces FPs. |
| LLM planner / judge | **Not built** | No `ANTHROPIC_API_KEY` in the environment, so it could not be tested, and the user asked for nothing untested. The rule planner reaches 20/20 here. The plan's LLM role (extra business-logic hypotheses) remains the most valuable addition when a key exists. |
| YAML test DSL | **Python technique functions** | Business-logic oracles need arithmetic over responses (expected total, wallet delta). A DSL would need an expression language of equal size. Flows and canary recipes stay in YAML config. |
| tree-sitter JS parsing | **Regex + constant folding** | 26/26 bundle routes recovered, 0 spurious, on the practice bundle. Limitation: heavily minified or obfuscated bundles. |
| Playwright crawler | **Not built** | HAR + JS + logs + prober reached all 26 UI routes plus the 4 hidden ones. A crawler matters at the event if HAR coverage is thin. It is the first gap to close. |
| networkx KG, SQLAlchemy, React, SSE | dict KG, stdlib sqlite3 (WAL), single-page HTML polling every 2 s | Under 100 endpoints. Each removed dependency or build step had no measured benefit. |
| Token bucket with burst = rps | **Burst = 1** | Evaluation measured 15 requests in one second against an 8 rps cap. Now at most rps+1 (measured 9). |

## Limitations (honest)
- One practice target, written by us. Its bugs, decoys and logs share our assumptions. Recall on an unknown app will be lower. crAPI/VAmPI runs remain to do.
- Business-logic techniques rely on `business.flows` and `canary_flows` in config. Filling these is the first 45 minutes of event day (runbook §10), using the HAR.
- Cross-tenant tests use one attacker→victim direction.
