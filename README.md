# TripWire — Agentic Real-Time DAST
> **VoyageHack 4.0 / TBO Security Hackathon (Track: Fraud Prevention & Security)**

Autonomous security agents that discover undocumented B2B travel APIs, inventory & label endpoints (*active* / *zombie* / *shadow*), plan targeted access-control and business-logic attacks, prove each vulnerability using rigorous oracles, and auto-generate actionable tickets. All outgoing requests are governed by a tamper-evident safety gate, and the testing loop re-evaluates automatically on every code deployment.

---

## 📁 Repository Structure

```
.
├── Fraud Prevention & Security.pdf    # Hackathon problem statement
├── HANDOFF.md                         # Detailed project handoff & technical deep dive
└── tripwire/                          # Main project codebase
    ├── config/                        # Configuration & test credentials
    ├── data/                          # Recorded HAR traffic & gateway logs
    ├── eval/                          # Evaluation harness & scored results
    ├── practice_target/               # Deliberately vulnerable practice target API
    ├── runs/                          # Output reports, tickets, knowledge graph
    ├── tests/                         # Safety-gate unit tests
    └── tripwire/                      # Core agentic engine
        ├── safety.py                  # Single egress safety gate & audit log
        ├── recon.py                   # Passive & active API recon & OpenAPI export
        ├── semantics.py               # Parameter semantic inference
        ├── attacks.py                 # Attack hypothesis planner & 20 techniques
        ├── inventory.py               # Zombie / shadow API classification
        ├── core.py                    # Orchestrator & ticket triage
        └── dashboard.py               # Real-time web dashboard & kill switch
```

---

## 🚀 Quick Start

All execution commands run from inside the `tripwire/` directory:

```bash
cd tripwire

# 1. Setup virtual environment and dependencies
uv venv -p 3.12 .venv
uv pip install -p .venv fastapi uvicorn httpx pyyaml pydantic scikit-learn numpy pyjwt pytest pytest-asyncio

# 2. Run safety gate unit tests (ensures 100% compliance with scope & rate limits)
.venv/Scripts/python -m pytest -q tests

# 3. Run the full evaluation harness against the practice target
.venv/Scripts/python eval/harness.py

# 4. Start the practice target server and TripWire with live dashboard
.venv/Scripts/python practice_target/sim.py serve &
.venv/Scripts/python practice_target/sim.py har data/har
.venv/Scripts/python practice_target/sim.py logs data/gateway.log
.venv/Scripts/python -m tripwire run --watch
```

Access the real-time web dashboard at **`http://127.0.0.1:8300`**.

For more comprehensive information, architecture explanations, and runbooks, please see:
- 📖 [HANDOFF.md](HANDOFF.md)
- 📖 [tripwire/README.md](tripwire/README.md)
- 📄 [Fraud Prevention & Security.pdf](Fraud%20Prevention%20&%20Security.pdf)
