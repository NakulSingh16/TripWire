# [High] Server-side template injection on GET /api/v3/vouchers/{id}
**Severity:** High (8.2) — base 8.8 (ssti_math); low-criticality asset (-1.0); sequential/enumerable IDs (+0.4)
**Owner:** booking-svc (#booking-eng)  **Status:** OPEN  **OWASP:** API8:2023 Security Misconfiguration  **CWE:** CWE-1336


## Business impact
Attacker-controlled input reaches an interpreter in voucher; may lead to data theft or code execution.

## Proof (oracle: `ssti_math`)
Param 'note': template expression {{1337*7}} evaluated to 9359

```bash
curl -s -X GET 'http://127.0.0.1:8100/api/v3/vouchers/{id}?note=%7B%7B1337%2A7%7D%7D' -H 'Authorization: Bearer $A1_AGENT_TOKEN'
```
Evidence audit IDs: 935 — replay with `python -m tripwire replay <audit_id>`


## Suggested fix
Never render user input as a template; pass it as data to a sandboxed template with autoescape.

## Retest
Automatic on next deploy of booking-svc
