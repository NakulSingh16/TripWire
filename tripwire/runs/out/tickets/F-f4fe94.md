# [High] SQL injection on GET /api/v3/hotels/search
**Severity:** High (7.6) — base 8.6 (sqli_error); low-criticality asset (-1.0)
**Owner:** booking-svc (#booking-eng)  **Status:** OPEN  **OWASP:** API8:2023 Security Misconfiguration  **CWE:** CWE-89


## Business impact
Attacker-controlled input reaches an interpreter in search; may lead to data theft or code execution.

## Proof (oracle: `injection_error`)
Param 'sort': quote causes DB error (500); comment-terminated payload is valid SQL (200) -> raw SQL concatenation

```bash
curl -s -X GET 'http://127.0.0.1:8100/api/v3/hotels/search?sort=price%27' -H 'Authorization: Bearer $A1_AGENT_TOKEN'
```
Evidence audit IDs: 965, 966, 968 — replay with `python -m tripwire replay <audit_id>`


## Suggested fix
Use parameterised queries; map sort fields through an allowlist (e.g. {'price','name'}) instead of concatenating.

## Retest
Automatic on next deploy of booking-svc
