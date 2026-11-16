# [High] Low role can grant admin role (BFLA) on POST /api/v3/agency/users
**Severity:** High (8.5) — base 8.0 (privilege_grant); asset criticality 1.3 (+0.5)
**Owner:** identity-svc (#identity-eng)  **Status:** OPEN  **OWASP:** API5:2023 BFLA  **CWE:** CWE-269


## Business impact
Any agency can read or act on another agency's user data, exposing PII/financial data across tenants.

## Proof (oracle: `privilege`)
a1_sub (role sub_agent) created user tw_49e33768 with role=agency_admin; admin read-back confirms

```bash
curl -s -X POST 'http://127.0.0.1:8100/api/v3/agency/users' -H 'Authorization: Bearer $A1_SUB_TOKEN' -H 'Content-Type: application/json' -d '{"username": "tw_49e33768", "role": "agency_admin", "password": "Tw#fe97bc5580"}'
```
Evidence audit IDs: 808, 813, 814 — replay with `python -m tripwire replay <audit_id>`


## Suggested fix
Enforce function-level authz (only agency_admin may create users) and forbid granting a role above the caller's own.

## Retest
Still reproducible at 20:18:13
