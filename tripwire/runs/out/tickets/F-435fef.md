# [Medium] Token valid after logout on POST /api/v3/auth/logout
**Severity:** Medium (4.4) — base 5.4 (logout_invalidation); low-criticality asset (-1.0)
**Owner:** identity-svc (#identity-eng)  **Status:** OPEN  **OWASP:** API2:2023 Broken Authentication  **CWE:** CWE-613


## Business impact
Account or session integrity is broken: an attacker can act as other users or keep access after logout.

## Proof (oracle: `jwt_accepted`)
Session token still accepted after successful logout

```bash
curl -s -X POST 'http://127.0.0.1:8100/api/v3/auth/logout' -H 'Authorization: Bearer $SESSION_TOKEN' -H 'Content-Type: application/json' -d '{}'
curl -s -X GET 'http://127.0.0.1:8100/api/v3/me' -H 'Authorization: Bearer $SESSION_TOKEN'
```
Evidence audit IDs: 997, 1001, 1003 — replay with `python -m tripwire replay <audit_id>`


## Suggested fix
Revoke tokens on logout (denylist by jti until expiry) or use short-lived access tokens with server-side refresh revocation.

## Retest
Automatic on next deploy of identity-svc
