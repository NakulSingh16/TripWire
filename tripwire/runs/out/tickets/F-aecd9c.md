# [Medium] Open redirect on GET /api/v3/auth/callback
**Severity:** Medium (4.2) — base 4.7 (open_redirect); low-criticality asset (-1.0); no valid credentials needed (+0.5)
**Owner:** identity-svc (#identity-eng)  **Status:** OPEN  **OWASP:** API8:2023 Security Misconfiguration  **CWE:** CWE-601


## Business impact
Server can be steered to attacker-chosen destinations (callback); internal network/phishing exposure.

## Proof (oracle: `redirect_location`)
'next' redirects to arbitrary external host (https://tw-redirect.example/x)

```bash
curl -s -X GET 'http://127.0.0.1:8100/api/v3/auth/callback?next=https%3A%2F%2Ftw-redirect.example%2Fx'
```
Evidence audit IDs: 999 — replay with `python -m tripwire replay <audit_id>`


## Suggested fix
Only allow relative paths (single leading '/', not '//') or an allowlist of hosts for `next`.

## Retest
Automatic on next deploy of identity-svc
