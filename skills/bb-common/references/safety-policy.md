# Bug-Bounty Safety & Authorization Policy

Applies to every skill, agent, script, and workflow in this ecosystem. This is
non-negotiable and fail-closed: any action that cannot be proven authorized is
blocked.

---

## 1. Authorization (who/what we may touch)

1. **Only targets explicitly in an authorized scope file.** An "authorized scope"
   is a HackerOne/GitHub/Intigriti program scope export or a user-provided
   allowlist. This must be validated by `safe_scope.py` before any outbound request.
2. **No arbitrary third-party targets.** If a target is not in scope, do not
   touch it. This includes subdomains/hosts discovered en route that aren't
   confirmed in scope.
3. **Re-validate scope whenever you switch targets.** Copy-paste the program
   scope each time — guessing is how programs get burned.
4. **Fail closed when scope is missing or ambiguous.** If scope can't be loaded
   or the target isn't clearly covered, BLOCK and ask the human. Never guess.

## 2. Impact default (passive / low-impact)

1. Default to **passive or low-impact** techniques: reading, listing, probing
   endpoints with harmless requests, recon from public sources.
2. **Active scanning, exploitation, or authenticated testing requires explicit
   human approval** before starting.
3. Respect program rules. Some programs forbid automated tests in certain
   subdomains or vuln classes — honor `excluded:` directives in the scope file.

## 3. Required approval gates

Obtain explicit, informed human approval **before**:
- Active vulnerability scanning (nuclei, sqlmap, heavy fuzzing) — esp. anything
  beyond a light probe.
- Exploitation or proof-of-impact actions (creating accounts, changing data,
  sending requests that modify server state).
- Authenticated testing under a real user identity.
- Any account action (posting, messaging, changing settings, credentials).
- Any action that could affect availability (DoS-like, resource-exhausting) or
  destroy/modify data.
- Contacting or social-engineering any person.

In `--yolo` mode, only GET/HEAD/OPTIONS are auto-approved; PUT/DELETE/PATCH and
anything state-changing still require human approval.

## 4. Prohibited actions

- Bypassing authentication, CAPTCHAs, rate limits, access controls, or paywalls.
- Denial-of-service testing.
- Spamming users or mass messaging.
- Social engineering.
- Exploiting real user data, or modifying/destroying data.
- Harassment or phishing.

## 5. Requests & data handling

1. **Rate limit.** Default ~1 req/sec for vuln testing, ~10 req/sec for recon.
   Respect program-specific limits.
2. **Log everything** to an audit trail (URL, method, scope-check result, status)
   so actions are reproducible and reviewable.
3. **Redact secrets.** Cookies, bearer tokens, API keys, passwords, and PII are
   never written to logs, reports, memory files, or hunt-memory. Only a hash
   (e.g., 12-char session_id) is recorded.
4. **Never log raw auth values.** Keep credentials in process memory or a
   gitignored `.private/` store.

## 6. Responsible automation

1. Controlled concurrency and timeouts — never blast a target.
2. Caching + dedup to avoid duplicate/repeated requests.
3. Graceful degradation: if a tool is missing or a service is rate-limiting,
   back off and report, don't retry-forever.
4. Every workflow is resumable and checkpointed so work isn't lost.
