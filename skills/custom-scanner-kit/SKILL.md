---
name: custom-scanner-kit
description: >
  Build advanced, temporary, one-off Python scanners when a target needs a custom
  script that existing tools (nuclei/ffuf/sqlmap/dalfox etc.) can't express.
  Covers WHEN to write custom code vs use a tool, the elite async + httpx + rich
  stack, the core architecture (async engine, semaphore-bounded concurrency,
  adaptive rate limiting, baseline-anchored response diffing, OOB callbacks,
  retry/backoff), copy-paste patterns for every major bug class (IDOR/auth-bypass
  GraphQL/race/SSTI/CRLF/parameter fuzzing/secret hunting), and how to keep it
  scope-safe, secret-redacting, and reusable via bb-common. USE THIS when a target
  needs custom logic (enumeration that a tool can't match, multi-step authz logic,
  signature/anti-bot fields to reverse, cross-account IDOR, race conditions, or a
  hand-tuned probe), when existing tools are too noisy or produce false positives,
  when you need a bespoke payload/probe for a specific feature, or when you want to
  turn a manual finding into a fast scanner. NOT for generic recon/crawling where a
  mature tool already wins — use the reconnaissance/nuclei stack instead.
---

# custom-scanner-kit — Advanced Temporary Python Scanners

The art of bug bounty is knowing **when to reach for a script vs a tool**, and
when you do write one, making it fast, quiet, and correct. This skill encodes
both.

Golden rules:

1. **Use a tool unless you can name a concrete reason it fails.** `ffuf` for
   dir/param fuzzing, `nuclei` for template matching, `sqlmap` for SQLi,
   `katana`/`gau` for crawling, `httpx` for probing. Those beat hand-rolled
   versions 90% of the time.
2. **You write custom code when the *logic* is the bug,** not the scan volume:
   multi-step authorization chains, cross-account object access, race windows,
   signature-reversed API calls, bespoke probes for a unique feature, or a
   hand-tuned confidence check that kills false positives.
3. **A temporary scanner is production code you throw away — not throw-away
   code.** It needs timeouts, retries, rate limits, scope checks, secret
   redaction, and a deterministic output. That's what this kit provides.
4. **Every outbound request passes the scope gate** (bb-common `safe_scope.py`)
   and goes through the Caido proxy unless you have a reason not to.

---

## 1. DECIDE: tool or custom script?

Run this check before writing any code.

| If you need... | Use |
|---|---|
| Directory/parameter brute force | `ffuf` (wordlist-driven) |
| Known-CVE / template matching | `nuclei` |
| General crawling / URL harvest | `katana`, `gau`, `waybackurls` |
| Live host / tech probing | `httpx` |
| Classic SQLi at scale | `sqlmap` |
| Reflected XSS at scale | `dalfox` |
| **Multi-step authz logic (A→B, IDOR chains)** | **CUSTOM script** |
| **Cross-account object access (2 tokens, N objects)** | **CUSTOM script** |
| **Race conditions (parallel TOCTOU, limit overrun)** | **CUSTOM script** |
| **Signature/anti-bot field on requests you can't replay** | **CUSTOM script** (client-reverse) |
| **Bespoke probe for a unique feature/endpoint** | **CUSTOM script** |
| **High-noise low-signal endpoint, need strict diff** | **CUSTOM script** (baseline) |
| **Logic fuzzing beyond a static wordlist** (edge cases, enum) | **CUSTOM script** |

**Decision question to ask yourself:** "Will `ffuf`/`nuclei`/`sqlmap` give me a
correct answer here?" If yes — use them. If the answer depends on *response
comparison, authentication state, request sequencing, or target-specific logic*
— write a script.

---

## 2. The stack (what "elite hackers" actually use)

Verified against real production scanners (research 2026):

| Concern | Library | Why |
|---|---|---|
| Async HTTP | **`httpx`** | Native `asyncio`, HTTP/2, clean `.AsyncClient`, connection reuse. The modern default (over `requests`/`aiohttp` for new scanners). |
| Async runtime | **`asyncio`** | `.Semaphore` for bounded concurrency; `TaskGroup` (3.11+) over `gather` for sane error handling. |
| Terminal UI | **`rich`** | Live progress bars, tables, severity-coded panels. Zero-friction presentable output. |
| HTML/JSON parse | **`bs4` + `lxml`** | Form/param/link extraction, robust parsing. |
| Headless browser | **`playwright`** | Only when you must render JS/crawl authenticated SPAs; heavy, use sparingly. |
| Interception | **mitmproxy** (addon) / Caido | Capture live authenticated traffic to feed a scanner with real requests. |
| Retry | **`tenacity`** **or** hand-rolled backoff | transient 429/5xx/timeout. |
| Networking/DB/Crypto | `dnspython`, `cryptography`, `sqlite3` (stdlib) | niche needs. |

Python 3.11+ assumed (TaskGroup, zoneinfo, modern typing). **Do not install heavy
deps for a 10-line patch** — `httpx` + `rich` (+ `bs4`) cover almost everything.
Check availability with `bb-common/capabilities.py --check httpx rich bs4`.

---

## 3. Core architecture (the template)

A production custom scanner has these layers. Use `scripts/scanplate.py` to
scaffold it; read on for each piece.

```
[CLI args/config] -> [Scope gate] -> [Async crawling/fetch]
                                      -> [Analysis + baseline diff]
                                      -> [Dedup + rank]
                                      -> [JSON/rich report]  (secrets redacted)
```

### Async engine with bounded concurrency + rate limit

```python
import asyncio, httpx

class Scanner:
    def __init__(self, max_concurrent=20, rps=5):
        self.sem = asyncio.Semaphore(max_concurrent)   # cap in-flight
        self.min_interval = 1.0 / rps                   # min spacing
        self._last = 0.0

    async def _rate_limit(self):                        # adaptive pacing
        now = asyncio.get_event_loop().time()
        delay = self.min_interval - (now - self._last)
        if delay > 0:
            await asyncio.sleep(delay)
        self._last = asyncio.get_event_loop().time()

    async def fetch(self, client, url):
        async with self.sem:
            await self._rate_limit()
            r = await client.get(url)                    # retry/backoff wraps this
            return r
```

- **Semaphore, not unbounded spawn** — avoids connection-pool / memory blowup.
- **Rate limit by min-spacing**, not just a counter — the server's tolerance is
  a *rate*, and spacing-first never trips burst detection. Add jitter (±30%) and
  auto-pause if you see repeated 403/429 (back off, don't hammer — a ban kills
  the hunt).
- Reuse **one `httpx.AsyncClient`** (connection pooling) with a sane `timeout`.

### Retry with exponential backoff (transient only)

```python
import random
async def fetch_with_retry(client, url, attempts=3):
    for n in range(attempts):
        try:
            r = await client.get(url)
            if r.status_code == 429:
                await asyncio.sleep(max(int(r.headers.get("Retry-After", 5)), 5))
                continue
            r.raise_for_status()
            return r
        except (httpx.RequestError, httpx.HTTPStatusError, asyncio.TimeoutError):
            if n == attempts - 1:
                raise
            await asyncio.sleep(2 ** n + random.uniform(0, 1))
```

- Retry **only** on transient (429/5xx/timeout). Do NOT retry 403 (you're
  blocked) or 4xx logic errors (you're wrong).
- `bb_common.retry()` (sync) exists if you're not async.

### Work dispatch via asyncio.Queue (stream, don't explode memory)

```python
async def run(self, client, urls):
    results = {}
    async def worker():
        while True:
            try: url = q.get_nowait()
            except asyncio.QueueEmpty: return
            results[url] = await self.fetch_with_retry(client, url)
            q.task_done()
    q = asyncio.Queue()
    [q.put_nowait(u) for u in urls]
    await asyncio.gather(*(worker() for _ in range(self.sem._value)))
    return results
```

---

## 4. Baseline-anchored detection (kills false positives)

The single biggest quality lever. **Never** decide "vulnerable" from one response
in a vacuum — compare an injection against a **cached baseline** of the same
resource *without* the payload.

```python
# Capture the baseline response key ONCE per (method,path,params-schema)
BASELINE = {"status": 200, "len": 5123, "fp": structural_hash(body)}

def changed(r, baseline, allowed=()):
    if r.status_code in allowed:            # e.g. 401/403 may be "not vulnerable"
        return False
    same_len  = abs(len(r.content) - baseline["len"]) < 10
    same_fp   = structural_hash(r.text) == baseline["fp"]
    same_code = r.status_code == baseline["status"]
    return not (same_code and same_len and same_fp)
```

For boolean blind / reflected detection, compare the injected response vs the
baseline and require **both** a difference and a *semantic* match (e.g. injected
string echoed back, or timing delta above an adaptive threshold with MAD/IQR
outlier detection).

Confidence scoring: don't flag on a single signal. Require N independent
confirmations (status + length + structural + echoed-marker) before "confirmed".

---

## 5. The patterns library

`references/pattern-library.md` has copy-paste, battle-tested snippets for every
major class you'll write a custom scanner for:

- **IDOR / cross-account** — two-token A↔B object swap, field-level leakage, 30ID
  probe generator (adjacent/enum/special/random), multi-axis diff engine.
- **Auth bypass (BFLA)** — sibling endpoint sweep with a low-priv token,
  method-swap (GET↔POST↔PATCH), old-API-version probing.
- **GraphQL** — introspection disabled → field-guess; `node(id:)` IDOR; mutation
  authz check; batching-as-rate-limit-bypass.
- **Race conditions** — parallel toctou with `asyncio.gather`, limit-overrun
  (coupon/referral/double-spend), single-flight window.
- **Parameter / endpoint fuzzing** that `ffuf` can't tune (value-aware,
  auth-aware, response-aware).
- **Response signalling** — timing outlier detection (MAD/IQR/Tukey), error-regex
  per framework, WAF `block guard`.
- **OOB** — interactsh callback for blind SSRF/XSS/SQLi/RCE/SSTI.
- **Secret / credential hunting** in JS + API responses (AWS, GitHub PAT, JWT,
  Stripe, flags).

---

## 6. Safety rails (non-negotiable)

- **Scope gate — every target, every run.** Use `bb-common/safe_scope.py`. If it
  doesn't return ALLOWED (or scope is missing/ambiguous), **abort** — never guess.
- **Route through Caido proxy** (`-x http://127.0.0.1:8081`) unless you have a
  reason not to — evidence + safe traffic.
- **Secret redaction.** Any value that looks like a token/key/cookie/id, when
  logged or written, MUST go through `bb_common.redact()`. Never print tokens,
  sessions, or auth headers in full to logs or reports. Use `bb_common.Logger`.
- **Approval gate.** Active interruption / auth'd actions / writing data /
  disruptive requests: stop and get explicit human go-ahead. Default to passive
  reads.
- **Don't retry 403. Don't hammer. Auto-back-off on block.**
- **Cache + dedup** (`bb_common.Cache`/`Dedup`) so re-runs don't re-scan and
  duplicates never re-fire.
- **Time-box.** A custom scanner that "should" take 10 minutes and takes 2 hours
  is wrong — put a target cap / N-per-host cap in by default.

---

## 7. Workflow

1. Load `bb-common` (scope + capabilities + utils) — always.
2. Run the DECIDE check (§1). Confirm a tool won't do it.
3. Capture the real request if it's auth'd/signed (Caido/mitmproxy or
   `client-reverse`). Feed the scanner real tokens/headers/cookies via args/env.
4. Scaffold with `scripts/scanplate.py` (or open `references/pattern-library.md`).
5. Add the *logic* (authz chain, diff, race window, probe) — not the plumbing.
6. `safe_scope.py` the target; run through proxy; passive/low first.
7. Parse JSON output, validate with `triage-validation`, redact, report.
8. Time-box violated or no signal after N requests → stop and rotate.

---

## Files in this skill

- `scripts/scanplate.py` — scaffold generator (produces a ready-to-run async
  scanner with scope gate, rate limit, retry, baseline diff, JSON+rich output).
- `references/pattern-library.md` — copy-paste patterns per bug class.
