---
name: bb-common
description: >
  Shared safety and utility layer for the bug-bounty ecosystem. Provides (1)
  fail-closed scope validation (safe_scope.py) — MUST be run before ANY outbound
  request, scan, or active action, and it refuses to proceed if scope is missing
  or ambiguous; (2) a dynamic tool/capability registry (capabilities.py) that
  detects which tools are actually installed instead of relying on hardcoded
  paths; and (3) shared helpers (bb_common.py) for retry-with-backoff, timeouts,
  disk caching, order-preserving dedup, controlled concurrency, structured
  output, and secret-redacting logging. USE THIS SKILL whenever you start any
  bug-bounty workflow, switch targets, need to know which tools are available,
  need to validate a target against authorized scope, or need to make a scan
  resilient (retries/timeouts/caching/dedup). This is the safety gate: if scope
  is missing, block and ask — never guess.
---

# bb-common — Shared Safety & Utility Layer

Everything in this skill is **passive** and **fail-closed**. The golden rule:

> **No outbound request, scan, or active action happens until `safe_scope.py`
> returns ALLOWED for an authorized scope file.**

## When to load this skill

- Before **any** recon/hunt/report workflow on a target.
- Whenever you need to know whether a tool is installed (capability detection).
- When scanning needs retries, timeouts, caching, or dedup.
- Whenever you switch targets — re-validate scope.

---

## 1. Scope validation — run FIRST, fail closed

`safe_scope.py` is the single enforcement point. It **never sends traffic**.

```bash
SS=/home/harsh/.config/opencode/skills/bb-common/scripts/safe_scope.py

# Validate a target against an authorized scope file
python3 "$SS" --target "https://api.example.com" --scope /path/to/scope.txt
# -> ALLOWED   (exit 0)
# -> BLOCKED   (exit 2) — out of scope / no scope / IP not permitted

# Also apply an exclusion file + block if a vuln class is excluded by the program
python3 "$SS" --target "sub.example.com" --scope scope.txt --exclude exclude.txt --vuln-class ssrf

# IP/CIDR targets require explicit --allow-ips AND the IP/CIDR in the scope file
python3 "$SS" --target "203.0.113.5" --scope scope.txt --allow-ips

# Machine-readable result for pipelines
python3 "$SS" --target "api.example.com" --scope scope.txt --json
```

**Fail-closed behavior (non-negotiable):**
- No `--scope` file → exit 3, refuse to proceed.
- Scope file exists but has **no** usable patterns → BLOCKED.
- Target not covered by any allow pattern → BLOCKED.
- IP/CIDR target without `--allow-ips` → BLOCKED.
- Target in the exclusion list → BLOCKED.
- `--vuln-class` is one the program excluded (a `excluded: <class>` line) → BLOCKED.

**Scope file format** (HackerOne-style, one pattern per line, `#` comments):
```
*.example.com
api.example.com
excluded: blog.example.com
excluded: dos
https://admin.example.com/*
```

## 2. Capability detection — what's actually installed

`capabilities.py` detects tools dynamically instead of skills hardcoding paths.
Critical: it resolves the **ProjectDiscovery httpx** (`~/go/bin/httpx`) over the
Python `httpx` that shadows it in `/usr/bin`.

```bash
CP=/home/harsh/.config/opencode/skills/bb-common/scripts/capabilities.py

# Full inventory summary (cached 1h)
python3 "$CP"

# Is a specific tool available + where?
python3 "$CP" --check httpx ffuf nuclei

# Force re-scan (a new tool was installed)
python3 "$CP" --refresh

# Fail if any required tool is missing (exit 1) — good CI gate
python3 "$CP" --require httpx ffuf nuclei   # space- or comma-separated

# JSON for downstream orchestration
python3 "$CP" --json
```

**Workflow rule:** before running a scan pipeline, run capabilities detection and
**skip** any tool that's missing (graceful fallback) rather than failing or
assuming it exists. When a required tool is missing, say so explicitly.

## 3. Shared utilities — resilience, caching, dedup, redaction

`bb_common.py` provides composable helpers. Use them in any custom script so you
don't reimplement retries/timeouts/caching:

```python
from bb_common import retry, Cache, Dedup, ThreadPool, run_cmd, redact, Logger

# Retry a flaky call with exponential backoff + jitter
result = retry(lambda: fetch_api(url), attempts=4, base_delay=1.0)

# Safe subprocess with timeout (kills on timeout, never blocks forever)
code, out, err = run_cmd(["ffuf", "-u", url, ...], timeout=60)

# Disk cache keyed by (target, query) — skip redundant work across runs
cache = Cache("/tmp/bb-cache", ttl=86400)
data = cache.cached_call(target, "probe", lambda: do_probe(target))

# Order-preserving dedup (pure-python anew)
for line in Dedup(key="text").filter(open("urls.txt")):
    ...

# Controlled concurrency
pool = ThreadPool(max_workers=8)
pool.submit(lambda: scan(host))

# Secret-redacting logger — tokens/keys never hit disk/logs
log = Logger("flow", level="info")
log.info("processing", token="sk-abc123...", url="https://api.example.com/x?key=...")  # values redacted
```

### CLI helpers
```bash
# Dedup a file preserving order
python3 bb_common.py dedup --input urls.txt --output unique.txt

# Redact secrets from a string (reports/logs)
python3 bb_common.py redact --text 'Authorization: Bearer eyJ...'
```

## 4. Safety policy

Read `/home/harsh/.config/opencode/skills/bb-common/references/safety-policy.md`
for the full authorization and safety rules. Summary:

- **Only** targets in an authorized scope file. Never arbitrary third-party targets.
- **Default passive/low-impact.** Active scanning, exploitation, or authenticated
  testing requires explicit human approval.
- **Approval gates** before: active scans, exploitation, authenticated testing,
  account actions, and anything affecting availability or data.
- **Never** bypass auth, CAPTCHAs, rate limits, access controls, or paywalls.
- **No** DoS, spam, social engineering, or modifying/destroying real user data.
- **Redact** secrets, tokens, cookies, API keys, PII from logs and reports.
