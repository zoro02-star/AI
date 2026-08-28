---
name: hackerone-scope
description: Pull the latest live scope assets (URLs, wildcards, CIDR ranges, IPs) from HackerOne programs via the Hacker API using the user's personal API token, and produce them in a gf-compatible scope.csv plus per-type lists. Handles program discovery, per-program structured-scope enumeration, the QinetIQ-style CSV export format the user's gf patterns expect, and tracks "new" (previously unseen) assets for fresh attack surface. Use when the user asks to "get scope", "fetch scope", "collect new/update scope", "download program assets", "pull HackerOne wildcards/domains/cidr/ips", or wants a refreshed bug-bounty target list from HackerOne. 中文触发词：scope、资产、通配符、CIDR、IP、漏洞赏金目标、从HackerOne拉取范围
---

# HACKERONE SCOPE COLLECTOR

Pull the latest in-scope assets from HackerOne programs via the public Hacker API, write them to a gf-compatible `scope.csv`, and emit per-type lists (domains, wildcards, cidrs, ips). Optionally diff against a previous run to surface **new** assets.

## CREDENTIALS

The user's personal HackerOne API token is stored as plaintext. Resolve it like this:

```bash
# Token lives in /home/harsh/.temp.md on the line: "hackerone api key : <KEY>"
H1_TOKEN=$(grep -oP '(?<=hackerone api key : ).*' /home/harsh/.temp.md)
H1_USER=harsh0707
```

If `$H1_TOKEN` is empty, ask the user for it (or where it lives). Never hardcode it in the skill. Use it as HTTP Basic auth: user = API token identifier (the account username), password = the token value.

## API ENDPOINTS

- List programs (paginated, 25/page): `GET https://api.hackerone.com/v1/hackers/programs?page[size]=100`
  - Response: `data[]` each with `attributes.handle`, `attributes.state`, `attributes.offers_bounties`, `attributes.eligible_for_submission`-style fields.
- Scope per program: `GET https://api.hackerone.com/v1/hackers/programs/<handle>/structured_scopes`
  - `data[]` each with `attributes.asset_type`, `attributes.asset_identifier`, `attributes.eligible_for_submission`, `attributes.eligible_for_bounty`, `attributes.max_severity`, `created_at`, `updated_at`.

The token gives the hacker's **public** programs only. Private/invite-only programs the user is a member of are NOT returned by `/hackers/programs` — those need the web UI or a program-side token. Say this if the user expects private programs.

## WORKFLOW

1. **Resolve credentials** (above). Timeout every curl: `--max-time 30`.
2. **Fetch all programs** — loop pagination until `data` is empty.
3. **For each program**, fetch `structured_scopes` and normalize every scope row. Track which program each asset came from (the identifier alone is not unique across programs).
4. **Write outputs** into `~/hackerone-files/` with a timestamp.

## OUTPUT FORMAT (gf-compatible)

The user's gf patterns (`~/.gf/scope-*.json`) expect the **exact QinetIQ CSV layout** and **lowercase** `true`/`false`:

```
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
www.example.com,URL,,false,true,,,,critical,,2024-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z
*.example.com,WILDCARD,,true,true,,,,critical,,2024-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z
192.168.0.0/24,CIDR,,false,true,,,,critical,,2024-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z
10.0.0.5,IP_ADDRESS,,false,true,,,,critical,,2024-01-01T00:00:00.000Z,2024-01-01T00:00:00.000Z
```

**Critical:** booleans must be written as `true`/`false` (lowercase), NOT Python `True`/`False` — the gf patterns match the literal `,false,true,` token. `instruction` is an empty field. `system_tags` is empty.

### gf pattern fix (ALREADY APPLIED)

The `scope-*` gf patterns originally hardcoded `...,false,true,` in their lookahead — they only matched rows with `eligible_for_bounty=false AND eligible_for_submission=true`. Since most real HackerOne programs have `true,true` (bounty + submission eligible), the patterns were silently dropping the highest-value rows (e.g. 215 of 329 rows). **Fixed** by replacing `false,true` with `(?:false|true),true` in `scope-domains`, `scope-wildcards`, `scope-cidr`, `scope-ips`, `scope-inscope`. Backups in `~/.gf.bak/`.

If a fresh machine loses the fix, re-apply it: in `~/.gf/scope-{domains,wildcards,cidr,ips,inscope}.json` change the lookahead `false,true` → `(?:false|true),true`.

## Per-type extraction (do this instead of relying on gf counts)

```python
# in: rows = list of dicts (asset_type, asset_identifier, eligible_for_submission)
import re
def is_cidr(s): return bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+/\d+', s))
def is_ip(s):   return bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+', s))

wildcard, url, cidr, ip, domain, root = set(), set(), set(), set(), set(), set()
for r in rows:
    if r['eligible_for_submission'] != 'true':   # or != True depending on source
        continue
    s = r['asset_identifier']; t = r['asset_type']
    if t == 'WILDCARD': wildcard.add(s.lstrip('*.'))
    elif t == 'CIDR':   cidr.add(s)
    elif t == 'IP_ADDRESS': ip.add(s)
    elif t == 'URL':
        url.add(s)
        domain.add(s)
        # root domain = eTLD+1 heuristics; strip leading labels
```

For root domains you can also just run the user's gf: `cat scope.csv | gf scope-rootdomains` (that one works regardless of bounty flag). The per-type sets above are the reliable path.

## "NEW / LATEST" TRACKING

To surface newly-added assets (what the user usually wants), diff against a previous snapshot:

1. Keep an idempotent accumulator in `~/hackerone-files/`:
   - `scope_all_programs_LATEST.csv` — current full export (symlink/copy of the newest).
   - `seen_assets.txt` — sorted set of identifiers already known.
2. After fetching, compute `new = current_identifiers - seen_assets`.
3. Write `new_assets.csv` (in the gf layout) with only new rows, and print them to the user.
4. Update `seen_assets.txt` to the full current set.

Use `comm -23 <(sort current) <(sort seen)` for the diff. Timestamped snapshots are also kept: `scope_all_programs_<UTC>.csv`.

## Reference: `updated_at` = freshness signal

Sort or highlight assets by `updated_at` (descending) — newly added/changed assets are the best bug-bounty targets (features that were just shipped, freshly-exposed hosts). Print the top N by updated_at at the end of the run.

## Files written

- `~/hackerone-files/scope_all_programs_<TS>.csv` — full gf-compatible export.
- `~/hackerone-files/new_assets.csv` — assets not in the previous snapshot (if any).
- `~/hackerone-files/scope_wildcards.txt`, `scope_urls.txt`, `scope_cidrs.txt`, `scope_ips.txt`, `scope_domains.txt` — clean per-type lists.

Always end by reporting counts per type and the newest `updated_at` assets.
