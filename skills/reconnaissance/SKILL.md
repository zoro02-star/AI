---
name: reconnaissance
description: Full web2 reconnaissance pipeline — scope/ASN (asnmap, RDAP), scope-compliance gate (scope_checker.py), passive subdomain enum (subfinder, assetfinder, chaos), fast active enum (puredns/massdns, alterx), DNS resolution (dnsx), subdomain takeover (subzy, takeover_scanner.sh), port scanning (naabu then nmap), HTTP probing (httpx), crawling/URL+JS extraction (katana, jsluice, gau, waybackurls, urlfinder, gf), content/param discovery (ffuf, gobuster, dirsearch, optional kiterunner; params via param_discovery.sh in Phase 12), targeted nuclei only, profile-routed niche recon via the script arsenal (secrets_hunter, cloud_recon, cors, bypass_403, cicd_scanner, eol_check, intel_engine, param_discovery, scope_aggregator), notify on completion, and handoff to autopilot hunting via lead_board.py. Time-efficient, value-first: every phase writes to an organized data/ folder and adapts based on what was found. Use when starting recon on any web2 target, expanding attack surface, or when asked about subdomain enum, port scanning, URL harvesting, asset mapping, takeover, or scope checking.
---

# RECONNAISSANCE

Full web2 recon pipeline from scope to a ranked attack surface, then straight into autopilot hunting. **Built for speed — get the value, move on, adapt.**

## THE HUNTER'S LOOP (analyze → learn → adapt)

Every phase is a loop, not a batch job:

1. **Run** — fastest tool that gives the answer.
2. **Analyze** — read the output, don't just save it. Spot anomalies: a dev subdomain, an alt port running an admin panel, a `/graphql` route, an internal hostname in a cert.
3. **Learn** — each finding reshapes what to do next (see "Adapt" in every phase).
4. **Adapt** — chase the interesting signal, skip the dead surface. If a phase yields nothing interesting, move on within minutes.

## TIME RULES

- **Speed-first**: when a phase has a "fastest" choice, use it. No full scans where targeted scans answer.
- **5-minute kill signal**: if a target shows nothing after 5 minutes (static marketing pages, 403 everything, no APIs, no interesting ports), stop and move to the next target.
- **Never let recon exceed the value of the target.** A `$500`-bounty static site gets 10 minutes. A big API-heavy program gets the full pipeline.
- **Parallelize with `xargs -P` / background jobs** when a phase is naturally per-host.

## ENVIRONMENT FACTS (verified — do not guess paths)

Full inventory lives in `~/tools/claude-bug-bounty/ENVIRONMENT.md`. Non-negotiables:

```bash
TOOLS=~/tools/claude-bug-bounty/tools
HTTPX=~/go/bin/httpx        # bare `httpx` is Python's client (/usr/bin shadows ~/go/bin)!
PROXY=http://127.0.0.1:8081 # Caido ("procsy") proxy; UI/history at 127.0.0.1:8080. Use -k for TLS.
WL=~/tools/claude-bug-bounty/wordlists
```

- **Proxy-awareness:** route manual/fuzzing traffic through Caido when you want it in
  history (`curl -x $PROXY`, `ffuf -x $PROXY`, arjun `-oB`). NEVER proxy passive DNS /
  subdomain enum / naabu — noise only. If Caido isn't up (`ss -tlnp | grep 8080`), run tools direct; nothing here hard-depends on the proxy.
- **Wordlists:** no SecLists installed. Use `$WL/common.txt` (dirs), `$WL/api-endpoints.txt`,
  `$WL/params.txt`, `$WL/raft-medium-dirs.txt`, `~/massdns/lists/names.txt` (DNS brute),
  `~/massdns/lists/resolvers.txt` (resolvers), class payload dirs under `$WL/<Class>/`.
- **Resumable engine alternative:** `recon quick <target>` / `recon run` / `recon status`
  runs a 14-phase deterministic pipeline (this skill's logic, resumable). Use it when you
  want hands-off execution; use the phases below when you want judgment per step.

## QUICK MODE (`--quick`)

Approved by the operator — when `QUICK=1` is set, run this exact map. Do not improvise the cutoffs.

| Full (run normally) | Reduced (lighter variants) | Skipped (do not run) |
|---|---|---|
| 0 scope gate · 2 passive subs · 4 resolve · 5 takeover · 6 naabu only (never nmap) · 7 httpx · 13 handoff (lead_board + notify, no autopilot ask) | 3 active subs — puredns brute, `~/massdns/lists/names_small.txt`, NO alterx · 8 crawl — katana `-d 2`, skip waybackurls · 9 content — ffuf vhost only (`-mc 200,301,302,401,403 -ac`) | 1 ASN/RDAP · 10 targeted nuclei · 11 service enum · 12 niche scripts |

Target wall-clock: **~8-10 min**. If the target is dead after Phases 7-8, stop and say so — don't drag it out.

## SCOPE COMPLIANCE (MANDATORY — before any outbound request)

Never touch an asset outside program scope. **Fail closed.** Two independent
gates, both run before any outbound request:
1. **`safe_scope.py`** (bb-common) — the deterministic, **fail-closed** gate.
   If no authorized scope file exists, or it is empty/ambiguous, it **blocks and
   exits 3** — never guess an allowlist.
2. **`scope_checker.py`** (repo) — bulk file filtering.

```bash
TARGET="target.com"
BASE="$TARGET/data"
TOOLS=~/tools/claude-bug-bounty/tools
BB=/home/harsh/.config/opencode/skills/bb-common/scripts   # shared safety layer

# 1. Declare scope patterns ONCE (from the program page — read it fully first)
SCOPE="target.com,*.target.com"
EXCLUDE="blog.target.com,status.target.com"

# 2. Save to the data folder for every downstream phase
mkdir -p "$BASE/scope"
echo "$SCOPE" > "$BASE/scope/scope.txt"
echo "$EXCLUDE" > "$BASE/scope/exclude.txt"

# 3. Fail-closed per-target gate (blocks if no scope / empty / ambiguous)
python3 "$BB/safe_scope.py" --target "https://api.$TARGET" --scope "$BASE/scope/scope.txt" \
  --exclude "$BASE/scope/exclude.txt" || exit 2   # ABORT — target not clearly authorized

# 4. Verify a single asset (repo check)
python3 $TOOLS/scope_checker.py https://api.$TARGET -d "$SCOPE" -x "$EXCLUDE"

# 5. Filter a whole host/URL file (in-place) before pointing any scanner at it
filter_scope() {  # usage: filter_scope <file>
  python3 $TOOLS/scope_checker.py --input-file "$1" -d "$SCOPE" -x "$EXCLUDE" \
    || echo "[!] out-of-scope entries dropped from $1"
}
filter_scope "$BASE/subdomains/resolved.txt"
filter_scope "$BASE/urls/urls-master.txt"
```

> **Capability detection:** before running a phase, confirm tools are installed
> via `python3 $BB/capabilities.py --check <tool...>` and **skip** any missing
> tool gracefully (don't fail the pipeline / don't assume the path).

Rules:
- Every host file that feeds a scanner (naabu, nmap, ~/go/bin/httpx, katana, ffuf, gobuster/dirsearch, nuclei) is **scope-filtered first**.
- IP addresses/CIDRs are NOT supported by scope_checker.py — flag them to the user, never scan them blindly.
- If the program excludes a vuln class, keep `-x` in mind and check with `--vuln-class` before testing it.
- **Re-read the program scope whenever you switch targets.** Copy-paste is how programs get burned.

## DATA FOLDER (everything lands here)

```
<target>/
├── data/
│   ├── scope/         # scope.txt, asns.txt, cidrs.txt, whois.txt
│   ├── subdomains/    # passive.txt, active.txt, subs-master.txt, resolved.txt, cnames.txt
│   ├── takeover/      # subzy.txt, takeover_scanner output
│   ├── ports/         # naabu.txt, open-ports.txt, nmap-detail.txt
│   ├── http/          # probe.txt (httpx output), live.txt, waf.txt
│   ├── urls/          # crawl.txt, historical.txt, urls-master.txt, urls-clean.txt, js.txt,
│   │                  # interesting/ (gf + grep classified candidates)
│   ├── content/       # ferox/ kiterunner/ ffuf/ per-host results
│   ├── services/      # smb/ snmp/ ike/ webdav/ (only if ports found)
│   ├── vulns/         # nuclei/ (targeted scans ONLY)
│   └── niche/         # secrets/ cloud/ cors/ bypass403/ cicd/ eol/ params/ (script outputs)
└── notes.md           # running hunter analysis — what's interesting, next moves
```

```bash
TARGET="target.com"
BASE="$TARGET/data"
mkdir -p "$BASE"/{scope,subdomains,takeover,ports,http,urls/interesting,content,services,vulns,niche/{secrets,cloud,cors,bypass403,cicd,eol,params}}
touch $TARGET/notes.md
```

- Every command below writes to these paths. Never dump to `/tmp` and lose it.
- `notes.md` is the live analysis log: findings, hypotheses, next phase targets.
- `notify` fires when a long phase finishes (Discord is configured) — so you're not watching output.

---

## PHASE 1 — SCOPE & ASN (2 min)

> **--quick:** SKIP — scope is already confirmed in Phase 0. Proceed to Phase 2.

Only passive, read-only. Establish what you're actually allowed to hit, then encode it (see SCOPE COMPLIANCE above).

```bash
# RDAP — registrar, org, contacts (whois binary NOT installed; RDAP gives the same intel)
curl -s "https://rdap.org/domain/$TARGET" | jq -r '.entities[]?.vcardArray[1][]? | select(.[0]=="fn") | .[3]' | tee $TARGET/data/scope/whois.txt

# asnmap — map domain → ASN → all CIDR ranges owned by org
asnmap -d $TARGET | tee $TARGET/data/scope/asns.txt
asnmap -asn ASN12345 | tee $TARGET/data/scope/cidrs.txt

# dig — quick sanity on the apex + NS/MX
dig +short $TARGET | tee $TARGET/data/scope/apex-ip.txt
dig +short NS $TARGET | tee $TARGET/data/scope/ns.txt
```

**Analyze:** Which ASNs host the target? Any in-scope CIDRs beyond the web host (cloud ranges, legacy blocks)?
**Adapt:** If the program scope lists CIDRs (not just domains), save them to `$TARGET/data/scope/scope.txt` and flag them to the user — scope_checker.py doesn't handle IPs, so CIDR-targeted scanning needs explicit human go-ahead.

---

## PHASE 2 — PASSIVE SUBDOMAIN ENUM (2-4 min)

Fastest passive sources only. No aggressive queries.

```bash
TARGET="target.com"
BASE="$TARGET/data/subdomains"

# subfinder — multi-source passive
subfinder -d $TARGET -silent | anew "$BASE/passive.txt"

# assetfinder — second passive source
assetfinder --subs-only $TARGET | anew "$BASE/passive.txt"

# chaos — ProjectDiscovery dataset (API key already configured in ~/.config/chaos)
chaos -d $TARGET -silent | anew "$BASE/passive.txt"

# crt.sh — certificate transparency, free, no key
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew "$BASE/passive.txt"

echo "[+] Passive subs: $(wc -l < "$BASE/passive.txt")"
cp "$BASE/passive.txt" "$BASE/subs-master.txt"
```

**Analyze:** Interesting subdomains jump out already — `dev.`, `staging.`, `api.`, `admin.`, `internal.`, `test.`, `jira.`, `jenkins.`, `grafana.`, `gitlab.`.
**Adapt:** Note them in `notes.md`. These get prioritized in Phases 6-9.

---

## PHASE 3 — ACTIVE SUBDOMAIN ENUM (fastest: puredns/massdns) (3-5 min)

> **--quick:** REDUCE — puredns brute with `subdomains-top1million-5000.txt`, skip the alterx permutation step.

The fastest active method is **puredns** (wraps massdns for high-speed brute force), plus **alterx** to generate permutations of what you already found.

```bash
TARGET="target.com"
BASE="$TARGET/data/subdomains"
RESOLVERS=~/massdns/lists/resolvers.txt
DNS_WL=~/massdns/lists/names.txt   # ~150k names; use names_small.txt for quick mode

# 1. Permutations from known subs (fast, cheap)
cat "$BASE/subs-master.txt" | alterx -silent | anew "$BASE/permutations.txt"

# 2. Wordlist brute-force via puredns + massdns (fastest brute)
puredns bruteforce "$DNS_WL" $TARGET -r "$RESOLVERS" \
  -w "$BASE/brute.txt" 2>/dev/null

# 3. Resolve permutations + brute results and merge
puredns resolve "$BASE/permutations.txt" -r "$RESOLVERS" \
  -w "$BASE/brute-resolved.txt" 2>/dev/null
cat "$BASE/brute.txt" "$BASE/brute-resolved.txt" | anew "$BASE/subs-master.txt"

# (alt fast brute: shuffledns is faster to set up, less robust output parsing)
echo "[+] Master subs: $(wc -l < "$BASE/subs-master.txt")"
```

> No amass here. It's installed but slow and the value/effort ratio is bad for the sweep — reserve it for deep passive enum on one high-value target. subfinder + assetfinder + chaos + brute already cover it.

**Analyze:** New subs from brute are usually lower-value (wordlist names) but can reveal forgotten staging/dev hosts.
**Adapt:** Zone transfer check — 5 seconds, free win if it works:
```bash
for ns in $(dig +short NS $TARGET); do dig AXFR $TARGET @$ns 2>/dev/null | grep -q "IN.*A" && echo "[ZONE XFER] $ns" | tee -a $TARGET/notes.md; done
```

---

## PHASE 4 — DNS RESOLUTION & DEDUPE (fastest: dnsx + anew) (1 min)

```bash
BASE="$TARGET/data/subdomains"

dnsx -silent < "$BASE/subs-master.txt" | anew "$BASE/resolved.txt"
echo "[+] Resolved: $(wc -l < "$BASE/resolved.txt")"

# SCOPE GATE — the single enforcement point before any live scanning
python3 ~/tools/claude-bug-bounty/tools/scope_checker.py \
  --input-file "$BASE/resolved.txt" \
  -d "$(cat $TARGET/data/scope/scope.txt)" 2>/dev/null

# CNAMEs — feeds Phase 5 takeover and reveals dangling/misconfigured records
dnsx -silent -cname -resp-only < "$BASE/subs-master.txt" | anew "$BASE/cnames.txt"
```

**Adapt:** Dangling CNAMEs are takeover candidates → straight into Phase 5.

---

## PHASE 5 — SUBDOMAIN TAKEOVER (2 min, highest value-per-minute in recon)

Fastest check: `subzy` (installed). Dangling CNAME → unclaimed S3/GitHub/Heroku → instant Critical. Run against all resolved subs + CNAME list.

```bash
BASE="$TARGET/data"
TOOLS=~/tools/claude-bug-bounty/tools

# Scope-filter the input first
python3 $TOOLS/scope_checker.py --input-file "$BASE/subdomains/resolved.txt" \
  -d "$(cat $BASE/scope/scope.txt)" 2>/dev/null

# Fastest: subzy
subzy run --targets "$BASE/subdomains/resolved.txt" --hide_fails \
  | tee "$BASE/takeover/subzy.txt"
grep -i "vulnerable\|[!]" "$BASE/takeover/subzy.txt" \
  | tee -a $TARGET/notes.md

# Full fingerprint set via the existing wrapper (dnsReaper/subjack + curl fallback)
$TOOLS/takeover_scanner.sh "$BASE/subdomains/resolved.txt"
```

**Analyze:** Any `[TAKEOVER]`/`[!]` hit is a report-ready finding — verify the CNAME chain and service signature manually (can-i-take-over-xyz), then log to `notes.md`.
**Adapt:** Verified takeovers go straight to the hunting phase — they don't need more recon.

---

## PHASE 6 — PORT SCANNING (naabu fast, then nmap detail on interesting) (2-6 min)

> **--quick:** naabu only, NEVER nmap. Alt-port leads go to an httpx re-probe, not nmap.

**naabu first** — fast and parallel across all resolved hosts. **nmap only on ports that matter.**

```bash
BASE="$TARGET/data/ports"
SUBS="$TARGET/data/subdomains/resolved.txt"

# Fast full-range sweep across all resolved hosts (already scope-filtered)
naabu -l "$SUBS" -top-ports 1000 -silent -o "$BASE/naabu.txt"

# Or targeted: common + alt ports where admin/dev panels hide
naabu -l "$SUBS" -ports 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379,27017,5432,3306 -silent -o "$BASE/naabu.txt"
```

**Analyze:** Anything beyond 80/443 is a lead. `:9200` Elasticsearch, `:6379` Redis, `:8080/actuator` Spring Boot, `:3000` Node dev — these are the money ports.

**nmap only on interesting ports** (not everything — time-efficient):

```bash
# Pick the interesting ports from naabu output
cat "$BASE/naabu.txt" | awk -F: '$NF != "80" && $NF != "443"' > "$BASE/interesting.txt"

# Full service + script scan on those only
nmap -sC -sV -Pn --open \
  -iL "$BASE/interesting.txt" \
  -oN "$BASE/nmap-detail.txt" 2>/dev/null
```

**Adapt:** If only 80/443 everywhere, skip nmap entirely — httpx gives you the value faster. Save nmap for alt ports, unusual services, or when you need version numbers to plan a specific exploit.

---

## PHASE 7 — HTTP PROBING (fastest, most value: httpx) (1-2 min)

`httpx` returns the most per second: status, title, tech stack, server header, CDN, IP, TLS info. That single output drives prioritization.

```bash
BASE="$TARGET/data/http"
TOOLS=~/tools/claude-bug-bounty/tools
HTTPX=~/go/bin/httpx   # bare `httpx` is Python's client — PATH shadowing!

cat "$TARGET/data/subdomains/resolved.txt" \
  | $HTTPX -silent -status-code -title -tech-detect -web-server -ip -asn \
  | tee "$BASE/probe.txt"

# WAF fingerprint — quick, only on hosts that answer (already probed; no second httpx pass)
awk '{print $1}' "$BASE/probe.txt" | wafw00f -i - -o "$BASE/waf.txt" 2>/dev/null
```

**Analyze (this is where the hunt is won):**
- `200` with `title` → real apps. `403` → often still reachable via path fuzz (Phase 9).
- Tech stack in `-tech-detect` tells you which bug classes to hunt later.
- `cdn: cloudflare/akamai` vs direct IP → direct-IP hosts skip the WAF.
- Hosts on alt ports from Phase 6 → re-probe those with httpx too.

**Adapt:**
- Mark app hosts vs. static/CDN hosts in `notes.md`. Only app hosts get Phases 8-9.
- Flag auth surfaces: `/login`, `/oauth`, `/sso`, `/graphql`, `/api` from titles/URLs.

---

## PHASE 8 — CRAWL + URL + JS EXTRACTION (manage URLs properly) (3-6 min)

> **--quick:** REDUCE — katana `-d 2 -jc`, skip waybackurls (keep gau). Keep the high-value grep classes (`/api/`, admin, auth); skip the rest.

Collect from every source, then **dedupe, classify, and prioritize** — a raw URL dump is noise, a classified list is a hunting map.

```bash
BASE="$TARGET/data/urls"
PROBE="$TARGET/data/http/probe.txt"

# 1. Live crawl (only on app hosts — they're already confirmed live in probe.txt)
awk '{print $1}' "$PROBE" | grep -v cdn \
  | katana -d 3 -jc -kf all -silent | anew "$BASE/crawl.txt"

# 2. Historical URLs
echo "$TARGET" | gau --subs --threads 5 | anew "$BASE/historical.txt"   # primary
urlfinder -d $TARGET -m wayback,otx,urlscan | anew "$BASE/historical.txt"
# Deep option when the target is old/large: waymore (bigger archives + responses)
# waymore -i $TARGET -mode U -oU "$BASE/waymore-urls.txt" && cat "$BASE/waymore-urls.txt" | anew "$BASE/historical.txt"

# 3. JS file inventory (high-signal)
cat "$BASE"/crawl.txt "$BASE"/historical.txt | grep -E '\.js(\?|$)' | sort -u | anew "$BASE/js.txt"
```

### URL management (the proper way)

```bash
# Master URL list, deduped
cat "$BASE/crawl.txt" "$BASE/historical.txt" | anew "$BASE/urls-master.txt"

# Normalize/dedupe by removing known-noise extensions & tracking params
grep -vE '\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp)$' "$BASE/urls-master.txt" \
  > "$BASE/urls-clean.txt"

# SCOPE GATE: only forward in-scope URLs to fuzzing/hunting
python3 ~/tools/claude-bug-bounty/tools/scope_checker.py \
  --input-file "$BASE/urls-clean.txt" --output "$BASE/urls-inscope.txt" \
  -d "$(cat $TARGET/data/scope/scope.txt)" 2>/dev/null
```

### Classify (gf + grep — `gf` is installed)

```bash
cd "$BASE/interesting"
cat ../urls-inscope.txt | gf idor   | anew idor.txt
cat ../urls-inscope.txt | gf sqli   | anew sqli.txt
cat ../urls-inscope.txt | gf ssrf   | anew ssrf.txt
cat ../urls-inscope.txt | gf lfi    | anew lfi.txt
cat ../urls-inscope.txt | gf redirect | anew redirect.txt
cat ../urls-inscope.txt | gf rce    | anew rce.txt

# High-value endpoint classes by hand (they always pay)
grep -iE '/api/|/v[0-9]/|/graphql|/rest/|/gql' ../urls-inscope.txt | anew api-endpoints.txt
grep -iE '/admin|/internal|/debug|/console|/management|/staging' ../urls-inscope.txt | anew admin-paths.txt
grep -iE '/(oauth|login|auth|sso|saml|oidc|callback|token)' ../urls-inscope.txt | anew auth-paths.txt
grep -iE 'upload|file|attachment|image|avatar|import|export' ../urls-inscope.txt | anew uploads.txt

# URLs with parameters are the ones worth fuzzing later
grep -E '=' ../urls-inscope.txt | anew params.txt
```

### JS analysis (jsluice + linkfinder on the JS inventory)

```bash
# jsluice — fetch each JS URL and extract endpoints/secrets in one pass
cat "$BASE/js.txt" | jsluice urls | anew "$BASE/interesting/api-endpoints.txt"
cat "$BASE/js.txt" | jsluice secrets | jq -r '.data // empty' 2>/dev/null | anew "$BASE/interesting/js-secrets.txt"

# linkfinder — per-file endpoint discovery (works; jsbeautifier installed 2026-08-22)
head -30 "$BASE/js.txt" | while read js; do
  linkfinder -i "$js" -o cli 2>/dev/null
done | anew "$BASE/interesting/api-endpoints.txt"

# SecretFinder — deeper source scan with context (best on a handful of key files)
python3 ~/tools/SecretFinder/SecretFinder.py -i "$BASE/js.txt" -o cli 2>/dev/null \
  | anew "$BASE/interesting/js-secrets.txt"
```

**Analyze:** The classified lists ARE the hunting plan. API endpoints with IDs → IDOR targets. Params with `url=`/`path=` → SSRF/LFI. Auth endpoints → auth bypass.
**Adapt:** Endpoints found in JS that aren't in the URL list = fresh attack surface most hunters miss. Add them to Phase 9's ffuf targets. JS file list also feeds `secrets_hunter.sh` in Phase 12.

---

## PHASE 9 — CONTENT DISCOVERY (ffuf / gobuster / dirsearch) (5-10 min)

> **--quick:** run only the ffuf vhost discovery + backup-file fuzz. Param discovery (Phase 12) is also skipped in quick mode.

Three tools, three distinct jobs. Pick by context — don't run all three on everything. **Parameter discovery moved to Phase 12** (`param_discovery.sh`).

```bash
WL=~/tools/claude-bug-bounty/wordlists
PROXY=http://127.0.0.1:8081   # add -x $PROXY if you want hits in Caido history (UI at :8080)
```

### dirsearch / feroxbuster — recursive directory brute-force (default for app hosts)

```bash
BASE="$TARGET/data/content/dirsearch"; mkdir -p "$BASE"
for host in $(awk '{print $1}' "$TARGET/data/http/probe.txt" | grep -v cdn); do
  name=$(echo "$host" | tr '/:.' '___')
  # feroxbuster: recursive + auto-tune (preferred); dirsearch as alt
  feroxbuster -u "$host" -w "$WL/raft-medium-dirs.txt" -t 40 \
    -x php,json,txt,html --smart --auto-tune --quiet -o "$BASE/$name.txt" 2>/dev/null &
done; wait
echo "[+] content discovery done" | notify -silent
```

### ffuf — custom fuzzing + API endpoints (when you have a hypothesis)

```bash
BASE="$TARGET/data/content/ffuf"; mkdir -p "$BASE"

# VHost discovery (high-value when the app is behind a shared IP)
ffuf -u "http://$(dig +short $TARGET | head -1)" \
     -H "Host: FUZZ.$TARGET" \
     -w ~/massdns/lists/names_small.txt \
     -mc 200,301,302,401,403 -ac -t 40 -o "$BASE/vhost.json"

# Backup/temp files on a known endpoint (cheap, always pays)
ffuf -u "https://$TARGET/FUZZ" \
     -w <(printf '%s\n' .bak .old .orig .save .swp .txt '~' .1 .copy .inc .dist .sql) \
     -mc 200 -ac -t 20 -o "$BASE/backup.json"

# Endpoint fuzz on an API base you found in JS
ffuf -u "https://$TARGET/api/FUZZ" \
     -w "$WL/api-endpoints.txt" \
     -mc 200,201,204,301,302,403 -ac -t 40 -o "$BASE/api-fuzz.json"

# (alt: gobuster dir -u HOST -w "$WL/common.txt" -x php,json,txt — faster than dirsearch, non-recursive)
```

### kiterunner — API routes (optional, ONLY on api./gateway. hosts)

No `.kite` wordlists cached locally — fetch first, then scan narrowly:

```bash
kr kb download kiterunner/routes-small.kite   # once
kr scan "https://api.$TARGET" -w routes-small.kite --ignore-wordlist-comments
```

**Analyze:** Every 200/301 on a path you didn't know about is new surface. Backup files (`.bak`, `.swp`) return raw source. VHosts can reveal staging apps on the same IP.
**Adapt:** Feed newly discovered paths back into ffuf. Found a `.env` or `.git/`? That's source disclosure — pivot to mining it (see web2-recon skill's SOURCE DISCLOSURE section).

---

## PHASE 10 — VULNERABILITY SCANNING (targeted nuclei ONLY) (only when hunting something specific)

> **--quick:** SKIP — no nuclei at all, not even targeted.

**Default: skip.** No broad nuclei sweeps (slow, noisy, mostly false positives). **No nikto.**

Use nuclei **only** when you want to check a specific vulnerability against a specific subdomain:

```bash
# Example — you saw a WordPress subdomain during Phase 7:
nuclei -u https://wp.$TARGET -t ~/nuclei-templates -tags wordpress -severity high,critical \
  -o $TARGET/data/vulns/wordpress.txt

# Example — hunting a specific CVE on a specific host:
nuclei -u https://app.$TARGET -id CVE-2024-4577 -o $TARGET/data/vulns/cve.txt
```

Rules:
- Always specify `-u <single host>` + `-tags`/`-id` for the exact vuln class you're chasing.
- Scope-filter the host list first, always.
- Output only to `data/vulns/`. Validate every hit manually before logging in `notes.md`.
- The hunting phase (your real value) happens in the vulnerability classes you prioritize from Phase 7 tech stack — not in nuclei output.

---

## PHASE 11 — SERVICE-SPECIFIC ENUM (ONLY if port scan found something) (conditional, fastest)

> **--quick:** SKIP.

No output → skip. Something open → use the fastest tool that answers.
enum4linux/onesixtyone/ike-scan/davtest are NOT installed — nmap NSE + smbmap/impacket cover it.

```bash
BASE="$TARGET/data/services"
PORTS="$TARGET/data/ports/naabu.txt"
mkdir -p "$BASE"/{smb,snmp,webdav}

# SMB (139/445) — shares, users, null session (smbmap + impacket; enum4linux not installed)
grep -E ':139$|:445$' "$PORTS" | cut -d: -f1 | while read h; do
  smbmap -H "$h" -R 2>/dev/null | tee "$BASE/smb/$h-shares.txt"
  nmap -p445 --script smb-vuln*,smb-enum-shares,smb-os-discovery -T4 "$h" \
    2>/dev/null | tee "$BASE/smb/$h-nse.txt"
done

# SNMP (161) — nmap community sweep + system info
grep -E ':161$' "$PORTS" | cut -d: -f1 | while read h; do
  nmap -sU -p161 --script snmp-brute,snmp-info,snmp-sysdescr "$h" \
    2>/dev/null | tee "$BASE/snmp/$h.txt"
done

# VPN gateways (500/4500) — vendor fingerprint via service/version probe
grep -E ':500$|:4500$' "$PORTS" | cut -d: -f1 | while read h; do
  nmap -sU -p500,4500 -sV "$h" 2>/dev/null | tee "$BASE/ike/$h.txt"
done

# WebDAV — OPTIONS check + PUT test with curl (davtest not installed)
for h in $(grep -E ':80$|:443$' "$PORTS" | cut -d: -f1); do
  curl -sk -i -X OPTIONS "https://$h/" -m 8 2>/dev/null | grep -qi dav \
    && echo "[+] WebDAV enabled: $h" | tee "$BASE/webdav/$h.txt"
done

echo "[+] service enum done" | notify -silent
```

**Adapt:** A writable SMB share, an SNMP community with full system info, or a WebDAV with PUT → immediate pivots. Log findings with their service in `notes.md` and move to hunting.

---

## PHASE 12 — NICHE RECON (profile-routed script arsenal) (run only what the target justifies)

> **--quick:** SKIP — no niche scripts in fast mode.

`~/tools/claude-bug-bounty/tools/` is a full plugin arsenal. **Route by profile signal** — run the scripts the target's Phase 6-10 output justifies, never all of them. Gate optional toolchains with `external_arsenal.sh`'s `_have <tool>` where a binary may be missing.

```bash
BASE="$TARGET/data/niche"
TOOLS=~/tools/claude-bug-bounty/tools
mkdir -p "$BASE"/{secrets,cloud,cors,bypass403,cicd,eol,params,cve-intel}
PROBE="$TARGET/data/http/probe.txt"

# Compat mirror: secrets_hunter.sh --js-bundle reads $TARGET/urls/js_files.txt
mkdir -p $TARGET/urls
[ -f "$TARGET/data/urls/js.txt" ] && cp -f "$TARGET/data/urls/js.txt" "$TARGET/urls/js_files.txt"
```

### Routing table (signal → script → output)

| Profile signal (from Phases 6-10) | Run | Output |
|---|---|---|
| JS bundles in `data/urls/js.txt` | `$TOOLS/secrets_hunter.sh --js-bundle $TARGET` | `niche/secrets/` |
| Cloud/CDN in httpx (`cloudflare/aws/azure/gcp/amazon`) | `$TOOLS/cloud_recon.sh --keyword "$TARGET"` + `--cf-bypass "$TARGET"` | `niche/cloud/` |
| API hosts with CORS headers | `python3 $TOOLS/cors_scanner.py -l "$PROBE"` | `niche/cors/` |
| Any `403` in httpx probe | `$TOOLS/bypass_403.sh <host>` per 403 host | `niche/bypass403/` |
| GitHub org/repo visible anywhere in recon | `$TOOLS/cicd_scanner.sh <owner/repo>` | `niche/cicd/` |
| Tech stack from Phase 7 | `python3 $TOOLS/eol_check.py --tech "<stack pairs>"` + `python3 $TOOLS/intel_engine.py --target $TARGET --tech "<stack>"` + **`python3 ~/.config/opencode/skills/tech-cve-intel/scripts/tech_cve_intel.py --from-file "$PROBE" --min-severity high --output-dir "$TARGET/data/niche/cve-intel/"`** | `niche/eol.txt` + intel → `notes.md` + `niche/cve-intel/` |
| Params worth hidden-param probing | `$TOOLS/param_discovery.sh -l "$BASE/urls/interesting/params.txt"` (x8 installed: `x8 -u "URL?param=x" -w "$WL/params.txt"` per endpoint) | `niche/params/` |
| Multi-platform program / want full scope pulled | `$TOOLS/scope_aggregator.sh --program "$TARGET"` (feed new in-scope hosts back into Phase 3/7) | `scope/aggregated.txt` |
| Known company name → cloud bucket naming | `$TOOLS/cloud_recon.sh --keyword "$COMPANY"` (bulk verify with s3scanner: `~/go/bin/s3scanner -bucket-file names.txt`) | `niche/cloud/` |

```bash
# Example — single-shot profile-routed run:
grep -qi "cloudflare\|aws\|azure\|gcp\|amazon" "$PROBE" \
  && $TOOLS/cloud_recon.sh --keyword "$TARGET" --cf-bypass "$TARGET" 2>/dev/null
[ -s "$TARGET/data/urls/js.txt" ] \
  && $TOOLS/secrets_hunter.sh --js-bundle $TARGET 2>/dev/null
```

**Hunt-only scripts stay in the hunt phase** — `graphql_audit.sh`, `jwt_scanner.py`, `nosqli_scanner.py`, `crlf_scanner.py`, `waf_encoder.py`, `multipart_mutator.py`, `llm_redteam.py`, `h1_*`, `vuln_scanner.sh`, `hunt.py`, `zero_day_fuzzer.py`, `oob_listener.py`. Do NOT run them during recon; route them to the autopilot/hunt handoff in Phase 13.

**Analyze:** A verified secret in JS, a public S3 bucket, a CORS `Access-Control-Allow-Origin: *` with credentials, a bypassed 403 to an admin panel, an EOL stack with known CVEs, or a CI/CD workflow with injection surface — each is a finding or a chain starter.
**Adapt:** Log verified hits to `notes.md` with evidence. These feed the handoff.

---

## PHASE 13 — HANDOFF TO HUNTING (autopilot bug bounty)

> **--quick:** keep lead_board ingest/show + notify. Skip the autopilot launch question — just note it in the summary.

Recon is only valuable if it becomes a hunting plan. Never let it die in a folder.

### 1. Log every lead to the lead board (never lose one)

```bash
TOOLS=~/tools/claude-bug-bounty/tools

# Compat feed: lead_board.py globs these canonical names — mirror our layout
mkdir -p $TARGET/urls $TARGET/live
cp -f $TARGET/data/urls/urls-master.txt   $TARGET/urls/all.txt            2>/dev/null
cp -f $TARGET/data/urls/interesting/params.txt $TARGET/urls/with_params.txt 2>/dev/null
cp -f $TARGET/data/urls/interesting/api-endpoints.txt $TARGET/urls/api_endpoints.txt 2>/dev/null
cp -f $TARGET/data/urls/js.txt            $TARGET/urls/js_files.txt       2>/dev/null
cp -f $TARGET/data/http/probe.txt         $TARGET/live/httpx_full.txt     2>/dev/null

python3 $TOOLS/lead_board.py ingest $TARGET --recon-dir $TARGET 2>/dev/null
python3 $TOOLS/lead_board.py show $TARGET 2>/dev/null    # ranked, untouched leads first
```

Every lead gets routed to its hunt skill: `api-endpoints.txt` → hunt-idor, `params.txt` with `url=` → hunt-ssrf, `admin-paths.txt` → hunt-auth-bypass, `cnames.txt` dangling → hunt-takeover. The board persists them so hyperfocus on one doesn't lose the rest.

### 2. Notify — recon complete

```bash
cat <<EOF | notify -silent
[RECON COMPLETE] $TARGET
  subs:        $(wc -l < $TARGET/data/subdomains/subs-master.txt 2>/dev/null || echo 0)
  live:        $(wc -l < $TARGET/data/http/probe.txt 2>/dev/null || echo 0)
  urls:        $(wc -l < $TARGET/data/urls/urls-master.txt 2>/dev/null || echo 0)
  api:         $(wc -l < $TARGET/data/urls/interesting/api-endpoints.txt 2>/dev/null || echo 0)
  takeover:    $(grep -ciE '\[TAKEOVER\]|\[VULNERABLE\]|\[!\]' $TARGET/data/takeover/subzy.txt 2>/dev/null || echo 0)
  leads:       $(python3 $TOOLS/lead_board.py show $TARGET 2>/dev/null | grep -c 'new\|investigating' || echo 0)
EOF
```

### 3. Post-recon analysis (5 min — mandatory)

```bash
cat $TARGET/notes.md
echo "--- PRIORITY SURFACE ---"
wc -l $TARGET/data/{subdomains/subs-master.txt,http/probe.txt,urls/urls-clean.txt,urls/interesting/*.txt} 2>/dev/null
```

Rank what to hunt, in this order:
1. **Takeovers** (Phase 5 hits) — report-ready, verify then submit.
2. **Auth surfaces** (login/oauth/sso) → auth bypass, account takeover chains
3. **API endpoints with IDs** → IDOR (the highest-frequency bounty)
4. **Alt-port services + exposed admin/debug** → config disclosure → escalation
5. **Interesting params** (`url=`, `file=`, `id=`, `redirect=`) → SSRF/LFI/redirect
6. **Secrets/cloud/CORS** from Phase 12 → verify, then chain or report
7. **New paths from JS** not in the URL list → unpatched surface

### 4. Launch autopilot hunting

Hand the ranked surface to the autonomous hunt loop. Load scope into the autopilot session so its `scope_checker` gate uses the same allowlist:

```bash
# From opencode:
#   /autopilot target.com --normal
#   (--paranoid for new targets, --yolo only on familiar targets you've hunted before)
```

The autopilot agent runs the full cycle (scope → recon → rank → hunt → validate → report-draft) and stops at configured checkpoints for human approval. It will read the lead board, consume `$TARGET/data/`, and route each lead to the right vuln-class skill. Consume the hunting skills (`bb-methodology`, `web2-vuln-classes`) for the actual technique — this skill's job is the attack surface.

---

## SPEED CHECKLIST (run in order, stop when value runs out)

| Phase | Tool (fastest choice) | Time | Output path |
|---|---|---|---|
| 0 Scope | scope_checker.py gate | 1 min | `data/scope/scope.txt` |
| 1 ASN | asnmap, RDAP (curl), dig | 2 min | `data/scope/` |
| 2 Passive subs | subfinder, assetfinder, chaos, crt.sh | 3 min | `data/subdomains/passive.txt` |
| 3 Active subs | puredns/massdns + alterx | 4 min | `data/subdomains/subs-master.txt` |
| 4 Resolve | dnsx + anew | 1 min | `data/subdomains/resolved.txt` |
| 5 Takeover | subzy, takeover_scanner.sh | 2 min | `data/takeover/` |
| 6 Ports | naabu → nmap (interesting only) | 3 min | `data/ports/` |
| 7 HTTP probe | ~/go/bin/httpx | 2 min | `data/http/probe.txt` |
| 8 Crawl/URL/JS | katana, gau, urlfinder, waymore(opt), gf, jsluice, linkfinder | 5 min | `data/urls/` |
| 9 Content | dirsearch / ffuf / gobuster / kr(api, opt) — param discovery is Phase 12 | 8 min | `data/content/` |
| 10 Vuln | nuclei (targeted only) | as needed | `data/vulns/` |
| 11 Services | smbmap/impacket/nmap-NSE/curl-OPTIONS (conditional) | as needed | `data/services/` |
| 12 Niche | profile-routed arsenal (secrets_hunter/cloud_recon/cors/bypass_403/cicd_scanner/eol_check/intel_engine/param_discovery/scope_aggregator) | as needed | `data/niche/` |
| 13 Handoff | lead_board ingest → notify → autopilot | 3 min | lead board + notes.md |

**`--quick`**: rows 0,2,4,5,6,7,13 run normally; rows 3,8,9 reduced (see QUICK MODE above); rows 1,10,11,12 skipped. ~8-10 min total.
