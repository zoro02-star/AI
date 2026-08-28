# ENVIRONMENT — verified tool inventory (Arch Linux, zsh)

> Single source of truth for every bug-bounty skill/command. Every path and flag
> below was verified by running the binary (`-h`/`--version`) on this machine.
> Skills reference this file instead of re-guessing paths. Last audit: 2026-08-22.

## 1. PATH ORDER & SHADOWING (read this first)

```
$PATH = ~/.opencode/bin : ~/.local/bin : /usr/local/bin : /usr/bin : ... : ~/go/bin
```

**Collision warning:** `/usr/bin/httpx` is the *Python* httpx client and SHADOWS
ProjectDiscovery's httpx in `~/go/bin`. Same pattern: `gitleaks`, `trufflehog`
(`/usr/bin` versions win; both are functional secret scanners).

| Need | Use exactly |
|---|---|
| ProjectDiscovery **httpx** | `~/go/bin/httpx` (NOT bare `httpx`) |
| Python httpx (rarely wanted) | `/usr/bin/httpx` |
| gitleaks / trufflehog | bare name is fine |

## 2. PROXY — Caido (a.k.a. "procsy"), not Burp

- **Proxy endpoint: `http://127.0.0.1:8081`** (TLS-intercepting, verified working)
- **Caido UI / history / replay: `http://127.0.0.1:8080`** (open in browser)
- Launched as `caido-cli --proxy-listen 0.0.0.0:8081 --ui-listen 127.0.0.1:8080`
- TLS MITM is active — clients see Caido's self-signed CA. Use `-k/--insecure` with
  curl/ffuf, or install Caido's root CA for system trust.
- Plain-HTTP (non-CONNECT) requests may return 502 — test HTTPS targets primarily.
- No Burp Suite, no mitmproxy, no ZAP installed.

Route through proxy when interception/replay history matters:

```bash
curl -sk -x http://127.0.0.1:8081 ...      # manual requests
ffuf -x http://127.0.0.1:8081 ...          # fuzzing
arjun -oB http://127.0.0.1:8081            # explicit target port
```

- Do NOT proxy: passive recon (subfinder/chaos/crt.sh), DNS tools (dnsx/puredns),
  mass port scans (naabu) — they pollute the site map with noise and gain nothing.
- "Burp Repeater/extension" instructions in any doc translate to: Caido Replay in
  the UI at 127.0.0.1:8080, or plain `curl -x http://127.0.0.1:8081 -k`.

## 3. BROWSER AUTOMATION

- Firefox installed; no Chrome/Chromium. Playwright CLI exists but **no browsers
  downloaded** (`playwright install chromium` fixes if needed). `agent-browser`
  CLI is NOT installed (`npm i -g agent-browser && agent-browser install`).
- Headless rendering fallback that works today: `katana -headless` (bundled
  chrome not present either — so for JS-rendered pages use Firefox manually or
  install one of the above).

## 4. WORDLISTS & PAYLOADS (real paths)

| Path | Contents |
|---|---|
| `~/tools/claude-bug-bounty/wordlists/` | common.txt (4.7k dirs), params.txt == burp-parameter-names.txt (6.4k), api-endpoints.txt (298), dirs.txt, sensitive.txt, sensitive-files.txt, raft-medium-dirs.txt, rockyou.txt (14M) |
| `~/tools/claude-bug-bounty/wordlists/<Category>/` | Payload sets per class: XSS Injection/, SQL Injection/, NoSQL Injection/, Command Injection/, File Inclusion/, Directory Traversal/, SSTI/, XXE Injection/, Open Redirect/, LDAP Injection/, Insecure Management Interface/, Web Cache Deception/ |
| `~/tools/IntruderPayloads/` | FuzzLists/, BurpBountyPayloads/, BurpAttacks/, Uploads/ (upload-bypass payloads) |
| `~/nuclei-templates/helpers/wordlists/` | params.txt, headers.txt, numbers.txt + product-specific lists (wordpress-, grafana-, shiro keys...) |
| `~/massdns/lists/` | names.txt + names_small.txt (DNS brute), resolvers.txt |
| `/opt/metasploit/data/wordlists/` | assorted (passwords, unix_users, etc.) |
| arjun built-in db | `{arjun dir}/db/large.txt` used when `-w` omitted |

**No SecLists installed.** Any command citing `/usr/share/wordlists/seclists/...`
or `~/wordlists/...` is stale — substitute from the table above or
`git clone --depth 1 https://github.com/danielmiessler/SecLists ~/tools/SecLists`.

## 5. TASK → TOOL MAP (verified installed)

### Recon / surface
subfinder (+API keys configured), assetfinder, chaos (key configured), amass,
knockpy, sublert, puredns, massdns, shuffledns, dnsx, alterx, hakrevdns, tlsx,
asnmap, mapcidr, cdncheck, uncover, bbscope, dnsreaper, maigret, cewler,
naabu, nmap, masscan, smap, httprobe, meg

### HTTP probing / crawl / URLs
`~/go/bin/httpx` (-sc -title -td -server -ip -cdn -probe -irr), katana
(-d -jc -kf all -fx -hf), hakrawler, gospider, cariddi, gau, waybackurls,
waymore (-i T -mode U/B -fc/-ft filters), urlfinder, getJS, jsluice urls/strings,
LinkFinder (fixed: jsbeautifier installed 2026-08-22), SecretFinder (works),
xnLinkFinder, arjun (-w -m GET/POST/XML/JSON -oB), x8 (hidden params:
`x8 -u URL -w params.txt`), qsreplace, unfurl, anew,
gf (37 patterns in ~/.gf), kxss, airixss, dalfox, XSStrike, byp4xx, ffuf,
gobuster, dirsearch, fff, feroxbuster v2.13.1 (`-w WL --smart --auto-tune`),
kiterunner (`kr scan|brute`; needs a .kite list —
none cached locally, run `kr wordlist` to fetch remote before use),
gowitness v3, aquatone, wafw00f, whatwaf, unwaf, nikto, sqlmap, ghauri,
log4j-scan, crlfuzz, nuclei (-t ~/nuclei-templates), interactsh-client, notify,
bbot (heavy but full-featured), pywhat

### Cloud / CI-CD / WebSocket
aws-cli v2 (`~/.local/bin/aws`; `aws s3 ls s3://b --no-sign-request`),
s3scanner (`~/go/bin/s3scanner -bucket-file f.txt -provider aws|gcp|azure|digitalocean`),
sisakulint v0.3.6 (`scan .github/workflows/`, `--remote owner/repo`),
wscat + wsdump (WS testing; `-c URL -H header` / `-n -o ORIGIN URL`)

### Secrets / git / cloud
trufflehog (--only-verified), gitleaks, shhgit, noseyparker, git-hound,
GitDorker, GitTools (Dumper/Extractor), dvcs-ripper, ds_store_exp, apkleaks,
cloud_enum, cloudfail, scoutsuite, semgrep

### GraphQL / JWT / auth
graphql-cop, graphw00f, clairvoyance, gqlmap, jwt_tool, trevorspray,
kerbrute, impacket suite (~/.local/bin/*.py: secretsdump, smbclient, getTGT...),
smbmap, certipy, cupp

### Custom arsenal (all verified working)
`~/tools/claude-bug-bounty/tools/` — scope_checker.py, recon_engine.sh,
takeover_scanner.sh, cors_scanner.py, crlf_scanner.py, nosqli_scanner.py,
jwt_scanner.py, oob_listener.py, llm_redteam.py, param_discovery.sh,
secrets_hunter.sh, cloud_recon.sh, bypass_403.sh, cicd_scanner.sh, eol_check.py,
intel_engine.py, wordlist_engine.sh, breach_checker.py, osint_employees.sh,
spray_orchestrator.sh, token_scanner.py, hunt.py, lead_board.py, mindmap.py,
validate.py + more (~50 scripts)
Orchestrators: `recon` (=reconauto; run|quick|status|report|phases — resumable),
`submon` (~/submon/submon.py subdomain monitoring), `hunt.py`

## 6. MISSING TOOLS (referenced somewhere but NOT installed)

Install only what a live target justifies:

| Missing | Broke which workflow | Working substitute today | Install |
|---|---|---|---|
| SecLists | generic wordlist paths | local curated lists above | `git clone --depth 1 github.com/danielmiessler/SecLists ~/tools/SecLists` |
| uro | URL dedupe | `anew` / `sort -u` | `go install github.com/s0md3v/uro@latest` |
| theHarvester, username-anarchy, CrossLinked, pydictor | employee OSINT stage | CT-log subs via crt.sh/tlsx; skip names stage | pipx installs |
| hashcat (+rules) | wordlist mutation stage | cewler raw output only | pacman -S hashcat |
| apktool, jadx, adb, frida, java, mitmproxy | mobile runtime testing | apkleaks static + unzip/strings on classes.dex | AUR/jabba |
| Burp/multizap/Param Miner/smuggler | extension-based checks | Caido + manual techniques | n/a |
| forge/cast/solc/slither/mythril | on-chain toolchains | token_scanner.py static heuristics | foundryup etc. |
| enum4linux, onesixtyone, ike-scan, davtest | service enum | nmap NSE scripts + smbmap/impacket | AUR |
| commix/tplmap, hydra/medusa | niche injection/brute | sqlmap+ghauri; trevorspray+kerbrute | as needed |

### Installed 2026-08-22 (were missing before)

| Tool | Path / version | Notes |
|---|---|---|
| feroxbuster | `~/.local/bin` v2.13.1 | recursive dir brute: `feroxbuster -u URL -w WL -x php,json,txt --smart --auto-tune` |
| sisakulint | `~/.local/bin` v0.3.6 | `sisakulint scan .github/workflows/` or bare (auto-detect); `--remote owner/repo` |
| aws-cli v2 | `~/.local/bin/aws` v2.36.29 | `aws s3 ls s3://b --no-sign-request`; configure keys via `aws configure` if needed |
| wscat | `~/.local/bin/wscat` | `-c <url>`, `-H header`, `-s subprotocol`; wsdump also works |
| x8 | `~/.local/bin/x8` v4.3.0 | hidden params: `x8 -u "URL" -w params.txt` (wordlist of names) |
| s3scanner | `~/go/bin/s3scanner` | `-bucket-file buckets.txt -provider aws` (+gcp/azure/digitalocean/custom) |

## 7. API KEYS (configured, do not re-setup)

- subfinder provider-config.yaml ✓ · chaos config.yaml ✓ · notify provider-config.yaml ✓
- HIBP used keylessly (k-anonymity) via breach_checker.py
