---
name: knowledge-base
description: Query the offline web-security knowledge base (PayloadsAllTheThings + HackTricks + OWASP Top 10/API Top 10, deduplicated into 144 canonical technique pages). Use when researching web vulnerabilities, payloads, bypasses, CVEs, tools, OWASP mapping, or defensive mitigations; keywords include knowledge-base, payloads, hacktricks, cheat sheet, XSS, SQLi, SSRF, IDOR, JWT, deserialization.
---

# Offline Web-Security Knowledge Base

A structured KB at `/home/harsh/mygithub/knowlegebaseforhacking/knowledge-base/`
built from PayloadsAllTheThings, HackTricks, OWASP API Security Top 10 (2019+2023)
and OWASP Web Top 10 (2017). 11/11 QA checks pass. Prefer it over raw source
repos — it is deduplicated, cross-referenced, and provenance-tracked.

## Retrieval workflow

1. **Find the technique page**: `techniques/<category>/<slug>.md` — browse
   `INDEX.md`, or grep:
   ```bash
   rg -li "prototype pollution|cache poisoning" /home/harsh/mygithub/knowlegebaseforhacking/knowledge-base/techniques/
   ```
2. **Technique pages have stable sections** (use them as retrieval anchors):
   Overview · Classification (OWASP/CWE) · Technologies · Prerequisites ·
   Detection · Testing Considerations · Examples · Payload References ·
   Tool References · Related Techniques · Defensive Considerations ·
   Source Provenance.
3. **Raw payloads**: every page links its verbatim pack under
   `payloads/<category>/<slug>.md`. If you need more than the pack holds,
   follow the provenance links into `original/` (byte-preserved sources).
4. **Machine lookup**:
   ```bash
   cd /home/harsh/mygithub/knowlegebaseforhacking/knowledge-base/metadata
   jq '.[] | select(.category=="ssrf") | .path' techniques.json
   jq '.[] | select(.cve=="CVE-2021-44228")' cves.json
   jq '.nginx' tags.json          # tag -> documents
   jq '.[] | select(.name=="sqlmap")' tools.json
   jq 'map(select(.type=="related"))' relationships.json
   ```
5. **Indexes**: `INDEX.md` (all techniques), `tools/TOOLS.md` (260 tools),
   `vulnerabilities/CVE-INDEX.md`, `wordlists/INDEX.md`,
   `references/owasp-top-ten-2017.md` + `owasp-api-security-top-10.md` (cross-walks),
   `defensive/INDEX.md` (mitigations), `references/non-web-sections.md`
   (779 non-web HackTricks pages).

## Rules

- Cite provenance: technique pages list exact original files; keep that chain.
- Respect markers: `[UNVERIFIED]`, `[POSSIBLY OUTDATED]`, `[CONFLICTING SOURCES]`.
- Payload packs cap at 400 blocks; originals are authoritative beyond that.
- Offensive content is contextualized for authorized testing only (CTFs,
  labs, in-scope bug bounty, defense). Never use it against systems without
  explicit permission.

## Rebuilding after source updates

```bash
cd /home/harsh/mygithub/knowlegebaseforhacking/knowledge-base/pipeline
python3 inventory.py && python3 dedup.py && python3 build_kb.py \
  && python3 indexes.py && python3 finalize.py && python3 qa.py
```

To extend the taxonomy or add alias mappings, edit `pipeline/taxonomy.py`
(TECHNIQUES dict) then rerun the build.
