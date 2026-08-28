#!/usr/bin/env python3
"""capabilities.py — Dynamic tool/capability registry for the bug-bounty ecosystem.

Detects which bug-bounty tools are actually installed on this machine, their
resolved path (accounting for PATH shadowing like the httpx collision), version
where derivable, and functional status. Caches the result to JSON.

This replaces hardcoded "assume X is at path Y" assumptions across skills. Every
workflow should ask capabilities.py "is X available + where?" instead of guessing.

Usage:
    python3 capabilities.py                        # full scan + print summary
    python3 capabilities.py --json                 # full JSON output
    python3 capabilities.py --check httpx nginx    # is tool X installed?
    python3 capabilities.py --list-categories      # list registered tool categories
    python3 capabilities.py --refresh              # force re-scan (ignore cache)
    python3 capabilities.py --cache-file PATH      # override cache location
    python3 capabilities.py --require httpx,ffuf   # exit non-zero if any missing

Exit codes:
    0  all required tools present (or no --require given)
    1  one or more required tools missing (returns 1)
    2  fatal error (bad args)

NOTE: This is a *discovery* tool. It never runs the tools against targets —
it only checks that binaries exist and are executable. Completely safe/passive.
"""

from __future__ import annotations

import argparse
import fnmatch
import functools
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Tool registry: category -> list of tool descriptors.
# Each descriptor: a canonical tool name and where to look for it.
# A tool may be 'optional' (nice to have) or required for a workflow.
# ---------------------------------------------------------------------------

def _which(name: str) -> str | None:
    """Resolve a command to an absolute path honoring PATH, with shadowing prio."""
    return shutil.which(name)


def _cmd_version(cmd: list[str], timeout: int = 6) -> str | None:
    """Try to extract a version string from a tool's --version/-V output."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    first = (out or "").strip().splitlines()
    return first[0][:80] if first else None


# Map: canonical tool name -> list of candidate binary names / preferred resolvers
# Ordered by preference so the *verified* PD httpx is chosen over the Python one.
TOOLS: dict[str, dict] = {
    # -- Recon / DNS --
    "subfinder": { "which": ["subfinder"], "ver": ["-version"] },
    "assetfinder": { "which": ["assetfinder"], "ver": ["-h"] },
    "chaos": { "which": ["chaos"], "ver": ["-v"] },
    "amass": { "which": ["amass"], "ver": ["-version"] },
    "puredns": { "which": ["puredns"], "ver": ["-h"] },
    "massdns": { "which": ["massdns"], "ver": ["-h"] },
    "shuffledns": { "which": ["shuffledns"], "ver": ["-v"] },
    "dnsx": { "which": ["dnsx"], "ver": ["-version"] },
    "alterx": { "which": ["alterx"], "ver": ["-version"] },
    "tlsx": { "which": ["tlsx"], "ver": ["-version"] },
    "hakrevdns": { "which": ["hakrevdns"], "ver": ["-h"] },
    "dnsreaper": { "which": ["dnsreaper"], "ver": ["-h"] },
    "asnmap": { "which": ["asnmap"], "ver": ["-v"] },
    "mapcidr": { "which": ["mapcidr"], "ver": ["-version"] },
    "cdncheck": { "which": ["cdncheck"], "ver": ["-version"] },
    "uncover": { "which": ["uncover"], "ver": ["-version"] },
    "knockpy": { "which": ["knockpy"], "ver": ["-h"] },
    "sublert": { "which": ["sublert"], "ver": ["-h"] },

    # -- HTTP probing / crawl / URLs --
    "httpx": { "which": ["httpx"], "prefer": ["~/go/bin/httpx", "go/bin/httpx"], "ver": ["-version"] },
    "katana": { "which": ["katana"], "ver": ["-version"] },
    "hakrawler": { "which": ["hakrawler"], "ver": ["-h"] },
    "gospider": { "which": ["gospider"], "ver": ["-h"] },
    "cariddi": { "which": ["cariddi"], "ver": ["-h"] },
    "gau": { "which": ["gau"], "ver": ["-v"] },
    "waybackurls": { "which": ["waybackurls"], "ver": ["-h"] },
    "waymore": { "which": ["waymore"], "ver": ["-h"] },
    "urlfinder": { "which": ["urlfinder"], "ver": ["-v"] },
    "getJS": { "which": ["getJS"], "ver": ["-h"] },
    "jsluice": { "which": ["jsluice"], "ver": ["-h"] },
    "xnLinkFinder": { "which": ["xnLinkFinder"], "ver": ["-h"] },
    "arjun": { "which": ["arjun"], "ver": ["-h"] },
    "x8": { "which": ["x8"], "ver": ["-version"] },
    "qsreplace": { "which": ["qsreplace"], "ver": ["-h"] },
    "unfurl": { "which": ["unfurl"], "ver": ["-h"] },
    "anew": { "which": ["anew"], "ver": ["-h"] },
    "gf": { "which": ["gf"], "ver": ["-h"] },
    "kxss": { "which": ["kxss"], "ver": ["-h"] },
    "airixss": { "which": ["airixss"], "ver": ["-h"] },
    "dalfox": { "which": ["dalfox"], "ver": ["-version"] },
    "XSStrike": { "which": ["XSStrike"], "ver": ["-h"] },
    "byp4xx": { "which": ["byp4xx"], "ver": ["-h"] },

    # -- Content discovery --
    "ffuf": { "which": ["ffuf"], "ver": ["-V"] },
    "gobuster": { "which": ["gobuster"], "ver": ["version"] },
    "dirsearch": { "which": ["dirsearch"], "ver": ["--version"] },
    "fff": { "which": ["fff"], "ver": ["-h"] },
    "feroxbuster": { "which": ["feroxbuster"], "ver": ["--version"] },
    "kiterunner": { "which": ["kr"], "ver": ["-h"] },

    # -- Port scanning / services --
    "naabu": { "which": ["naabu"], "ver": ["-version"] },
    "nmap": { "which": ["nmap"], "ver": ["-V"] },
    "masscan": { "which": ["masscan"], "ver": ["--version"] },
    "smap": { "which": ["smap"], "ver": ["-h"] },
    "httprobe": { "which": ["httprobe"], "ver": ["-h"] },
    "meg": { "which": ["meg"], "ver": ["-h"] },

    # -- Screenshots / visual --
    "gowitness": { "which": ["gowitness"], "ver": ["version"] },
    "aquatone": { "which": ["aquatone"], "ver": ["-version"] },

    # -- Scanning / vuln --
    "nuclei": { "which": ["nuclei"], "ver": ["-version"] },
    "nikto": { "which": ["nikto"], "ver": ["-Version"] },
    "sqlmap": { "which": ["sqlmap"], "ver": ["--version"] },
    "ghauri": { "which": ["ghauri"], "ver": ["--version"] },
    "log4j-scan": { "which": ["log4j-scan"], "ver": ["-h"] },
    "crlfuzz": { "which": ["crlfuzz"], "ver": ["version"] },
    "interactsh-client": { "which": ["interactsh-client"], "ver": ["-version"] },
    "notify": { "which": ["notify"], "ver": ["-version"] },
    "subzy": { "which": ["subzy"], "ver": ["-version"] },
    "wafw00f": { "which": ["wafw00f"], "ver": ["-h"] },
    "whatwaf": { "which": ["whatwaf"], "ver": ["--help"] },
    "unwaf": { "which": ["unwaf"], "ver": ["-h"] },

    # -- Cloud / CI-CD / WebSocket --
    "aws": { "which": ["aws", "aws-cli"], "ver": ["--version"] },
    "s3scanner": { "which": ["s3scanner"], "prefer": ["~/go/bin/s3scanner", "go/bin/s3scanner"], "ver": ["-h"] },
    "sisakulint": { "which": ["sisakulint"], "ver": ["--version"] },
    "wscat": { "which": ["wscat"], "ver": ["-h"] },
    "wsdump": { "which": ["wsdump"], "ver": ["-h"] },
    "cloud_enum": { "which": ["cloud_enum"], "ver": ["-h"] },
    "cloudfail": { "which": ["cloudfail"], "ver": ["-h"] },
    "scoutsuite": { "which": ["scout"], "ver": ["--version"] },

    # -- Secrets / git / cloud --
    "trufflehog": { "which": ["trufflehog"], "ver": ["--version"] },
    "gitleaks": { "which": ["gitleaks"], "ver": ["version"] },
    "shhgit": { "which": ["shhgit"], "ver": ["-h"] },
    "noseyparker": { "which": ["noseyparker"], "ver": ["--version"] },
    "git-hound": { "which": ["git-hound"], "ver": ["-h"] },
    "GitDorker": { "which": ["GitDorker"], "ver": ["-h"] },
    "GitTools": { "which": ["GitTools"], "ver": ["-h"] },
    "dvcs-ripper": { "which": ["dvcs-ripper"], "ver": ["-h"] },
    "ds_store_exp": { "which": ["ds_store_exp"], "ver": ["-h"] },
    "apkleaks": { "which": ["apkleaks"], "ver": ["--version"] },
    "semgrep": { "which": ["semgrep"], "ver": ["--version"] },

    # -- GraphQL / JWT / auth --
    "graphql-cop": { "which": ["graphql-cop"], "ver": ["-h"] },
    "graphw00f": { "which": ["graphw00f"], "ver": ["-h"] },
    "clairvoyance": { "which": ["clairvoyance"], "ver": ["-h"] },
    "gqlmap": { "which": ["gqlmap"], "ver": ["-h"] },
    "jwt_tool": { "which": ["jwt_tool"], "ver": ["-h"] },
    "trevorspray": { "which": ["trevorspray"], "ver": ["-h"] },
    "kerbrute": { "which": ["kerbrute"], "ver": ["-h"] },
    "smbmap": { "which": ["smbmap"], "ver": ["-h"] },
    "certipy": { "which": ["certipy"], "ver": ["-h"] },
    "cupp": { "which": ["cupp"], "ver": ["-h"] },
    "impacket": { "which": ["secretsdump"], "ver": ["-h"] },

    # -- Custom arsenal (repo tools) --
    "scope_checker": { "py": "scope_checker.py" },
    "eol_check": { "py": "eol_check.py" },
    "intel_engine": { "py": "intel_engine.py" },
    "tech_cve_intel": { "py": "tech_cve_intel.py" },
    "scanplate": { "py": "scanplate.py" },
    "hunt": { "py": "hunt.py" },
    "lead_board": { "py": "lead_board.py" },
    "recon_engine": { "sh": "recon_engine.sh" },
    "takeover_scanner": { "sh": "takeover_scanner.sh" },
    "cve_scan": { "sh": "cve_scan.sh" },
    "vuln_scanner": { "sh": "vuln_scanner.sh" },
    "bypass_403": { "sh": "bypass_403.sh" },
    "cloud_recon": { "sh": "cloud_recon.sh" },
    "cicd_scanner": { "sh": "cicd_scanner.sh" },
    "param_discovery": { "sh": "param_discovery.sh" },
    "secrets_hunter": { "sh": "secrets_hunter.sh" },
    "spray_orchestrator": { "sh": "spray_orchestrator.sh" },
    "osint_employees": { "sh": "osint_employees.sh" },
    "wordlist_engine": { "sh": "wordlist_engine.sh" },
    "scope_aggregator": { "sh": "scope_aggregator.sh" },
}

# Extended search roots beyond $PATH for binaries that live in ~/go/bin etc.
EXTRA_ROOTS: list[str] = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/bin"),
]


def _expand_roots() -> list[str]:
    return EXTRA_ROOTS


def _resolve_binary(name: str, desc: dict) -> str | None:
    """Resolve a tool binary, honoring preferred paths then PATH then extra roots."""
    prefer = desc.get("prefer", [])
    # Preferred explicit paths (e.g. ~/go/bin/httpx over the Python httpx)
    for p in prefer:
        full = os.path.expanduser(p)
        if not os.path.isabs(full):
            for root in _expand_roots():
                cand = os.path.join(root, os.path.basename(full))
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    return cand
            continue
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    # Which names (honoring PATH)
    for n in desc.get("which", [name]):
        resolved = shutil.which(n)
        if resolved:
            return resolved
    # Extra roots fallback for any name
    for root in _expand_roots():
        for n in desc.get("which", [name]):
            cand = os.path.join(root, n)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def _tool_version(path: str, desc: dict) -> str | None:
    ver_flags = desc.get("ver")
    if not ver_flags:
        return None
    # Version flags can carry spaces (e.g. "version")
    for flag in ver_flags:
        v = _cmd_version([path, *flag.split()])
        if v:
            return v
    return None


def _repo_tools_dir() -> str | None:
    for cand in (
        os.path.expanduser("~/tools/claude-bug-bounty/tools"),
        os.path.expanduser("~/.config/opencode/skills/tech-cve-intel/scripts"),
        os.path.expanduser("~/.config/opencode/skills/custom-scanner-kit/scripts"),
    ):
        if os.path.isdir(cand):
            return cand
    return None


def _resolve_py(sh_name: str, desc: dict) -> str | None:
    dirs = _repo_tools_dir()
    if not dirs:
        return None
    # Check the repo tools dir and the tech-cve-intel scripts dir
    for d in (os.path.expanduser("~/tools/claude-bounty/tools"),
              os.path.expanduser("~/tools/claude-bug-bounty/tools"),
              os.path.expanduser("~/.config/opencode/skills/tech-cve-intel/scripts"),
              os.path.expanduser("~/.config/opencode/skills/custom-scanner-kit/scripts")):
        if not d or not os.path.isdir(d):
            continue
        cand = os.path.join(d, sh_name)
        if os.path.isfile(cand):
            return cand
    return None


def scan(refresh: bool = False, cache_file: str | None = None) -> dict:
    """Full capability scan. Returns {tool: {status, path, version, source}}."""
    if cache_file is None:
        cache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".capabilities-cache.json")

    if not refresh and os.path.isfile(cache_file):
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            if cached.get("_version") == 1 and time.time() - cached.get("_ts", 0) < 3600:
                return cached
        except (OSError, ValueError):
            pass

    result: dict = {
        "_version": 1,
        "_ts": time.time(),
        "tools": {},
        "categories": {},
    }

    for name, desc in TOOLS.items():
        path = None
        source = "missing"
        if "which" in desc or "prefer" in desc:
            path = _resolve_binary(name, desc)
            source = "binary" if path else "missing"
        elif "py" in desc:
            p = _resolve_py(desc["py"], desc)
            if p:
                path, source = p, "python-script"
        elif "sh" in desc:
            p = _resolve_py(desc["sh"], desc)
            if p:
                path, source = p, "shell-script"

        version = _tool_version(path, desc) if path and source == "binary" else None

        category = "other"
        for cat, names in CATEGORIES.items():
            if name in names:
                category = cat
                break

        result["tools"][name] = {
            "status": "present" if path else "missing",
            "path": path,
            "version": version,
            "source": source,
            "category": category,
        }
        result["categories"].setdefault(category, []).append(name)

    try:
        with open(cache_file, "w") as f:
            json.dump(result, f, indent=2)
    except OSError:
        pass

    return result


CATEGORIES: dict[str, list[str]] = {
    "recon-dns": ["subfinder", "assetfinder", "chaos", "amass", "puredns", "massdns", "shuffledns", "dnsx", "alterx", "tlsx", "hakrevdns", "dnsreaper", "asnmap", "mapcidr", "cdncheck", "uncover", "knockpy", "sublert"],
    "http-crawl": ["httpx", "katana", "hakrawler", "gospider", "cariddi", "gau", "waybackurls", "waymore", "urlfinder", "getJS", "jsluice", "xnLinkFinder"],
    "params-js": ["arjun", "x8", "qsreplace", "unfurl", "anew", "gf", "kxss", "airixss"],
    "xss": ["dalfox", "XSStrike"],
    "content": ["ffuf", "gobuster", "dirsearch", "fff", "feroxbuster", "kiterunner"],
    "ports": ["naabu", "nmap", "masscan", "smap", "httprobe", "meg"],
    "screenshots": ["gowitness", "aquatone"],
    "scanning": ["nuclei", "nikto", "sqlmap", "ghauri", "log4j-scan", "crlfuzz", "interactsh-client", "notify", "subzy"],
    "waf": ["wafw00f", "whatwaf", "unwaf"],
    "cloud-cicd": ["aws", "s3scanner", "sisakulint", "wscat", "wsdump", "cloud_enum", "cloudfail"],
    "secrets": ["trufflehog", "gitleaks", "shhgit", "noseyparker", "git-hound", "GitDorker", "GitTools"],
    "auth": ["graphql-cop", "graphw00f", "clairvoyance", "gqlmap", "jwt_tool", "trevorspray", "kerbrute", "smbmap", "certipy", "impacket"],
    "custom": ["scope_checker", "eol_check", "intel_engine", "tech_cve_intel", "scanplate", "hunt", "lead_board", "recon_engine", "takeover_scanner", "cve_scan", "vuln_scanner", "bypass_403", "cloud_recon", "cicd_scanner", "param_discovery", "secrets_hunter", "spray_orchestrator", "osint_employees", "wordlist_engine", "scope_aggregator"],
}


def format_summary(data: dict, color: bool = True) -> str:
    present = [k for k, v in data["tools"].items() if v["status"] == "present"]
    missing = [k for k, v in data["tools"].items() if v["status"] == "missing"]

    green = "\033[0;32m" if color else ""
    red = "\033[0;31m" if color else ""
    dim = "\033[2m" if color else ""
    nc = "\033[0m" if color else ""

    lines = []
    lines.append(f"\n{'='*64}")
    lines.append("  BUG-BOUNTY CAPABILITY REGISTRY")
    lines.append(f"{'='*64}")
    lines.append(f"  {green}{len(present)}{nc} tools present · {red}{len(missing)}{nc} missing")

    for cat in CATEGORIES:
        in_cat = [k for k in CATEGORIES[cat] if k in data["tools"]]
        present_cat = [k for k in in_cat if data["tools"][k]["status"] == "present"]
        missing_cat = [k for k in in_cat if data["tools"][k]["status"] == "missing"]
        lines.append(f"\n  [{cat}]")
        if present_cat:
            lines.append(f"    {green}{', '.join(present_cat)}{nc}")
        if missing_cat:
            lines.append(f"    {dim}missing: {', '.join(missing_cat)}{nc}")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dynamic tool/capability registry for bug-bounty workflows"
    )
    parser.add_argument("--json", action="store_true", help="Full JSON output")
    parser.add_argument("--refresh", action="store_true", help="Force re-scan")
    parser.add_argument("--cache-file", default=None, help="Override cache path")
    parser.add_argument("--check", nargs="+", default=[], help="Check specific tools")
    parser.add_argument("--list-categories", action="store_true", help="List categories")
    parser.add_argument("--require", nargs="+", default=[], help="Exit non-zero if any missing")
    parser.add_argument("--no-color", action="store_true", help="Disable color")
    args = parser.parse_args()

    if args.list_categories:
        for cat in CATEGORIES:
            print(f"{cat}: {', '.join(CATEGORIES[cat])}")
        return 0

    data = scan(refresh=args.refresh, cache_file=args.cache_file)

    if args.check:
        for name in args.check:
            t = data["tools"].get(name)
            if not t:
                print(f"{name}: NOT REGISTERED")
            elif t["status"] == "present":
                print(f"{name}: present @ {t['path']}" + (f" ({t['version']})" if t["version"] else ""))
            else:
                print(f"{name}: MISSING")
        return 0

    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    print(format_summary(data, color=not args.no_color))

    if args.require:
        # nargs="+" can receive comma-separated or space-separated; normalize
        required = []
        for chunk in args.require:
            required.extend(p.strip() for p in chunk.split(",") if p.strip())
        missing = [n for n in required
                   if data["tools"].get(n, {}).get("status") != "present"]
        if missing:
            print(f"\nRequirement not met — missing: {', '.join(missing)}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
