#!/usr/bin/env python3
"""safe_scope.py — Scope validation utility. FAILS CLOSED.

The single enforcement point for "is this target authorized?" before any
outbound request, scan, or active action. Every bug-bounty workflow MUST call
this before touching a target. If scope is missing, empty, or ambiguous, this
returns BLOCKED (never proceeds).

Scope comes from an authorized scope file:
  - A HackerOne/GitHub program scope export, OR
  - A user-provided allowlist file (one pattern per line).

Rules enforced:
  - If no scope file is supplied/configured -> BLOCKED (fail closed).
  - If a target is not covered by any allow pattern -> BLOCKED.
  - If the scope file is empty of patterns -> BLOCKED.
  - IP/CIDR targets are only allowed if the scope file explicitly permits them
    (most programs are domain-based; IP scanning needs explicit human opt-in).

Exit codes:
  0  ALLOWED
  2  BLOCKED (out of scope, empty scope, IP without permission, or invalid)
  3  FATAL (bad arguments / missing scope file)

Usage:
    python3 safe_scope.py --target api.example.com --scope scope.txt [--exclude excl.txt] [--json]
    python3 safe_scope.py --target 10.0.0.1 --scope scope.txt --allow-ips
    python3 safe_scope.py --target sub.example.com --scope scope.txt --vuln-class ssrf
    # --vuln-class aborts if the program excludes that vuln class line "excluded: <class>"

The --vuln-class gate reads "excluded: <class>" directives in the scope file.

This tool is passive/fail-closed by design. It never sends traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import fnmatch
import ipaddress
import sys
from urllib.parse import urlparse


def load_scope_file(path: str | None, flags: dict | None = None) -> list[str] | None:
    """Load pattern lines from a scope file. Returns None if unavailable/invalid.

    Recognizes HackerOne-style annotated lines:
        *.example.com
        api.example.com
        excluded: blog.example.com
        "excluded: <vuln-class>"  -> a per-line exclusion directive
        URL lines like https://example.com/*  -> normalized to host wildcard

    Comments (#) and blank lines are ignored. If no usable domain/IP pattern is
    found, returns None (which callers must treat as BLOCKED).
    """
    if not path or not os.path.isfile(path):
        return None
    patterns = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                low = line.lower()
                if low.startswith("excluded:"):
                    # Record allocation in flags if provided
                    if flags is not None:
                        flags.setdefault("exclusions", []).append(line.split(":", 1)[1].strip())
                    continue
                # Normalize a URL line to a host wildcard
                if line.startswith(("http://", "https://")):
                    host = urlparse(line).netloc
                    line = host if host else line
                # Strip trailing /* and /path
                line = line.split("/")[0]
                line = line.strip()
                # Ignore purely path-looking entries
                if not line or line.startswith(("/*", "*.")) is False and "." not in line and not line.startswith("*") and "/" in line:
                    continue
                patterns.append(line)
    except OSError:
        return None
    return patterns if patterns else None


def extract_vuln_class_directives(scope_path: str | None) -> set[str]:
    """Return vuln classes the program has excluded, e.g. {'dos','social_engineering'}."""
    excluded = set()
    if not scope_path or not os.path.isfile(scope_path):
        return excluded
    try:
        with open(scope_path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip().lower()
                if line.startswith("excluded:") and not line.startswith("excluded: http"):
                    val = line.split(":", 1)[1].strip()
                    excluded.add(val)
    except OSError:
        pass
    return excluded


def _extract_host(target: str) -> str:
    """Normalize a target (URL or host) to just the hostname for matching."""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).netloc
        # strip userinfo
        if "@" in t:
            t = t.rsplit("@", 1)[1]
        # strip port
        if ":" in t and not t.startswith("["):
            t = t.split(":")[0]
    return t.rstrip("/").lower()


def _is_ip(target: str) -> bool:
    t = _extract_host(target)
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def _matches(pattern: str, host: str) -> bool:
    """Match a host against a scope pattern (supports *.wildcard)."""
    p = pattern.strip().lower().rstrip("/")
    # Exact
    if p == host:
        return True
    # Wildcard: *.example.com matches sub.example.com and example.com (recursive)
    if p.startswith("*."):
        base = p[2:]
        if host == base:
            return True
        if host.endswith("." + base):
            return True
        # also match *.example.com against example.com itself
        return host == base
    # Plain wildcard glob
    if fnmatch.fnmatch(host, p):
        return True
    # Subdomain of a bare domain scope (example.com covers api.example.com)
    if "." in p and "." not in p.split("*")[0]:
        if host.endswith("." + p):
            return True
    return False


def evaluate(target: str, scope_path: str | None, exclude_path: str | None = None,
             allow_ips: bool = False, vuln_class: str | None = None) -> dict:
    """Evaluate a single target against scope. Returns a structured decision."""
    result = {
        "target": target,
        "allowed": False,
        "reason": "",
        "scope_file": scope_path,
        "vuln_class": vuln_class,
        "checks": {},
    }

    # Fail closed: no scope loaded
    patterns = load_scope_file(scope_path)
    if not patterns:
        result["reason"] = "NO_SCOPE_OR_EMPTY_SCOPE"
        return result

    # Optional: excluded vuln-class gate
    if vuln_class:
        excluded = extract_vuln_class_directives(scope_path)
        if vuln_class.lower() in excluded:
            result["reason"] = f"VULN_CLASS_EXCLUDED:{vuln_class}"
            return result

    # Exclusions
    excl_pats = load_scope_file(exclude_path) if exclude_path else None
    if exclude_path and not excl_pats:
        # If an exclude file was supplied but unreadable, block (fail closed)
        result["reason"] = "EXCLUDE_FILE_UNREADABLE"
        return result

    host = _extract_host(target)
    if not host:
        result["reason"] = "INVALID_TARGET"
        return result

    # IP handling: only allow if allow_ips AND scope explicitly has that IP/CIDR
    if _is_ip(host):
        result["checks"]["ip"] = "target-is-ip"
        if not allow_ips:
            result["reason"] = "IP_TARGET_REQUIRES_ALLOW_IPS" if not allow_ips else ""
            result["reason"] = "IP_TARGET_NOT_PERMITTED"
            return result
        ip_allowed = False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        for pat in patterns:
            pat_l = pat.lower()
            if "/" in pat_l:  # CIDR in scope file
                try:
                    net = ipaddress.ip_network(pat_l, strict=False)
                    if ip and ip in net:
                        ip_allowed = True
                        break
                except ValueError:
                    continue
            elif pat_l == host:
                ip_allowed = True
                break
        if not ip_allowed:
            result["reason"] = "IP_OUT_OF_SCOPE"
            return result
    else:
        # Domain/subdomain matching
        matched = False
        for pat in patterns:
            if _matches(pat, host):
                matched = True
                # check exclusion
                if excl_pats:
                    blocked = False
                    for ep in excl_pats:
                        if _matches(ep, host):
                            blocked = True
                            break
                    if blocked:
                        result["reason"] = "EXCLUDED_BY_RULE"
                        return result
                break
        if not matched:
            result["reason"] = "OUT_OF_SCOPE"
            return result

    result["allowed"] = True
    result["reason"] = "ALLOWED"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="safe_scope.py — fail-closed scope validation"
    )
    parser.add_argument("--target", required=True, help="Target URL or host to validate")
    parser.add_argument("--scope", help="Path to authorized scope file (allowlist)")
    parser.add_argument("--exclude", help="Optional path to exclusion patterns")
    parser.add_argument("--allow-ips", action="store_true",
                        help="Permit IP/CIDR targets (only if also in scope)")
    parser.add_argument("--vuln-class", help="Abort if program excludes this vuln class")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    args = parser.parse_args()

    # If no scope file given, fail closed (do not guess an allowlist)
    if not args.scope:
        print("safe_scope: FATAL — no --scope file provided; refusing to proceed (fail closed)", file=sys.stderr)
        return 3

    res = evaluate(args.target, args.scope, args.exclude, args.allow_ips, args.vuln_class)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"safe_scope: {res['target']} -> {'ALLOWED' if res['allowed'] else 'BLOCKED'} ({res['reason']})")

    return 0 if res["allowed"] else (2 if not res.get("checks") or res["reason"] != "NO_SCOPE_OR_EMPTY_SCOPE" else 2)


if __name__ == "__main__":
    sys.exit(main())
