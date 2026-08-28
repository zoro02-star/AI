#!/usr/bin/env python3
"""bb_common.py — Shared utilities for the bug-bounty ecosystem.

Provides composable primitives used across all skills/tools so each script
doesn't reimplement retries, timeouts, caching, dedup, structured output, and
secret-redacting logging.

Features:
  - retry()  : exponential backoff with jitter, configurable attempts/timeout
  - timeout()/run_cmd(): safe subprocess with timeout + secret scrub
  - Cache    : disk cache keyed by (target, query); avoids redundant work
  - Dedup    : file/stream dedup that preserves order (anew-like, pure python)
  - Semaphore : controlled concurrency (threads with cap)
  - redact() : strip secrets/tokens/cookies/keys from strings for safe logging
  - Log      : leveled logger that redacts secrets

This module is SAFE — it never sends traffic on its own. It only provides
helpers the user's workflows call against authorized targets.

Usage (import as a library, or as CLI for small utilities):
    from bb_common import retry, Cache, Dedup, redact, run_cmd

CLI:
    python3 bb_common.py dedup --input f.txt [--output out.txt] [--key hash|text]
    python3 bb_common.py redact --text "token=abc123"
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterable, Iterator

# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

# Pattern that catches common secret-bearing strings
_SECRET_PATTERNS = [
    re.compile(r"(?i)(\b(?:api|secret|token|key|password|passwd|client_secret|auth|bearer|session|cookie)\s*[=:]\s*)([A-Za-z0-9_\-\.]{8,})"),
    re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9_\-\.=]+)"),
    re.compile(r"(?i)([\"']?(?:authorization|cookie)\s*[\"']?\s*[:=]\s*[\"'])([^\"']+)([\"'])"),
    re.compile(r"(?i)(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),  # JWT
    re.compile(r"(?i)(ghp_[A-Za-z0-9]{20,})"),       # github PAT
    re.compile(r"(?i)(AKIA[0-9A-Z]{16})"),           # AWS access key
    re.compile(r"(?i)(sk-[A-Za-z0-9]{10,})"),        # openai-ish / generic sk-
    re.compile(r"(?i)(\b(?:sk|pk|rk)_[A-Za-z0-9]{10,}\b)"),  # other _-suffixed keys
]

_REDACT = "<REDACTED>"


def redact(text: str, keep_prefix: int = 0) -> str:
    """Replace secrets in a string with <REDACTED>. Safe for logs/reports.

    If keep_prefix>0, keeps the first N chars of the matched secret so the
    operator can correlate without exposing the whole value.
    """
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        # Rebuild each match as [revealed label] + [redacted value]
        out = pat.sub(_redact_match, out)
    return out


def _redact_match(m: re.Match) -> str:
    """Redact the value portion of a secret-bearing match, keep the label."""
    groups = [g for g in m.groups() if g is not None]
    if len(groups) >= 2:
        # keep the first group (label/quote), redact everything after
        keep = groups[0]
        return keep + _REDACT
    return _REDACT


# ---------------------------------------------------------------------------
# Logging (redacting)
# ---------------------------------------------------------------------------

class Logger:
    """Minimal leveled logger that redacts secrets before write."""
    LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}

    def __init__(self, name: str = "bb", level: str = "info", stream=None):
        self.name = name
        self.level = self.LEVELS.get(level, 20)
        self.stream = stream or sys.stderr

    def _log(self, lvl: int, lvlname: str, msg: str, **kw):
        if lvl < self.level:
            return
        safe = redact(str(msg))
        if kw:
            # Redact each value independently so json.dumps spacing/quotes
            # can't hide a secret (e.g. token="sk-...")
            scrubbed = {str(k): redact(str(v)) for k, v in kw.items()}
            safe += " " + json.dumps(scrubbed, default=str)
        self.stream.write(f"[{lvlname}] {safe}\n")

    def debug(self, m, **kw): self._log(10, "D", m, **kw)
    def info(self, m, **kw): self._log(20, "I", m, **kw)
    def warn(self, m, **kw): self._log(30, "W", m, **kw)
    def error(self, m, **kw): self._log(40, "E", m, **kw)


# ---------------------------------------------------------------------------
# Retry with exponential backoff + jitter
# ---------------------------------------------------------------------------

def retry(
    fn: Callable[..., Any],
    *,
    attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff: float = 2.0,
    jitter: bool = True,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> Any:
    """Call fn(), retrying on failure with exponential backoff + jitter.

    Raises the last exception if attempts are exhausted.
    """
    delay = base_delay
    last_exc: BaseException | None = None
    for i in range(1, attempts + 1):
        try:
            return fn()
        except retry_on as e:
            last_exc = e
            if i >= attempts:
                break
            sleep = delay * (backoff ** (i - 1))
            if sleep > max_delay:
                sleep = max_delay
            if jitter:
                sleep *= random.uniform(0.5, 1.5)
            time.sleep(sleep)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Safe subprocess with timeout + redaction
# ---------------------------------------------------------------------------

def run_cmd(
    cmd: list[str],
    *,
    timeout: float = 30.0,
    input_bytes: bytes | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    check: bool = False,
    logger: Logger | None = None,
) -> tuple[int, str, str]:
    """Run a command safely with timeout. Returns (returncode, stdout, stderr).

    Never blocks past `timeout`; on timeout kills the process. Logs are
    redacted so tokens/keys aren't written.
    """
    safe_cmd = [redact(str(c)) for c in cmd]
    if logger:
        logger.debug("run: " + " ".join(safe_cmd))
    try:
        p = subprocess.run(
            cmd, capture_output=True, input=input_bytes, text=True,
            timeout=timeout, cwd=cwd, env=env,
        )
    except subprocess.TimeoutExpired as e:
        return (124, "", redact(str(e)))
    except FileNotFoundError as e:
        return (127, "", f"not found: {e}")
    except OSError as e:
        return (1, "", redact(str(e)))

    code = p.returncode
    out = p.stdout or ""
    err = p.stderr or ""
    if logger:
        logger.debug(f"rc={code} out={len(out)}B err={len(err)}B")
    return (code, out, err)


# ---------------------------------------------------------------------------
# Disk cache (target+query keyed) — avoids redundant work across runs
# ---------------------------------------------------------------------------

class Cache:
    """Simple JSON disk cache. Key = sha256(target|query). TTL in seconds."""

    def __init__(self, cache_dir: str, ttl: int = 86400):
        self.cache_dir = cache_dir
        self.ttl = ttl
        os.makedirs(cache_dir, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, target: str, query: str, namespace: str = "") -> str:
        h = hashlib.sha256(f"{namespace}|{target}|{query}".encode()).hexdigest()[:24]
        return os.path.join(self.cache_dir, f"{h}.json")

    def get(self, target: str, query: str, namespace: str = "") -> Any | None:
        path = self._path(target, query, namespace)
        try:
            with open(path) as f:
                entry = json.load(f)
            if time.time() - entry.get("_ts", 0) > self.ttl:
                return None
            return entry.get("value")
        except (OSError, ValueError):
            return None

    def set(self, target: str, query: str, value: Any, namespace: str = "") -> None:
        path = self._path(target, query, namespace)
        entry = {"_ts": time.time(), "value": value}
        with self._lock:
            try:
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(entry, f, default=str)
                os.replace(tmp, path)
            except OSError:
                pass

    # Convenience: cached_call runs fn() only if not cached & not too fresh
    def cached_call(self, target: str, query: str, fn: Callable[[], Any],
                    namespace: str = "", ttl: int | None = None) -> Any:
        if ttl is not None:
            old = self.ttl
            self.ttl = ttl
            v = self.get(target, query, namespace)
            self.ttl = old
        else:
            v = self.get(target, query, namespace)
        if v is not None:
            return v
        value = fn()
        self.set(target, query, value, namespace)
        return value


# ---------------------------------------------------------------------------
# Dedup preserving order (pure-python "anew")
# ---------------------------------------------------------------------------

class Dedup:
    """Order-preserving dedup on an iterable of strings, by exact or by key."""

    def __init__(self, key: str = "text"):
        self.key = key
        self._seen: set[str] = set()

    def _k(self, item: str) -> str:
        if self.key == "hash":
            return hashlib.sha256(item.encode()).hexdigest()
        return item

    def filter(self, items: Iterable[str]) -> Iterator[str]:
        for it in items:
            k = self._k(it.strip())
            if k not in self._seen:
                self._seen.add(k)
                yield it


# ---------------------------------------------------------------------------
# Controlled concurrency
# ---------------------------------------------------------------------------

class ThreadPool:
    """Run tasks with a cap on concurrency (thread-based, bounded)."""

    def __init__(self, max_workers: int = 8):
        self.max_workers = max(1, max_workers)
        self._sem = threading.Semaphore(self.max_workers)

    def submit(self, fn: Callable[[], Any]) -> Any:
        with self._sem:
            return fn()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_dedup(args: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default=None)
    p.add_argument("--key", choices=["text", "hash"], default="text")
    a = p.parse_args(args)
    d = Dedup(key=a.key)
    with open(a.input, encoding="utf-8", errors="replace") as f:
        results = list(d.filter(f))
    out_path = a.output or a.input
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + ("\n" if results else ""))
    print(f"dedup: {len(results)} unique lines -> {out_path}")
    return 0


def _cli_redact(args: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--text", default="")
    a = p.parse_args(args)
    print(redact(a.text))
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd, rest = sys.argv[1], sys.argv[2:]
    if cmd == "dedup":
        return _cli_dedup(rest)
    if cmd == "redact":
        return _cli_redact(rest)
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
