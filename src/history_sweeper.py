#!/usr/bin/env python3
"""ghostaction-history-sweeper — scan a git repo's FULL history for leaked secrets.

Defensive tool that mirrors what the Oct 2026 GhostAction campaign added to its
payload: scanning git history for secrets, because attackers bank on the secrets
you forgot to rotate after they were committed (even if deleted later).

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field


VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Detection patterns (original regexes, tuned to the GhostAction v2 payload
# target list: AWS IDs, GitHub/GitLab tokens, common AI-provider keys, and
# generic high-entropy assignments).
# ---------------------------------------------------------------------------
PATTERNS: list[tuple[str, str, str]] = [
    (
        "AWS Access Key ID",
        r"AKIA[0-9A-Z]{16}",
        "Rotate via IAM immediately; invalidate the ID and audit CloudTrail.",
    ),
    (
        "GitHub token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}",
        "Revoke in GitHub Settings > Developer settings; check audit log.",
    ),
    (
        "GitLab token",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        "Revoke in GitLab User Settings > Access Tokens.",
    ),
    (
        "Anthropic API key",
        r"sk-ant-[A-Za-z0-9_\-]{20,}",
        "Revoke in Anthropic Console > API keys; rotate and check usage.",
    ),
    (
        "xAI API key",
        r"xai-[A-Za-z0-9]{20,}",
        "Revoke in the xAI console and rotate.",
    ),
    (
        "OpenAI-style API key",
        r"sk-(?:proj-)?[A-Za-z0-9]{20,}",
        "Revoke in the provider dashboard and rotate.",
    ),
    (
        "Stripe-style secret",
        r"sk_(?:live|test)_[A-Za-z0-9]{16,}",
        "Roll in the Stripe dashboard; review payments for abuse.",
    ),
    (
        "Generic high-entropy secret",
        # assignment-looking lines: KEY = "longish base64/hex-ish value"
        r"""(?im)^[^#\n]*?\b(?:secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-+/=]{16,})['"]?""",
        "Treat as leaked: rotate and invalidate.",
    ),
]


@dataclass
class Finding:
    secret_type: str
    commit: str
    commit_date: str
    file: str
    matched_text: str
    context: list[str] = field(default_factory=list)
    suggestion: str = ""


def _run_git(repo: str, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _verify_repo(repo: str) -> None:
    if not os.path.isdir(os.path.join(repo, ".git")):
        raise SystemExit(f"error: {repo!r} is not a git repository")


def scan_repo(repo: str, since: str | None = None) -> list[Finding]:
    """Scan every commit diff in history; return findings."""
    _verify_repo(repo)
    compiled = [(name, re.compile(pat), tip) for name, pat, tip in PATTERNS]

    rev_args = ["rev-list", "--all", "--reverse", "--timestamp"]
    if since:
        rev_args += [f"--since={since}"]
    out = _run_git(repo, *rev_args)
    commits = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        ts, sha = line.split(" ", 1)
        date = dt.datetime.fromtimestamp(int(ts), tz=dt.timezone.utc)
        commits.append((sha, date.strftime("%Y-%m-%d")))

    findings: list[Finding] = []
    for sha, date in commits:
        diff = _run_git(repo, "show", sha, "--format=", "--no-ext-diff", "-U2")
        # Split the combined diff into per-file hunks so we can name files.
        current_file = "unknown"
        block_lines: list[str] = []
        blocks: list[tuple[str, list[str]]] = []

        def flush():
            if block_lines:
                blocks.append((current_file, list(block_lines)))

        for line in diff.splitlines():
            if line.startswith("diff --git"):
                flush()
                block_lines = []
                m = re.search(r"b/(.+)$", line)
                current_file = m.group(1) if m else "unknown"
            else:
                block_lines.append(line)
        flush()

        for fname, lines in blocks:
            for i, line in enumerate(lines):
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                body = line[1:]
                for name, rx, tip in compiled:
                    for m in rx.finditer(body):
                        matched = m.group(0)
                        if name == "Generic high-entropy secret" and m.lastindex:
                            matched = m.group(1)
                        # Only count added lines (not hunk headers etc.)
                        ctx = [
                            l[1:] if l.startswith(("+", "-", " ")) else l
                            for l in lines[max(0, i - 2): i + 3]
                        ]
                        findings.append(
                            Finding(
                                secret_type=name,
                                commit=sha,
                                commit_date=date,
                                file=fname,
                                matched_text=matched[:120],
                                context=ctx,
                                suggestion=tip,
                            )
                        )
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse identical secret occurrences across identical file+commit."""
    seen: set[tuple[str, str, str, str]] = set()
    out = []
    for f in findings:
        key = (f.secret_type, f.commit, f.file, f.matched_text)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def render_checklist(findings: list[Finding], repo: str, since: str | None) -> str:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Secret rotation checklist",
        "",
        f"Repo: `{repo}`",
        f"Scanned: {now}",
        f"Since: {since or 'beginning of history'}",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No secrets found in history. 🎉")
        return "\n".join(lines) + "\n"
    for n, f in enumerate(findings, 1):
        lines += [
            f"## {n}. {f.secret_type}",
            "",
            f"- **Found in:** commit `{f.commit[:12]}` ({f.commit_date}) — `{f.file}`",
            f"- **Match:** `{f.matched_text}`",
            "- **Context (helps pair the secret with its key):**",
            "```",
            *[c.rstrip() for c in f.context],
            "```",
            f"- **Suggested action:** {f.suggestion}",
            "",
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Scan a git repo's full history for leaked secrets "
        "(defensive mirror of the GhostAction Oct-2026 history-scanning payload)."
    )
    ap.add_argument("--repo", required=True, help="Path to the git repository to scan")
    ap.add_argument("--output", help="Write the markdown checklist to this file")
    ap.add_argument("--since", help="Only scan commits after this date (e.g. 2025-01-01)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = ap.parse_args(argv)

    findings = dedupe(scan_repo(args.repo, args.since))
    report = render_checklist(findings, args.repo, args.since)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
