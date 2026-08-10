#!/usr/bin/env python3
"""Repository identity/secret hygiene scanner.

This intentionally scans every file under the repository root, including hidden
directories, caches, virtualenvs, generated reports, and binary artifacts. Binary
content is scanned as bytes and reported with byte offsets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import tempfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
CHUNK_SIZE = 1024 * 1024
OVERLAP_SIZE = 4096
DEFAULT_MAX_WORKERS = 8
_WORKER_ROOT: Path | None = None
_WORKER_RULES: list["Rule"] | None = None


@dataclass(frozen=True)
class Rule:
    name: str
    severity: int
    pattern: re.Pattern[bytes]
    description: str
    redact: bool = True


@dataclass
class Finding:
    severity: int
    rule: str
    description: str
    path: str
    line: int | None
    offset: int | None
    value: str
    context: str


def _bregex(pattern: str, flags: int = 0) -> re.Pattern[bytes]:
    return re.compile(pattern.encode("utf-8"), flags)


def _regex_for_literal(value: str) -> bytes:
    return rb"(?<![A-Za-z0-9_.-])" + re.escape(value.encode("utf-8")) + rb"(?![A-Za-z0-9_.-])"


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").replace("\x00", "\\0")


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[:1] + "***" + value[-1:] if len(value) > 2 else "***"
    return value[:4] + "***" + value[-4:]


def _context(raw: bytes, start: int, end: int, *, width: int = 80) -> str:
    left = max(0, start - width)
    right = min(len(raw), end + width)
    text = _decode(raw[left:right])
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 180:
        return text[:177] + "..."
    return text


def _line_number(chunk: bytes, start: int, line_base: int) -> int:
    return line_base + chunk.count(b"\n", 0, start)


def _is_public_ipv4_text(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    if any(num < 0 or num > 255 for num in nums):
        return False
    first, second = nums[0], nums[1]
    if first == 10 or first == 127 or first == 0:
        return False
    if first == 169 and second == 254:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first >= 224:
        return False
    return True


def _local_identity_rules() -> list[Rule]:
    values: set[str] = set()
    for key in ("USER", "LOGNAME", "USERNAME"):
        value = (os.environ.get(key) or "").strip()
        if value and value.lower() not in {"root", "user", "runner"}:
            values.add(value)
    for candidate in (
        socket.gethostname(),
        os.environ.get("HOSTNAME", ""),
        str(Path.home()),
        Path.home().name,
    ):
        candidate = (candidate or "").strip()
        if candidate and candidate not in {"/", ".", "root"}:
            values.add(candidate)

    rules: list[Rule] = []
    for value in sorted(values, key=lambda item: (item.lower(), item)):
        if len(value) < 3:
            continue
        rules.append(
            Rule(
                name="local-identity-token",
                severity=4,
                pattern=re.compile(_regex_for_literal(value), re.I),
                description=f"local username/hostname/path token {value!r}",
                redact=False,
            )
        )
    return rules


def _pem_begin_marker(*parts: str) -> re.Pattern[bytes]:
    """Build a PEM BEGIN regex without storing a live header literal in this file."""
    return _bregex("".join(parts))


def build_rules() -> list[Rule]:
    # Split PEM headers so this scanner does not match its own rule source.
    private_key_marker = _pem_begin_marker("-----BEGIN ", r"[A-Z0-9 ]*PRIVATE KEY", "-----")
    openssh_private_key = _pem_begin_marker("-----BEGIN ", "OPENSSH PRIVATE KEY", "-----")
    rules = [
        Rule("private-key-marker", 5, private_key_marker, "private key material marker", redact=False),
        Rule("openssh-private-key", 5, openssh_private_key, "OpenSSH private key marker", redact=False),
        Rule("aws-access-key", 5, _bregex(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS access key id"),
        Rule("github-token", 5, _bregex(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"), "GitHub token"),
        Rule("slack-token", 5, _bregex(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
        Rule("google-api-key", 5, _bregex(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
        Rule("generic-secret-assignment", 5, _bregex(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|credential|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"), "secret-like assignment"),
        Rule("email-address", 4, _bregex(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "email address"),
        Rule("ssh-public-key", 4, _bregex(r"\bssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{40,}"), "SSH public key"),
        Rule("mac-address", 4, _bregex(r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b", re.I), "MAC address"),
        Rule("public-ipv4", 4, _bregex(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "public IPv4 address"),
        Rule("ipv6-address", 4, _bregex(r"\b(?:[0-9A-F]{1,4}:){2,7}[0-9A-F]{0,4}\b", re.I), "IPv6 address"),
        Rule("windows-user-path", 4, _bregex(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"']+"), "Windows user profile path", redact=False),
        Rule("wsl-user-path", 4, _bregex(r"/mnt/[a-z]/Users/[^/\s\"']+", re.I), "WSL Windows user profile path", redact=False),
        Rule("unix-home-path", 4, _bregex(r"/home/[^/\s\"']+"), "Unix home path", redact=False),
        Rule("macos-home-path", 4, _bregex(r"/Users/[^/\s\"']+"), "macOS home path", redact=False),
        Rule("phone-number", 3, _bregex(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s][2-9]\d{2}[-.\s]\d{4}\b"), "phone-number-shaped text"),
        Rule("url", 3, _bregex(r"\bhttps?://[^\s\"'<>]+", re.I), "URL"),
        Rule("bare-domain", 2, _bregex(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|local|lan|internal|corp|home)\b", re.I), "domain/hostname-like string"),
        Rule("lab-client-name", 4, _bregex(r"(?i)\b(?:my-alpine-client|openwrt[_-]?lan[_-]?client|client[_-]?vm|lab[_-]?client|test[_-]?client|overdrive)\b"), "lab/client identifying name", redact=False),
        Rule("virtualbox-vm-name", 4, _bregex(r"(?i)\b(?:OpenWrt_2026_Router|OpenWrt_LAN_Client|VirtualBox VMs)\b"), "VM/lab name", redact=False),
    ]
    return _local_identity_rules() + rules


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, _dirs, names in os.walk(root, topdown=True, followlinks=False):
        base = Path(current_root)
        for name in names:
            files.append(base / name)
    files.sort(key=lambda path: str(path.relative_to(root)).lower())
    return files


def _path_findings(path: Path, rel: str, rules: list[Rule]) -> list[Finding]:
    raw = rel.encode("utf-8", errors="replace")
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.pattern.finditer(raw):
            value = _decode(match.group(0))
            findings.append(
                Finding(
                    severity=rule.severity,
                    rule=rule.name,
                    description=rule.description,
                    path=rel,
                    line=None,
                    offset=None,
                    value=_redact(value) if rule.redact else value,
                    context=f"path: {rel}",
                )
            )
    return findings


def _content_findings(path: Path, rel: str, rules: list[Rule]) -> tuple[list[Finding], str | None, int]:
    findings: list[Finding] = []
    note: str | None = None
    total_bytes = 0
    line_base = 1
    offset_base = 0
    previous = b""

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                scan_chunk = previous + chunk
                scan_start = len(previous)

                for rule in rules:
                    for match in rule.pattern.finditer(scan_chunk):
                        if match.start() < scan_start:
                            continue
                        value = _decode(match.group(0))
                        if rule.name == "public-ipv4" and not _is_public_ipv4_text(value):
                            continue
                        absolute_offset = offset_base + match.start() - len(previous)
                        line = _line_number(chunk, match.start() - len(previous), line_base)
                        findings.append(
                            Finding(
                                severity=rule.severity,
                                rule=rule.name,
                                description=rule.description,
                                path=rel,
                                line=line,
                                offset=absolute_offset,
                                value=_redact(value) if rule.redact else value,
                                context=_context(scan_chunk, match.start(), match.end()),
                            )
                        )

                line_base += chunk.count(b"\n")
                offset_base += len(chunk)
                previous = scan_chunk[-OVERLAP_SIZE:]
    except OSError as exc:
        note = f"{type(exc).__name__}: {exc}"

    return findings, note, total_bytes


def _scan_one_file(path: Path, root: Path, rules: list[Rule]) -> tuple[list[Finding], str | None, int]:
    rel = str(path.relative_to(root))
    all_findings = _path_findings(path, rel, rules)
    findings, note, size = _content_findings(path, rel, rules)
    all_findings.extend(findings)
    read_error = f"{rel}: {note}" if note else None
    return all_findings, read_error, size


def _init_scan_worker(root: str) -> None:
    global _WORKER_ROOT, _WORKER_RULES
    _WORKER_ROOT = Path(root)
    _WORKER_RULES = build_rules()


def _scan_file_worker(path: str) -> tuple[list[Finding], str | None, int]:
    if _WORKER_ROOT is None or _WORKER_RULES is None:
        raise RuntimeError("dirty_words worker was not initialized")
    return _scan_one_file(Path(path), _WORKER_ROOT, _WORKER_RULES)


def default_jobs() -> int:
    cpu_count = os.cpu_count() or 1
    return max(1, min(DEFAULT_MAX_WORKERS, cpu_count))


def scan_repo(root: Path, rules: list[Rule], jobs: int) -> tuple[list[Finding], list[str], int, int]:
    all_findings: list[Finding] = []
    read_errors: list[str] = []
    files = iter_files(root)
    total_bytes = 0

    if jobs <= 1 or len(files) <= 1:
        for path in files:
            findings, note, size = _scan_one_file(path, root, rules)
            total_bytes += size
            all_findings.extend(findings)
            if note:
                read_errors.append(note)
    else:
        chunksize = max(1, min(64, len(files) // (jobs * 4) if jobs else 1))
        with ProcessPoolExecutor(
            max_workers=jobs,
            initializer=_init_scan_worker,
            initargs=(str(root),),
        ) as pool:
            for findings, note, size in pool.map(
                _scan_file_worker,
                (str(path) for path in files),
                chunksize=chunksize,
            ):
                total_bytes += size
                all_findings.extend(findings)
                if note:
                    read_errors.append(note)

    all_findings.sort(key=lambda f: (-f.severity, f.path.lower(), f.line or -1, f.offset or -1, f.rule))
    return all_findings, read_errors, len(files), total_bytes


def score_findings(findings: list[Finding], read_errors: list[str]) -> tuple[int, str]:
    if not findings:
        if read_errors:
            return 3, f"No identifying strings found, but {len(read_errors)} file(s) could not be read."
        return 1, "No possibly identifying strings found."

    max_sev = max(f.severity for f in findings)
    if max_sev >= 5:
        return 5, f"High-confidence secret or credential-like material found ({len(findings)} total finding(s))."
    if max_sev == 4:
        return 4, f"Identifying local/user/network/lab data found ({len(findings)} total finding(s))."
    if max_sev == 3:
        return 3, f"Possibly identifying contact, URL, or metadata strings found ({len(findings)} total finding(s))."
    return 2, f"Low-confidence domain/hostname-like identifying strings found ({len(findings)} total finding(s))."


def _finding_location(finding: Finding) -> str:
    loc = finding.path
    if finding.line is not None:
        return f"{loc}:{finding.line}"
    if finding.offset is not None:
        return f"{loc}@{finding.offset}"
    return loc


def _format_finding(finding: Finding) -> list[str]:
    lines = [f"- sev={finding.severity} rule={finding.rule} {_finding_location(finding)}"]
    lines.append(f"  value: {finding.value}")
    lines.append(f"  note:  {finding.description}")
    if finding.context:
        lines.append(f"  ctx:   {finding.context}")
    return lines


def _default_detail_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(tempfile.gettempdir()) / "overdrive_dirty_words" / f"dirty_words_detail_{stamp}.txt"


def write_detail_report(
    path: Path,
    findings: list[Finding],
    read_errors: list[str],
    file_count: int,
    total_bytes: int,
    score: int,
    status: str,
    jobs: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    by_rule = Counter(f.rule for f in findings)
    by_sev = Counter(f.severity for f in findings)
    by_file = Counter(f.path for f in findings)

    lines: list[str] = []
    lines.append("=== Dirty Words / Identity Hygiene Scan: Full Detail ===")
    lines.append(f"Root: {REPO_ROOT}")
    lines.append("Scope: every file under the repository root; no directory, cache, hidden file, or binary artifact is skipped.")
    lines.append(f"Files scanned: {file_count}")
    lines.append(f"Bytes scanned: {total_bytes}")
    lines.append(f"Findings: {len(findings)}")
    lines.append(f"Workers: {jobs}")
    lines.append(f"SCORE: {score}")
    lines.append(f"STATUS: {status}")

    if by_sev:
        lines.append("")
        lines.append("Findings by severity:")
        for sev in sorted(by_sev, reverse=True):
            lines.append(f"  severity {sev}: {by_sev[sev]}")
    if by_rule:
        lines.append("")
        lines.append("Findings by rule:")
        for rule, count in by_rule.most_common():
            lines.append(f"  {rule}: {count}")
    if by_file:
        lines.append("")
        lines.append("Findings by file:")
        for file_name, count in by_file.most_common():
            lines.append(f"  {file_name}: {count}")

    lines.append("")
    lines.append("All findings:")
    if findings:
        for finding in findings:
            lines.extend(_format_finding(finding))
    else:
        lines.append("none")

    if read_errors:
        lines.append("")
        lines.append("Read errors:")
        lines.extend(f"- {item}" for item in read_errors)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_report(
    findings: list[Finding],
    read_errors: list[str],
    file_count: int,
    total_bytes: int,
    max_findings: int,
    detail_path: Path,
    score: int,
    status: str,
    jobs: int,
) -> None:
    print("=== Dirty Words / Identity Hygiene Scan ===")
    print(f"Root: {REPO_ROOT}")
    print("Scope: every file under the repository root; no directory, cache, hidden file, or binary artifact is skipped.")
    print(f"Files scanned: {file_count}")
    print(f"Bytes scanned: {total_bytes}")
    print(f"Findings: {len(findings)}")
    print(f"Workers: {jobs}")

    by_rule = Counter(f.rule for f in findings)
    by_sev = Counter(f.severity for f in findings)
    if by_sev:
        print("\nFindings by severity:")
        for sev in sorted(by_sev, reverse=True):
            print(f"  severity {sev}: {by_sev[sev]}")
    if by_rule:
        print("\nTop rules:")
        for rule, count in by_rule.most_common(12):
            print(f"  {rule}: {count}")

    by_file = Counter(f.path for f in findings)
    if by_file:
        print("\nTop files:")
        for file_name, count in by_file.most_common(12):
            print(f"  {file_name}: {count}")

    shown = findings if max_findings == 0 else findings[:max_findings]
    if shown:
        print("\nHighest-severity examples:")
        for finding in shown:
            for line in _format_finding(finding):
                print(line)
    else:
        print("\nHighest-severity examples: none")

    if max_findings and len(findings) > max_findings:
        print(f"\n[!] Console examples capped at {max_findings} finding(s). Full detail is in the report file.")

    if read_errors:
        print("\nRead errors:")
        for item in read_errors[:25]:
            print(f"- {item}")
        if len(read_errors) > 25:
            print(f"- ... {len(read_errors) - 25} more")

    print(f"\nDetailed report: {detail_path}")
    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print(f"DETAILS: {detail_path}")


def write_json(path: Path, findings: list[Finding], read_errors: list[str], score: int, status: str, file_count: int, total_bytes: int, jobs: int) -> None:
    payload = {
        "score": score,
        "status": status,
        "files_scanned": file_count,
        "bytes_scanned": total_bytes,
        "workers": jobs,
        "read_errors": read_errors,
        "findings": [asdict(finding) for finding in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan the whole repository for possibly identifying strings.")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=5,
        help="Maximum example findings to print in the console; 0 prints all. Default: 5.",
    )
    parser.add_argument(
        "--detail-file",
        type=Path,
        default=None,
        help="Full text report path. Default: timestamped file under the system temp directory.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        help=f"Worker processes for file scanning. 0=auto, 1=sequential. Default: 0 (auto up to {DEFAULT_MAX_WORKERS}).",
    )
    parser.add_argument("--json", type=Path, default=None, help="Optional full JSON report path.")
    args = parser.parse_args()

    jobs = default_jobs() if args.jobs <= 0 else args.jobs
    rules = build_rules()
    findings, read_errors, file_count, total_bytes = scan_repo(REPO_ROOT, rules, jobs)
    score, status = score_findings(findings, read_errors)
    detail_path = args.detail_file or _default_detail_path()
    write_detail_report(detail_path, findings, read_errors, file_count, total_bytes, score, status, jobs)
    print_report(
        findings,
        read_errors,
        file_count,
        total_bytes,
        args.max_findings,
        detail_path,
        score,
        status,
        jobs,
    )
    if args.json:
        write_json(args.json, findings, read_errors, score, status, file_count, total_bytes, jobs)
        print(f"\n[+] Wrote JSON report: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
