#!/usr/bin/env python3
"""Reject staged files containing IPv4 or IPv6 address literals."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys

IPV4 = re.compile(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
IPV6_CANDIDATE = re.compile(rb"(?<![A-Za-z0-9_])[0-9A-Fa-f:.]+(?![A-Za-z0-9_])")

SAFE_IPS = {
    "8.8.8.8",
    "0.0.0.0",
    "127.0.0.1",
    "169.254.169.254",
    "255.255.255.255",
}

def git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True, check=False)
    if result.returncode:
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        raise RuntimeError(f"git {' '.join(args)} failed")
    return result.stdout


def addresses(data: bytes):
    for number, line in enumerate(data.splitlines(), 1):
        found = set()
        for match in IPV4.finditer(line):
            value = match.group().decode("ascii")
            try:
                ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                continue
            if value in SAFE_IPS:
                continue
            found.add(value)
        for match in IPV6_CANDIDATE.finditer(line):
            token = match.group().decode("ascii").strip(".")
            if token.count(":") < 2:
                continue
            try:
                value = str(ipaddress.IPv6Address(token))
            except ipaddress.AddressValueError:
                continue
            found.add(value)
        for value in sorted(found):
            yield number, value


def main() -> int:
    try:
        paths = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
        violations = []
        for raw_path in filter(None, paths.split(b"\0")):
            path = raw_path.decode("utf-8", "surrogateescape")
            data = git("show", f":{path}")
            for number, value in addresses(data):
                violations.append((path, number, value))
    except RuntimeError as error:
        print(f"IP address check could not run: {error}", file=sys.stderr)
        return 2

    if violations:
        print("Commit blocked: staged files contain IP addresses:", file=sys.stderr)
        for path, number, value in violations[:50]:
            print(f"  {path}:{number}: {value}", file=sys.stderr)
        if len(violations) > 50:
            print(f"  ... and {len(violations) - 50} more matches", file=sys.stderr)
        print("Remove the addresses from the staged files and stage them again.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
