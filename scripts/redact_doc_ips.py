#!/usr/bin/env python3
"""Replace IP literals in staged documentation and its working-tree copy."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

from check_staged_ips import IPV4, IPV6_CANDIDATE, addresses

ALIAS = re.compile(rb"\b(IPv[46])-(\d+)\b")


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=root, input=data, capture_output=True, check=False
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def is_document(path: str) -> bool:
    name = Path(path).name.lower()
    return name.startswith("readme") or Path(path).suffix.lower() in {
        ".md", ".rst", ".adoc"
    } or (path.startswith("docs/") and Path(path).suffix.lower() == ".txt")


class Redactor:
    def __init__(self, documents: list[bytes]) -> None:
        self.aliases: dict[tuple[str, str], bytes] = {}
        self.next_number = {"IPv4": 1, "IPv6": 1}
        for document in documents:
            for match in ALIAS.finditer(document):
                kind = match.group(1).decode("ascii")
                self.next_number[kind] = max(
                    self.next_number[kind], int(match.group(2)) + 1
                )

    def alias(self, kind: str, address: str) -> bytes:
        key = kind, address
        if key not in self.aliases:
            number = self.next_number[kind]
            self.next_number[kind] += 1
            self.aliases[key] = f"{kind}-{number}".encode("ascii")
        return self.aliases[key]

    def redact(self, data: bytes) -> bytes:
        def replace_v6(match: re.Match[bytes]) -> bytes:
            token = match.group().decode("ascii").strip(".")
            if token.count(":") < 2:
                return match.group()
            try:
                address = str(ipaddress.IPv6Address(token))
            except ipaddress.AddressValueError:
                return match.group()
            return self.alias("IPv6", address)

        def replace_v4(match: re.Match[bytes]) -> bytes:
            token = match.group().decode("ascii")
            try:
                address = str(ipaddress.IPv4Address(token))
            except ipaddress.AddressValueError:
                return match.group()
            return self.alias("IPv4", address)

        return IPV4.sub(replace_v4, IPV6_CANDIDATE.sub(replace_v6, data))


def staged_mode(root: Path, path: str) -> str:
    record = git(root, "ls-files", "--stage", "-z", "--", path).split(b"\0")[0]
    metadata, _, indexed_path = record.partition(b"\t")
    if indexed_path.decode("utf-8", "surrogateescape") != path:
        raise RuntimeError(f"Could not read staged file mode for {path}")
    mode, _, stage = metadata.split(b" ")
    if stage != b"0":
        raise RuntimeError(f"Cannot redact unmerged file {path}")
    return mode.decode("ascii")


def main() -> int:
    try:
        root = Path(os.fsdecode(git(Path.cwd(), "rev-parse", "--show-toplevel").strip()))
        names = git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
        paths = [
            raw.decode("utf-8", "surrogateescape")
            for raw in names.split(b"\0")
            if raw and is_document(raw.decode("utf-8", "surrogateescape"))
        ]
        staged = {path: git(root, "show", f":{path}") for path in paths}
        worktrees = {
            path: (root / path).read_bytes()
            for path in paths
            if (root / path).is_file() and not (root / path).is_symlink()
        }
        redactor = Redactor([*staged.values(), *worktrees.values()])
        changed: list[str] = []
        for path, original in staged.items():
            replacement = redactor.redact(original)
            if any(addresses(replacement)):
                raise RuntimeError(f"Could not redact every address in {path}")
            if path in worktrees:
                worktree_path = root / path
                worktree_original = worktrees[path]
                worktree_replacement = redactor.redact(worktree_original)
                if worktree_replacement != worktree_original:
                    worktree_path.write_bytes(worktree_replacement)
            if replacement == original:
                continue
            mode = staged_mode(root, path)
            oid = git(root, "hash-object", "-w", "--stdin", data=replacement).strip().decode("ascii")
            git(root, "update-index", "--cacheinfo", mode, oid, path)
            changed.append(path)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Documentation IP redaction failed: {error}", file=sys.stderr)
        return 2

    if changed:
        print("Redacted IP addresses from staged documentation: " + ", ".join(changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
