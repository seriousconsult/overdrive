#!/usr/bin/env python3
"""Loopback TLS certificate helpers for local browser transport probes."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

__all__ = ["make_localhost_probe_cert"]

_ASSET_DIR = Path(__file__).resolve().parent
_EMBEDDED_CERT = _ASSET_DIR / "localhost_probe.crt"
_EMBEDDED_KEY = _ASSET_DIR / "localhost_probe.key"


def make_localhost_probe_cert(work_dir: Path | str) -> tuple[Path, Path]:
    """
    Write a short-lived 127.0.0.1/localhost cert into ``work_dir``.

    Prefer ``openssl`` when available; otherwise copy the repo-bundled probe
    certificate so Alpine guests without openssl still run HTTP/2 and HTTP/3
    loopback observers.
    """
    dest = Path(work_dir)
    dest.mkdir(parents=True, exist_ok=True)
    cert_path = dest / "localhost.crt"
    key_path = dest / "localhost.key"

    openssl = shutil.which("openssl")
    if openssl:
        try:
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-sha256",
                    "-days",
                    "1",
                    "-nodes",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-subj",
                    "/CN=127.0.0.1",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1,DNS:localhost",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=30,
            )
            return cert_path, key_path
        except (OSError, subprocess.SubprocessError):
            # Fall through to the bundled certificate.
            pass

    if not _EMBEDDED_CERT.is_file() or not _EMBEDDED_KEY.is_file():
        raise RuntimeError(
            "openssl is unavailable and bundled localhost_probe.{crt,key} are missing"
        )
    cert_path.write_bytes(_EMBEDDED_CERT.read_bytes())
    key_path.write_bytes(_EMBEDDED_KEY.read_bytes())
    return cert_path, key_path
