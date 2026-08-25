#!/usr/bin/env python3
"""Run every detection script in detections/network."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.run_detections import run_detection_suite


def main() -> int:
    return run_detection_suite(
        folders=["network"],
        report_name="network_detection_results.html",
        suite_title="OVERDRIVE NETWORK DETECTION SUITE",
    )


if __name__ == "__main__":
    raise SystemExit(main())
