#!/usr/bin/env python3
"""Run browser detection probes (Selenium / Chromium).

Self-contained under ``detections/`` so it works on the Alpine guest
(``/root/detections``) as well as on the host repo.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.run_detections import (  # noqa: E402
    BROWSER_SCRIPT_TIMEOUT_SEC,
    BASE_DIR,
    collect_detection_results,
    generate_html_report,
    print_results_summary,
    run_detection_suite,
    select_detection_folders,
)


def _normalize_script_name(name: str) -> str:
    return name if name.endswith(".py") else f"{name}.py"


def _list_browser_scripts() -> list[str]:
    scripts_map, folder_order, rc = select_detection_folders(["browser"])
    if rc != 0:
        return []
    return scripts_map.get(folder_order[0], []) if folder_order else []


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run every probe in detections/browser and write browser_detection_results.html."
        ),
    )
    parser.add_argument(
        "--script",
        metavar="NAME",
        help="Run one probe (e.g. cookie_tracking or cookie_tracking.py).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List browser probe script names and exit.",
    )
    parser.add_argument(
        "--report-name",
        default="browser_detection_results.html",
        help="HTML report filename (default: browser_detection_results.html).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=BROWSER_SCRIPT_TIMEOUT_SEC,
        metavar="SEC",
        help=f"Per-probe subprocess timeout (default: {BROWSER_SCRIPT_TIMEOUT_SEC}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.list:
        scripts = _list_browser_scripts()
        if not scripts:
            print("No browser detection scripts found.", file=sys.stderr)
            return 2
        for name in scripts:
            print(name)
        return 0

    if args.script:
        script_name = _normalize_script_name(args.script)
        scripts_map, folder_order, rc = select_detection_folders(["browser"])
        if rc != 0:
            return rc
        available = scripts_map.get("browser", [])
        if script_name not in available:
            print(
                f"Unknown browser probe: {script_name}\n"
                f"Available: {', '.join(available)}",
                file=sys.stderr,
            )
            return 2
        scripts_map["browser"] = [script_name]

        print("=" * 60)
        print("OVERDRIVE BROWSER DETECTION SUITE")
        print("=" * 60)
        print()

        start = time.time()
        results = collect_detection_results(
            scripts_map,
            folder_order,
            script_timeout=args.timeout,
        )
        elapsed = time.time() - start
        print_results_summary(results, folder_order)

        html_path = BASE_DIR / args.report_name
        html_path.write_text(
            generate_html_report(results, folder_order, elapsed_time=elapsed),
            encoding="utf-8",
        )
        minutes, seconds = divmod(int(elapsed), 60)
        print(f"\nHTML report: {html_path}")
        print(f"Elapsed: {minutes}m {seconds}s")
        return 0

    return run_detection_suite(
        folders=["browser"],
        report_name=args.report_name,
        suite_title="OVERDRIVE BROWSER DETECTION SUITE",
        script_timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
