#!/usr/bin/env python3
"""Run browser detection probes through Chromium.

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
    collect_browser_detection_results,
    generate_html_report,
    print_results_summary,
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


def _run_browser_suite(
    *,
    scripts_map: dict[str, list[str]],
    folder_order: list[str],
    report_name: str,
    suite_title: str | None,
    script_timeout: int,
) -> int:
    start = time.time()
    from detections.common.common_browser import browser_runtime_diagnostics

    runtime = browser_runtime_diagnostics()

    print("[*] Browser runtime:")
    print(f"    Chromium:     {runtime['chromium']}")
    print(f"    Chromium version:     {runtime['chromium_version']}")
    print()
    if runtime["chromium"] == "(missing)":
        print(
            "[!] Browser runtime is incomplete. Rebuild/provision the Alpine client image "
            "so build-time install.py can stage Chromium before the VM boots."
        )
        return 2

    def _collect_and_report() -> int:
        results = collect_browser_detection_results(
            scripts_map,
            folder_order,
            script_timeout=script_timeout,
        )
        print_results_summary(results, folder_order)
        elapsed = time.time() - start
        html_path = BASE_DIR / report_name
        html_path.write_text(
            generate_html_report(results, folder_order, elapsed_time=elapsed),
            encoding="utf-8",
        )
        minutes, seconds = divmod(int(elapsed), 60)
        print(f"\nHTML report: {html_path}")
        print(f"Elapsed: {minutes}m {seconds}s")
        has_errors = any(
            str(score).lower() == "error"
            for rows in results.values()
            for _script_name, score, _comment in rows
        )
        return 2 if has_errors else 0

    print("[*] Browser probes will run in isolated Chromium subprocesses.")

    if suite_title:
        print("=" * 60)
        print(suite_title)
        print("=" * 60)
        print()
    return _collect_and_report()


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

        return _run_browser_suite(
            scripts_map=scripts_map,
            folder_order=folder_order,
            report_name=args.report_name,
            suite_title=None,
            script_timeout=args.timeout,
        )

    scripts_map, folder_order, rc = select_detection_folders(["browser"])
    if rc != 0:
        return rc

    return _run_browser_suite(
        scripts_map=scripts_map,
        folder_order=folder_order,
        report_name=args.report_name,
        suite_title="OVERDRIVE BROWSER DETECTION SUITE",
        script_timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
