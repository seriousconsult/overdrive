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

from detections.common.browser_logging import (  # noqa: E402
    blog_chromium_event,
    blog_debug,
    blog_error,
    blog_file_tail,
    blog_info,
    blog_probe_end,
    blog_probe_start,
    current_log_path,
    init_browser_log_session,
)
from detections.common.common_browser import prompt_suite_external_browser_access  # noqa: E402
from detections.common.direct_chromium import shared_chromium_session  # noqa: E402
from detections.run_detections import (  # noqa: E402
    BROWSER_SCRIPT_TIMEOUT_SEC,
    collect_browser_detection_results,
    generate_html_report,
    print_results_summary,
    resolve_report_path,
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
            "Run every probe in detections/browser and write detections/browser/browser_detection_results.html."
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
        help="HTML report filename (default: detections/browser/browser_detection_results.html).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=BROWSER_SCRIPT_TIMEOUT_SEC,
        metavar="SEC",
        help=(
            "Long safety expiration while waiting for each probe's completion callback "
            f"(default: {BROWSER_SCRIPT_TIMEOUT_SEC}; use 0 to wait indefinitely)."
        ),
    )
    parser.add_argument(
        "--no-shared-browser",
        action="store_true",
        help=(
            "Cold-start a fresh Chromium for each probe instead of one shared session "
            "(slower on VMs; useful for debugging a single failing probe)."
        ),
    )
    external = parser.add_mutually_exclusive_group()
    external.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow probes that contact the public internet (skip the Y/N prompt).",
    )
    external.add_argument(
        "--deny-external",
        action="store_true",
        help="Skip probes that contact the public internet (skip the Y/N prompt).",
    )
    return parser.parse_args(argv)


def _run_browser_suite(
    *,
    scripts_map: dict[str, list[str]],
    folder_order: list[str],
    report_name: str,
    suite_title: str | None,
    script_timeout: int,
    use_shared_browser: bool,
    allow_external: bool | None,
) -> int:
    start = time.time()
    log_path = init_browser_log_session(label="browser-suite")
    if log_path:
        print(f"[*] Browser debug log: {log_path}")

    from detections.common.common_browser import browser_runtime_diagnostics

    runtime = browser_runtime_diagnostics()
    blog_info("browser runtime", **runtime)

    print("[*] Browser runtime:")
    print(f"    Chromium:     {runtime['chromium']}")
    print(f"    Chromium version:     {runtime['chromium_version']}")
    print()
    if runtime["chromium"] == "(missing)":
        blog_error("browser runtime incomplete", runtime=runtime)
        print(
            "[!] Browser runtime is incomplete. Rebuild/provision the Alpine client image "
            "so build-time install.py can stage Chromium before the VM boots."
        )
        return 2

    browser_scripts: list[str] = []
    for folder in folder_order:
        browser_scripts.extend(scripts_map.get(folder, []))
    prompt_suite_external_browser_access(
        script_names=browser_scripts,
        force=allow_external,
    )

    def _collect_and_report() -> int:
        results = collect_browser_detection_results(
            scripts_map,
            folder_order,
            script_timeout=script_timeout,
        )
        print_results_summary(results, folder_order)
        elapsed = time.time() - start
        html_path = resolve_report_path(report_name, folder_order)
        html_path.parent.mkdir(parents=True, exist_ok=True)
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

    def _with_title() -> None:
        if suite_title:
            print("=" * 60)
            print(suite_title)
            print("=" * 60)
            print()

    if use_shared_browser:
        print("[*] Starting shared Chromium session for browser probes...")
        blog_chromium_event("shared session starting")
        try:
            with shared_chromium_session():
                print("[*] Shared Chromium is ready; probes will attach via DevTools.")
                blog_chromium_event("shared session ready")
                _with_title()
                return _collect_and_report()
        except Exception as exc:
            blog_error("shared chromium failed", exc=exc)
            print(f"[!] Shared Chromium failed to start: {exc}", file=sys.stderr)
            print("[*] Falling back to isolated Chromium launches per probe.")
            use_shared_browser = False

    print("[*] Browser probes will run in isolated Chromium subprocesses.")
    _with_title()
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

    allow_external: bool | None
    if args.allow_external:
        allow_external = True
    elif args.deny_external:
        allow_external = False
    else:
        allow_external = None

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
            use_shared_browser=not args.no_shared_browser,
            allow_external=allow_external,
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
        use_shared_browser=not args.no_shared_browser,
        allow_external=allow_external,
    )


if __name__ == "__main__":
    raise SystemExit(main())
