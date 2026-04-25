#!/usr/bin/env python3
"""
Parent script that runs all detection scripts and outputs scores.

Discovers scripts dynamically: root-level *.py (except this runner and
virtual_env_setup.py) plus *.py in each immediate subfolder (skipping
virtual_env, .git, etc.). Section order: Root first, then subfolders A–Z.

Outputs to console and generates a compact HTML report.

Scripts whose source contains a TODO marker (word TODO) are not executed;
they are reported as score 0 with comment "TODO:".

TCP_stack.py runs via ``sudo -n`` (non-interactive). Configure NOPASSWD for your user
in WSL/Linux, or that step will fail with a clear error in the report.
"""

import html
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Longer capture + scapy startup
SUDO_SCRIPT_TIMEOUT_SEC = 180

# Base directory
BASE_DIR = Path(__file__).parent

# Root-level .py files to skip (runner / tooling, not detection modules)
EXCLUDE_ROOT_SCRIPTS = frozenset({"run_all_detections.py", "virtual_env_setup.py"})

# Subdirectories under BASE_DIR to skip when auto-discovering
SKIP_SUBDIRS = frozenset(
    {"virtual_env", ".git", "__pycache__", ".venv", "node_modules", ".idea", ".vscode"}
)

# Scripts that need sudo (run with elevated privileges)
SUDO_SCRIPTS = {"TCP_stack.py"}


def discover_detection_scripts() -> tuple[dict[str, list[str]], list[str]]:
    """
    Build folder -> sorted list of *.py script names from disk.
    Root = BASE_DIR/*.py (excluding EXCLUDE_ROOT_SCRIPTS).
    Other folders = immediate subdirs (except SKIP_SUBDIRS) that contain at least one *.py.
    """
    scripts: dict[str, list[str]] = {}

    root_py = sorted(
        p.name
        for p in BASE_DIR.glob("*.py")
        if p.is_file() and p.name not in EXCLUDE_ROOT_SCRIPTS
    )
    scripts["root"] = root_py

    for child in sorted(BASE_DIR.iterdir(), key=lambda x: x.name.lower()):
        if not child.is_dir():
            continue
        if child.name.startswith(".") or child.name in SKIP_SUBDIRS:
            continue
        py_files = sorted(p.name for p in child.glob("*.py") if p.is_file())
        if not py_files:
            continue
        scripts[child.name] = py_files

    order = ["root"] + sorted((k for k in scripts if k != "root"), key=str.lower)
    return scripts, order

TODO_PATTERN = re.compile(r"\bTODO\b")

# Try to find Python - check WSL first, then local virtual env
VENV_PYTHON = None

try:
    result = subprocess.run(
        ["wsl", "-d", "Ubuntu-24.04", "which", "python3"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode == 0 and result.stdout.strip():
        wsl_python = result.stdout.strip()
        VENV_PYTHON = ["wsl", "-d", "Ubuntu-24.04", wsl_python]
except OSError:
    pass

if not VENV_PYTHON:
    local_py = BASE_DIR / "virtual_env" / "bin" / "python"
    if local_py.exists():
        VENV_PYTHON = [str(local_py)]

if not VENV_PYTHON:
    VENV_PYTHON = [sys.executable]


def script_path_for(folder: str, script_name: str) -> Path:
    if folder == "root":
        return BASE_DIR / script_name
    return BASE_DIR / folder / script_name


def _to_wsl_posix(path: Path) -> str:
    """Windows C:\\path → /mnt/c/path; POSIX paths unchanged (slashes normalized)."""
    try:
        s = str(path.resolve())
    except OSError:
        s = str(path.absolute())
    if len(s) >= 2 and s[1] == ":" and s[0].isalpha():
        return "/mnt/" + s[0].lower() + s[2:].replace("\\", "/")
    return s.replace("\\", "/")


def _wsl_invocation_prefix() -> list[str] | None:
    """
    If VENV_PYTHON is ['wsl', '-d', '<distro>', '<python_in_distro>'], return ['wsl', '-d', '<distro>'].
    """
    vp = VENV_PYTHON
    if (
        len(vp) >= 4
        and vp[0].lower() == "wsl"
        and vp[1] == "-d"
        and not vp[2].startswith("-")
    ):
        return [vp[0], vp[1], vp[2]]
    return None


def script_has_todo(script_path: Path) -> bool:
    try:
        text = script_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return TODO_PATTERN.search(text) is not None


def run_script(script_path: Path, use_sudo: bool = False) -> tuple[str, str, int]:
    """Run a script and return (output, error, returncode)."""
    timeout = SUDO_SCRIPT_TIMEOUT_SEC if use_sudo else 120
    try:
        script_str = str(script_path)
        linux_venv = BASE_DIR / "virtual_env" / "bin" / "python"

        if use_sudo:
            wsl_script = _to_wsl_posix(script_path)
            wsl_venv = _to_wsl_posix(linux_venv)

            if not linux_venv.is_file():
                return (
                    "",
                    "TCP_stack needs virtual_env/bin/python (Linux/WSL venv). "
                    "Windows-only venv (Scripts\\python.exe) cannot run Scapy capture.",
                    -1,
                )

            wsl_prefix = _wsl_invocation_prefix()
            if wsl_prefix:
                # Same distro as normal runs: sudo -n must be passwordless in that distro
                cmd = wsl_prefix + ["-e", "sudo", "-n", wsl_venv, wsl_script]
            elif sys.platform == "win32":
                cmd = ["wsl", "-e", "sudo", "-n", wsl_venv, wsl_script]
            else:
                cmd = ["sudo", "-n", str(linux_venv.resolve()), str(script_path.resolve())]
        else:
            cmd = VENV_PYTHON + [script_str]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(BASE_DIR),
        )
        output = (result.stdout or "") + (result.stderr or "")
        err = ""
        if use_sudo and result.returncode != 0:
            ol = output.lower()
            if "password" in ol and ("sudo" in ol or "a password is required" in ol):
                err = "sudo needs a password; allow NOPASSWD for this user to run TCP_stack unattended"
            else:
                err = "sudo or capture failed (see output; Scapy usually needs root)"
        return output, err, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except OSError as e:
        return "", str(e), -1


def extract_score(output: str) -> tuple[str, str]:
    """Extract score and short comment from script stdout/stderr."""
    score = "N/A"
    comment = ""
    lines = output.splitlines()

    matches: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = re.search(r"\bSCORE:\s*(\d+)", line, re.I)
        if m:
            matches.append((i, m.group(1)))
            continue
        m = re.search(r"^Score:\s*(\d+)\s*", line.strip(), re.I)
        if m:
            matches.append((i, m.group(1)))

    if matches:
        last_idx, score = matches[-1]
        for j in range(last_idx + 1, min(last_idx + 5, len(lines))):
            t = lines[j].strip()
            if not t:
                continue
            if t.startswith("- ") and len(t) < 220:
                comment = t[2:].strip()
                break
            if t.startswith("(") and t.endswith(")") and len(t) < 220:
                comment = t.strip("() ")
                break
            if any(k in t for k in ("STATUS:", "Status:", "Verdict:", "RESULT:")):
                comment = t
                break
            if len(t) < 180 and not t.startswith("---"):
                comment = t
                break

    if comment == "":
        for line in lines:
            if "STATUS:" in line.upper() or "MISMATCH" in line.upper():
                comment = line.strip()
                break
            if "CONSISTENT" in line.upper() or "SUSPICIOUS" in line.upper():
                comment = line.strip()
                break

    return score, comment


def _badge_class(score: str) -> str:
    if score == "Error":
        return "badge err"
    if score == "N/A":
        return "badge na"
    if score == "0":
        return "badge todo"
    if score.isdigit():
        n = int(score)
        return f"badge n{n}"
    return "badge na"


def generate_html_report(results: dict, folder_order: list[str]) -> str:
    """Generate compact HTML report (tables, escaped text)."""
    ts = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    parts = [
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Overdrive Detection Results</title>
<style>
:root {
  --bg: #0f1419;
  --surface: #1a2332;
  --border: #2d3a4d;
  --text: #e7ecf3;
  --muted: #8b9cb3;
  --accent: #3d9eff;
}
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", system-ui, sans-serif;
  margin: 0;
  padding: 1.25rem 1.5rem 2rem;
  background: var(--bg);
  color: var(--text);
  line-height: 1.45;
  font-size: 14px;
}
header {
  max-width: 960px;
  margin: 0 auto 1rem;
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.75rem;
}
h1 {
  margin: 0;
  font-size: 1.35rem;
  font-weight: 600;
  color: var(--accent);
  letter-spacing: -0.02em;
}
.timestamp { color: var(--muted); font-size: 0.8rem; }
main { max-width: 960px; margin: 0 auto; }
section { margin-bottom: 1.5rem; }
h2 {
  margin: 0 0 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}
table {
  width: 100%;
  table-layout: fixed;
  border-collapse: collapse;
  background: var(--surface);
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--border);
}
th, td {
  text-align: left;
  padding: 0.45rem 0.65rem;
  vertical-align: top;
}
th:nth-child(1), td:nth-child(1) { width: 32%; }
th:nth-child(2), td:nth-child(2) { width: 5.5rem; }
th:nth-child(3), td:nth-child(3) { width: auto; }
th {
  background: rgba(0,0,0,0.25);
  color: var(--muted);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 600;
}
tr:not(:last-child) td { border-bottom: 1px solid var(--border); }
.script { font-family: ui-monospace, monospace; font-size: 0.85rem; color: #b8d4ff; }
.comment {
  color: var(--muted);
  font-size: 0.8rem;
  word-break: break-word;
  overflow-wrap: anywhere;
}
.badge {
  display: inline-block;
  min-width: 2rem;
  text-align: center;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  font-weight: 600;
  font-size: 0.8rem;
}
.badge.na { background: #3d4555; color: #c5cdd8; }
.badge.err { background: #5c2a2a; color: #ffb4b4; }
.badge.todo { background: #4a3d6b; color: #d4c4ff; }
.badge.n1 { background: #1e4d2b; color: #9fe3b4; }
.badge.n2 { background: #2d4a3a; color: #a8e0c0; }
.badge.n3 { background: #3d4a5c; color: #c5d4e8; }
.badge.n4 { background: #5c4a2a; color: #ffd89a; }
.badge.n5 { background: #5c3a2a; color: #ffb89a; }
</style>
</head>
<body>
<header>
  <h1>Overdrive detection results</h1>
  <span class="timestamp">""",
        ts,
        """</span>
</header>
<main>
""",
    ]

    def section_title(folder_key: str) -> str:
        if folder_key == "root":
            return "Root"
        return folder_key.replace("_", " ").strip().title() or folder_key

    for folder in folder_order:
        rows = results.get(folder) or []
        if not rows:
            continue
        parts.append(f'<section>\n<h2>{html.escape(section_title(folder))}</h2>\n')
        parts.append(
            "<table>"
            "<colgroup><col><col><col></colgroup>"
            "<thead><tr><th>Script</th><th>Score</th><th>Comment</th></tr></thead><tbody>\n"
        )
        for script_name, score, comment in rows:
            bc = _badge_class(str(score))
            esc_name = html.escape(script_name)
            esc_score = html.escape(str(score))
            esc_comment = html.escape(comment) if comment else "—"
            parts.append(
                f"<tr><td class=\"script\">{esc_name}</td>"
                f"<td><span class=\"badge {bc}\">{esc_score}</span></td>"
                f"<td class=\"comment\">{esc_comment}</td></tr>\n"
            )
        parts.append("</tbody></table>\n</section>\n")

    parts.append("</main>\n</body>\n</html>")
    return "".join(parts)


def main():
    print("=" * 60)
    print("OVERDRIVE DETECTION SUITE")
    print("=" * 60)
    print()

    scripts_map, folder_order = discover_detection_scripts()

    results: dict[str, list] = {k: [] for k in folder_order}

    for folder in folder_order:
        script_names = scripts_map.get(folder, [])
        if not script_names:
            continue

        print(f"\n{'=' * 40}")
        print(f"FOLDER: {folder.upper()}")
        print(f"{'=' * 40}")

        for script_name in script_names:
            script_path = script_path_for(folder, script_name)

            print(f"\n▶ {script_name}...")

            if not script_path.exists():
                print(f"  ⚠️  Not found: {script_path}")
                results[folder].append((script_name, "N/A", "Script not found"))
                continue

            if script_has_todo(script_path):
                print("  ⏭️  Contains TODO — skipped (score 0)")
                results[folder].append((script_name, "0", "TODO:"))
                continue

            use_sudo = script_name in SUDO_SCRIPTS
            if use_sudo:
                print("  (running with sudo -n — needs passwordless sudo in WSL/Linux)")

            output, error, returncode = run_script(script_path, use_sudo=use_sudo)

            if error or returncode != 0:
                detail = error or "Non-zero exit"
                tail = (output or "").strip().splitlines()
                hint = ""
                if tail:
                    hint = " | " + tail[-1][-200:]
                print(f"  ❌ {detail}{hint}")
                results[folder].append(
                    (script_name, "Error", (detail + (hint or ""))[:500])
                )
            else:
                score, comment = extract_score(output)
                print(f"  ✓ Score: {score}")
                if comment:
                    print(f"    → {comment[:100]}")
                results[folder].append((script_name, score, comment))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for folder in folder_order:
        if folder not in results or not results[folder]:
            continue
        print(f"\n{folder.upper()}:")
        for script_name, score, comment in results[folder]:
            tail = f" — {comment[:60]}…" if comment and len(comment) > 60 else (f" — {comment}" if comment else "")
            print(f"  {script_name}: {score}{tail}")

    html_content = generate_html_report(results, folder_order)
    html_path = BASE_DIR / "detection_results.html"
    html_path.write_text(html_content, encoding="utf-8")

    print(f"\nHTML report: {html_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
