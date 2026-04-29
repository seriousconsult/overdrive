# Overdrive

Overdrive is a Python-based privacy detection suite that runs multiple privacy, fingerprinting,
network, and environment checks, then summarizes the results as scores.

It is designed for quick local analysis of how your current network/browser/runtime
environment looks to remote services (for example: VPN consistency, browser leaks,
header mismatch signals, and hosting reputation checks).

## What You Get

- Individual detection scripts grouped by topic (`vpn`, `browser`, `network`, `router`, and root checks)
- A batch runner (`run_all_detections.py`) that discovers scripts automatically
- Console output plus an HTML report at `detection_results.html`
- Script-level scoring on a `1-5` scale


## Scoring Model
Scripts print a `SCORE` value in the range `1-5`.
Interpretation can vary slightly by script, but a common pattern is:

- `1`: low risk / no anomaly detected
- `3`: uncertain or mixed signal
- `5`: strong mismatch, leak, or suspicious condition

Special cases in the batch runner:

- `Error`: script failed, timed out, or returned non-zero
- `0`: script contains `TODO` and was skipped intentionally


## Running Checks

### Run Everything

```bash
python3 run_all_detections.py
```

Outputs:

- Detailed console output
- HTML report: `detection_results.html`


## Important Runtime Notes

### Passwordless sudo (Scapy capture scripts)

`run_all_detections.py` runs these scripts with **`sudo -n`** (non-interactive sudo, no password prompt):

- `vpn/TCP_stack.py`
- `router/TTL.py`
- `router/NAT_OS.py`

Scapy packet capture usually needs elevated privileges on Linux/WSL. `router/NAT_OS.py` and `router/TTL.py` **re-exec** to `virtual_env/bin/python` when you launch them with `./…`, so the process matches the interpreter you granted **NOPASSWD** or **setcap** on (not whatever `python3` appears first on `PATH`).

Running those scripts **without** `sudo` or `setcap` on that venv Python will raise **PermissionError**; the script catches that and prints example `sudo` / `setcap` commands.

The batch runner never prompts for a password; if your user cannot run those commands **without** a password, those steps fail and show as **Error** in the HTML report.

**Configure NOPASSWD for only the venv Python + those scripts** (adjust paths to match your clone; inside WSL, paths are typically under `/home/<you>/...` or `/mnt/c/...`):

1. Resolve the interpreter path you use for Overdrive (for example the project venv):

   ```bash
   readlink -f virtual_env/bin/python
   ```

2. Edit sudoers safely:

   ```bash
   sudo visudo
   ```

3. Add one line per script (same `python` binary, different script path), replacing `YOURUSER` and the paths:

   ```text
   YOURUSER ALL=(root) NOPASSWD: /ABS/PATH/virtual_env/bin/python /ABS/PATH/vpn/TCP_stack.py
   YOURUSER ALL=(root) NOPASSWD: /ABS/PATH/virtual_env/bin/python /ABS/PATH/router/TTL.py
   YOURUSER ALL=(root) NOPASSWD: /ABS/PATH/virtual_env/bin/python /ABS/PATH/router/NAT_OS.py
   ```

   Paths must match what `sudo -n` executes (absolute paths; WSL is case-sensitive).

**Alternative (Linux only):** grant capabilities to the venv interpreter so capture works **without** sudo, for example `cap_net_raw` and `cap_net_admin` on `virtual_env/bin/python` (`getcap` / `setcap`). The batch runner checks for those capabilities on the venv Python and, when present, runs **all** capture scripts above **without** sudo (same behavior as for `TCP_stack.py` alone).

### Router probes from WSL2

`router/upnp_discovery.py` often gets **no SSDP** inside WSL2 because multicast does not reach your LAN router; pass **`--ip`** with your **LAN gateway** (e.g. `192.168.1.1`) so M-SEARCH is also sent unicast to port 1900.

`router/banners.py` prints a **short summary** by default; use **`-v`** / **`--verbose`** for every path.

### TODO-Based Skip Logic

The batch runner scans each script's source for the word `TODO`.  
If present, the script is skipped and recorded as score `0` with comment `TODO:`.

This makes partially implemented modules visible without breaking full-suite runs.

## Limitations

- Results are heuristics, not definitive attribution.
- VPNs, CDNs, CGNAT, enterprise networks, and hardened browsers can produce
  false positives/false negatives.
- Some scripts rely on third-party pages/APIs and may drift as upstream behavior changes.
