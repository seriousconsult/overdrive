# Overdrive

Overdrive is a Python-based privacy detection suite that runs multiple privacy, fingerprinting,
network, and environment checks, then summarizes the results as scores.

It is designed for quick local analysis of how your current network/browser/runtime
environment looks to remote services (for example: VPN consistency, browser leaks,
header mismatch signals, and hosting reputation checks).

## What You Get

- Individual detection scripts grouped by topic (`vpn`, `browser`, `network`, and root checks)
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

### WSL + `TCP_stack.py`

`run_all_detections.py` runs `TCP_stack.py` with `sudo -n` (non-interactive).  
If passwordless sudo is not configured in your Linux/WSL environment, that step will fail
and be marked as an error in the report.

### TODO-Based Skip Logic

The batch runner scans each script's source for the word `TODO`.  
If present, the script is skipped and recorded as score `0` with comment `TODO:`.

This makes partially implemented modules visible without breaking full-suite runs.

## Limitations

- Results are heuristics, not definitive attribution.
- VPNs, CDNs, CGNAT, enterprise networks, and hardened browsers can produce
  false positives/false negatives.
- Some scripts rely on third-party pages/APIs and may drift as upstream behavior changes.
