# Overdrive

Overdrive is a Python-based privacy detection suite that runs multiple privacy, fingerprinting,
network, and environment checks, then summarizes the results as scores.

It is designed for analysis of how your current network/browser/runtime
environment looks to remote services (for example: VPN consistency, browser leaks,
header mismatch signals, and hosting reputation checks).

## What You Get

- Individual detection scripts grouped by topic (`vpn`, `browser`, `network`, `router`, and root checks)
- A full runner (`run/run_all.py`) that can run VM setup/verification and then detections
- A detection-only runner (`run/run_all_detections.py`) that discovers probe scripts automatically
- A VM lab runner (`run/run_VMs.py`) that runs `VM/create_VM_*.py` setup scripts and then `VM/verify_lab_from_host.py`
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

From the **repository root**, using the project virtualenv on **Linux or WSL** (recommended):

```bash
cd /path/to/overdrive
source virtual_env/bin/activate   # optional
python3 run/run_all.py
```

Outputs:

- Detailed console output
- HTML report: `detection_results.html`

`run/run_all.py` runs VM setup/verification first and then runs detections. Useful options:

```bash
python3 run/run_all.py --dry-run
python3 run/run_all.py --skip-vms
python3 run/run_all.py --skip-detections
python3 run/run_all.py --keep-going
python3 run/run_all.py --vm-arg=--skip-verify
```

You can also run it from the `run/` directory:

```bash
cd /path/to/overdrive/run
python3 run_all.py
```

### Run Detections Only

If the VM lab is already configured, or you do not want the runner to touch VirtualBox:

```bash
cd /path/to/overdrive
python3 run/run_all_detections.py
```

The detection runner skips support/tooling folders and scripts, including `common/`, `run/`, `VM/create_VM_*.py`, and `VM/verify_lab_from_host.py`.

### Run VM Setup Only

To create/refresh the OpenWrt lab VMs and verify host-side VirtualBox wiring:

```bash
cd /path/to/overdrive
python3 run/run_VMs.py
```

Useful options:

```bash
python3 run/run_VMs.py --dry-run
python3 run/run_VMs.py --skip-verify
python3 run/run_VMs.py --keep-going
python3 run/run_VMs.py --include-todo
```

By default, `run/run_VMs.py` skips `create_VM_*.py` scripts whose source contains `TODO`.

#### Where to run (host vs VMs)
**WSL or native Linux** at repo root 


#### OpenWrt lab: two vantage points (WAN vs LAN)
- **WAN profile** — Run directed router checks from the **host** (or anything on the **same Layer-2 segment as the router’s bridged WAN**), targeting the router’s **WAN IP**. That matches how upstream / “outside the guest” paths see the router.
- **LAN profile** — Run checks from the **client VM** on internal network `openwrt-lan`, targeting the router’s **LAN IP** (e.g. `192.168.1.1`). The **WSL/Linux host cannot reach intnet** (VirtualBox isolates `openwrt-lan`), so LAN-plane probes must originate inside a guest on that intnet.

Outbound traffic to the internet (e.g. HTTPS to Google) from the **client VM** still exits via **OpenWrt’s WAN** (NAT). What remote collectors see reflects that WAN path. **Management-plane** probes to `192.168.1.x` must still use the **LAN** seat.

The full batch runner may probe **whatever your default gateway is**, which might **not** be OpenWrt. For lab fidelity, run router modules with explicit `--ip` (and the correct profile) as described in [`VM/ROUTER_PLAN.txt`](VM/ROUTER_PLAN.txt). Topology diagrams and example `VBoxManage` / guest output live in [`VM/LAB_TOPOLOGY.md`](VM/LAB_TOPOLOGY.md). To verify only VirtualBox wiring from the host: `python3 VM/verify_lab_from_host.py`.

## Important Runtime Notes


### Notes
- `setup_virtual_env.py` sets up the environment and installs all dependencies
- `run/run_all.py` runs VM setup/verification and then the full detection suite
- `run/run_all_detections.py` runs the detection suite only
- `run/run_VMs.py` runs VM setup scripts and then `VM/verify_lab_from_host.py`
- `/local/wsl_config.py` turns on mirrored mode for WSL networking
- `/VM/verify_lab_from_host.py` verifies basic networking is set up correctly on the VMs
- `/local/*` reports information about your physical environment

### WSL2 Prerequisite: Mirrored Networking
If you are running Overdrive inside Windows Subsystem for Linux (WSL2), the default NAT networking isolates your environment, preventing accurate discovery of local routers, mDNS services, and broadcast traffic.

You must enable Mirrored Networking to make WSL a peer to your Windows host.

1. Configure WSL mode
   Run the included configuration utility from within your Overdrive directory:

   ```bash
   chmod +x wsl_config.py
   ./wsl_config.py --enable
   ```

2. Restart WSL
   Configuration changes to the WSL VM require a full shutdown to take effect. Run this in a Windows PowerShell terminal:

   ```powershell
   wsl --shutdown
   ```

3. Verify
   Re-open your WSL terminal and run:

   ```bash
   ./wsl_config.py
   ```

   It should now report `[*] Current WSL Networking Mode: MIRRORED.`


### Passwordless sudo (Scapy capture scripts)

`run/run_all_detections.py` runs these scripts with **`sudo -n`** (non-interactive sudo, no password prompt):

- `vpn/TCP_stack.py`
- `router/TTL.py`
- `router/NAT_OS.py`

Scapy packet capture usually needs elevated privileges on Linux/WSL.

On Linux/WSL, you can grant the virtualenv Python binary raw-socket capabilities so captures work without sudo. For example:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip virtual_env/bin/python
```

When those capabilities are present, the batch runner may execute the capture scripts without sudo.


### TODO-Based Skip Logic

The batch runner scans each script's source for the word `TODO`.  
If present, the script is skipped and recorded as score `0` with comment `TODO:`.

This makes partially implemented modules visible without breaking full-suite runs.

## Limitations

- Results are heuristics, not definitive attribution.
- VPNs, CDNs, CGNAT, enterprise networks, and hardened browsers can produce
  false positives/false negatives.
- Some scripts rely on third-party pages/APIs and may drift as upstream behavior changes.
