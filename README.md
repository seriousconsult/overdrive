# Overdrive

Python probes for browser, VPN, network, router, local-host, and VM-lab signals. Detection probes live under `detections/`; results print to the console and `detection_results.html`.

## Score

All scripts use the same `SCORE: 1-5` host-authenticity scale:

- `1`: authentic residential / not alerting
- `2`: mildly atypical, probably still home-like
- `3`: inconclusive, inconsistent or misleading
- `4`: very alerting, but not proven
- `5`: definitely artificial host

Batch runner extras: `0` means skipped due to `TODO`; `Error` means failed, timed out, or non-zero exit.

## Run

Initial setup:

```bash
python3 install.py
```

Non-interactive setup for scripts/CI:

```bash
python3 install.py --non-interactive
```

`--non-interactive` uses `sudo -n` for system packages and `setcap`, so it exits
instead of prompting if passwordless sudo is not already configured.

```bash
cd /path/to/overdrive
source virtual_env/bin/activate   # optional
python3 run/run_all.py
```

Useful commands:

```bash
python3 run/run_all.py --skip-vms          # detections only
python3 run/run_all.py --skip-detections   # VM setup/verification only
python3 detections/run_detections.py
python3 run/run_VMs.py
```

## Layout

- `detections/browser`, `detections/network`, `detections/router`, `detections/vpn`: score-producing probes.
- `detections/common`: shared constants and helper libraries; not run directly.
- `local_host`: local machine / WSL checks.
- `VM`: OpenWrt lab VM setup and verification.
- `run`: batch runners.

## Gotchas

- Run from the repo root unless a script says otherwise.
- `run/run_all.py` touches the VM lab first; use `--skip-vms` for detections only.
- Scripts containing `TODO` are skipped and reported as score `0`.
- `VM/create_VM_linux.py` is unfinished and skipped unless explicitly included by VM tooling.
- `run/run_VMs.py` skips `VM/create_VM_client_browser_pipe.py` by default because it attaches to the serial console; pass `--include-client` to run it.
- Third-party pages/APIs can be blocked, rate-limited, or changed upstream; expect some score `3` ambiguity.
- Packet-capture probes need raw socket privileges: `detections/vpn/TCP_stack.py`, `detections/router/TTL.py`, `detections/router/NAT_OS.py`, `detections/network/DHCP.py`, `detections/network/client_mac_exposure.py`.

Optional capture setup:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip virtual_env/bin/python
```

## WSL2

Default WSL2 NAT hides LAN broadcast/multicast behavior. For router, mDNS (including consumer diversity), ARP/OUI, LAN neighbor density, LLMNR/NBNS/WS-Discovery, and capture probes, enable mirrored networking:

```bash
python3 local_host/wsl_config.py --enable
```

Then restart WSL from Windows PowerShell:

```powershell
wsl --shutdown
```

Verify after reopening WSL:

```bash
python3 local_host/wsl_config.py
```

## OpenWrt Lab

- **WAN checks:** run from the host or the router WAN segment; target the router WAN IP.
- **LAN checks:** run from the client VM on `openwrt-lan`; target the router LAN IP, usually `192.168.1.1`.
- The WSL/Linux host cannot directly reach VirtualBox `intnet` LANs.
- The batch runner may probe your current default gateway, not the OpenWrt VM. Use explicit `--ip` values for lab router modules.
- The Alpine LAN client scrubs tracking identifiers at build time (neutral hostname `desktop`, non-VirtualBox NIC MAC, tame DHCP client identity, cleared `machine-id`, generic timezone User-Agent). Rebuild the Alpine VM after changing those settings. LAN silence is still expected and discovery probes may still score it as lab-like.
- Alpine client checker/network deps are installed by guest `install.py` during VDI prime (Python libs into `/root/virtual_env`; curl, iproute2, iputils, nmap, dig, tcpdump, Chromium via apk). Bootstrap image install keeps `bash` / `python3` / `tzdata` / `iptables` (so `client-firewall` works without `install.py`). Rebuild the client after changing bootstrap packages or `install.py`.

Verify wiring:

```bash
python3 VM/verify_lab_from_host.py
```

More detail: `VM/LAB_TOPOLOGY.md`.

## Limits

Scores are heuristics, not attribution. VPNs, CGNAT, enterprise networks, CDNs, hardened browsers, missing permissions, and blocked APIs can all skew results.
