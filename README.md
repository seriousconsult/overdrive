# Overdrive

Python probes for browser, VPN, network, router, local-host, and VM-lab signals. Detection probes live under `detections/`; results print to the console and HTML reports are written under the matching `detections/` folder.

## Score

All scripts use the same `SCORE: 1-5` host-authenticity scale:

- `1`: authentic residential / not alerting
- `2`: mildly atypical, probably still home-like
- `3`: inconclusive, inconsistent or misleading
- `4`: very alerting, but not proven
- `5`: definitely artificial host

Batch runner extras: `0` means skipped due to `TODO`; `Error` means failed, timed out, or non-zero exit.

## Run

Initial setup (WSL/Linux host):

```bash
python3 install.py
```

`install.py` is non-interactive by default and uses `sudo -n` for system
packages and `setcap`. If passwordless sudo is missing, it installs
`/etc/sudoers.d/overdrive` (one password prompt when a TTY is available), then
continues without further prompts. On the host it also installs QEMU
(`qemu-system-x86`, `qemu-utils`). Inside a primed Kali guest it installs
`kali-linux-default` (wireshark, metasploit, top10, …).

Open an activated shell after setup:

```bash
python3 install.py --interactive
```

```bash
cd /path/to/overdrive
source virtual_env/bin/activate   # optional
python3 run/run_all.py
```

Useful commands:

```bash
python3 run/run_all.py --skip-vms          # detections only
python3 run/run_all.py --skip-detections   # VM setup/verification only
python3 detections/run_detections.py       # report: detections/detection_results.html
python3 run/run_browser_detections.py      # report: detections/browser/browser_detection_results.html
python3 run/run_VMs_then_client_browser.py # rebuild lab, then run browser probes in the client
python3 run/run_VMs.py                     # rebuild lab (headless by default; tmux on TTY)
python3 run/run_VMs.py --gui               # same rebuild with QEMU GTK windows
python3 run/run_VMs.py --no-tmux           # skip managed tmux serial layout
python3 VM/qemu_manager.py list            # list/stop/kill/serial for running QEMU VMs
python3 VM/verify_lab_from_host.py         # bridge / taps / serial wiring check
```

### Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

- `tests/infrastructure`: lab constants, QEMU helpers, `run_VMs` defaults
- `tests/detections`: detections package smoke checks

## Layout

- `detections/browser`, `detections/network`, `detections/router`, `detections/vpn`: score-producing probes.
- `detections/common`: shared constants and helper libraries (including QEMU/KVM lab helpers); not run directly.
- `detections/*/*_detection_results.html`: category-specific HTML reports.
- `local_host`: local machine / WSL checks.
- `VM`: lab VM builders, verification, `lab_vms/` disks, downloads, and `qemu_manager.py`.
- `run`: batch runners (`run_VMs.py`, `run_all.py`, …).
- `tests`: unit tests (`infrastructure/`, `detections/`).

## Gotchas

- Run from the repo root unless a script says otherwise.
- `run/run_all.py` touches the VM lab first; use `--skip-vms` for detections only.
- Scripts containing `TODO` are skipped and reported as score `0`.
- Lab VMs are **direct QEMU/KVM** (not libvirt/VirtualBox). `virsh list` will not show them.
- `run/run_VMs.py` starts headless by default; pass `--gui` for display windows.
- On a TTY, `run_VMs.py` opens a managed tmux session (`overdrive-vms`) with Kali serial as the main (focused) pane. Use `--no-tmux` to disable.
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

You also need `/dev/kvm` and permission to create the `test-lan` bridge / taps (`ip` via sudo).

## Lab VMs

The lab runs four QEMU guests on Linux bridge `test-lan`:

| VM | Role | Serial TCP | Tap |
|---|---|---|---|
| `Test_Router` | OpenWrt (LAN DHCP/DNS + Mullvad DoT; WAN = QEMU user/SLIRP) | `127.0.0.1:2324` | `tap-router-lan` |
| `Test_Clienta` | Alpine browser client | `127.0.0.1:2325` | `tap-clienta` |
| `Test_Clientk` | Kali client (`kali-linux-default` tools) | `127.0.0.1:2326` | `tap-clientk` |
| `target` | Metasploitable 2 (intentionally vulnerable, **not** hardened) | `127.0.0.1:2327` | `tap-target` |

Disks live under `VM/lab_vms/<VM_NAME>/`. Secrets (root passwords) are in `VM/.env` (gitignored).

tmux layout from `run/run_VMs.py` (interactive TTY):

```
top:    Kali serial :2326   (main / focused)
bottom: host (wider) | Alpine :2325 | target :2327 | router :2324
        ↑ smaller serial panes: alpine, target, router
```

- **WAN checks:** run from the host or the router WAN segment; target the router WAN IP.
- **LAN checks:** run from a client VM on `test-lan`; target the router LAN IP, usually `192.168.50.1`.
- The WSL/Linux host is on the `test-lan` bridge but usually has no IP there; LAN checks run from client VMs.
- DNS path: client → OpenWrt dnsmasq (`192.168.50.1`) → stubby → Mullvad DoT (`dns.mullvad.net`).
- The batch runner may probe your current default gateway, not the OpenWrt VM. Use explicit `--ip` values for lab router modules.
- `Test_Clienta` uses hostname `clienta`, a fresh Dell NIC MAC, tame DHCP client identity, cleared `machine-id`, and a generic timezone User-Agent at build time. Rebuild after changing those settings.
- Client checker/network deps are installed by guest `install.py` during disk prime (Python libs into `/root/virtual_env`; Chromium/tools via distro packages). Rebuild clients after changing `install.py`.
- `target` login is stock Metasploitable 2: `msfadmin` / `msfadmin`. Keep it on the lab LAN only.

Manage running QEMU processes:

```bash
python3 VM/qemu_manager.py              # interactive
python3 VM/qemu_manager.py status
python3 VM/qemu_manager.py serial Test_Clientk
python3 VM/qemu_manager.py stop --all
```

Verify wiring:

```bash
python3 VM/verify_lab_from_host.py
```

## Limits

Scores are heuristics, not attribution. VPNs, CGNAT, enterprise networks, CDNs, hardened browsers, missing permissions, and blocked APIs can all skew results.
