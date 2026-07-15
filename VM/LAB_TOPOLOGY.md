# OpenWrt VirtualBox lab topology

This document matches the behavior of:

- `create_VM_OpenWrt_router.py` — VM name **`OpenWrt_2026_Router`**
- `create_VM_client_browser_pipe.py` — VM name **`OpenWrt_LAN_Client`**
- Internal network name (must be identical on router LAN and client): **`openwrt-lan`**

If any name or NIC order drifts, the lab breaks in subtle ways (DHCP works on the wrong segment, or not at all).

---

## 1. One diagram (source of truth)

VirtualBox runs on **Windows**. Guests do not share the WSL network namespace; **WSL mirrored mode does not attach your host Linux to `openwrt-lan`**.

```text
                         Windows host / VirtualBox
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Host terminals (WSL or Windows)                                     │
  │    COM1 @ TCP 2324 ──► OpenWrt_2026_Router ttyS0 (ash)               │
  │    COM1 @ TCP 2323 ──► OpenWrt_LAN_Client  ttyS0 (login)              │
  │                                                                      │
  │   Your LAN / ISP                                                     │
  │   (physical)          ┌─────────────────────────────┐                │
  │        ▲              │ OpenWrt_2026_Router         │                │
  │        │              │  NIC1 intnet "openwrt-lan"  │◄──┐            │
  │        │              │       eth0 / br-lan         │   │            │
  │        │              │       192.168.1.1/24        │   │            │
  │        └──────────────┤  NIC2 NAT or bridged (WAN)  │   │            │
  │                       │       eth1 / wan            │   │            │
  │                       │  COM1 → host TCP :2324      │   │            │
  │                       │                             │   │            │
  │                       │  DNS path (LAN clients):    │   │            │
  │                       │   dnsmasq :53               │   │            │
  │                       │     → stubby :5453          │   │            │
  │                       │     → Mullvad DoT :853      │   │            │
  │                       └─────────────────────────────┘   │            │
  │                                      │ only on intnet   │            │
  │                                      ▼                  │            │
  │                       ┌─────────────────────────────┐   │            │
  │                       │ OpenWrt_LAN_Client          │───┘            │
  │                       │  NIC1 intnet "openwrt-lan"  │                │
  │                       │       enp0s3 (DHCP)         │                │
  │                       │  COM1 → host TCP :2323      │                │
  │                       │  DNS → 192.168.1.1 only     │                │
  │                       └─────────────────────────────┘                │
  └──────────────────────────────────────────────────────────────────────┘

WSL / Linux shell on host: runs scripts, calls VBoxManage.exe — NOT on openwrt-lan
```

**Stock OpenWrt x86** maps the **first** guest NIC to **`eth0`**, the second to **`eth1`**. The scripts order VirtualBox NICs so that matches **LAN on `eth0`**, **WAN on `eth1`** without editing UCI.

---

## 2. VirtualBox NIC + COM matrix

| Machine | Adapter | Mode | Host endpoint / must match | Guest |
|--------|---------|------|----------------------------|-------|
| **OpenWrt_2026_Router** | **NIC1** | Internal network **`openwrt-lan`** | Same name as client NIC1 | **`eth0`** → **`br-lan`** `192.168.1.1/24` |
| **OpenWrt_2026_Router** | **NIC2** | **NAT** (default) or bridged | Uplink / ISP path | **`eth1`** → **`wan`** |
| **OpenWrt_2026_Router** | **COM1** | UART TCP server | Host **TCP `2324`** (Windows VBox) | **`ttyS0`** ash (`console=ttyS0`) |
| **OpenWrt_LAN_Client** | **NIC1** | Internal network **`openwrt-lan`** | Same name as router NIC1 | **`enp0s3`** DHCP client |
| **OpenWrt_LAN_Client** | **COM1** | UART TCP server | Host **TCP `2323`** (Windows VBox) | **`ttyS0`** login |

Native Linux VirtualBox (not Windows/`VBoxManage.exe`) uses Unix sockets instead of TCP:

| Machine | Unix socket | PTY helper path |
|--------|-------------|-----------------|
| Router | `/tmp/OpenWrt_2026_Router_serial.sock` | `/tmp/OpenWrt_2026_Router_serial.pty` |
| Client | `/tmp/OpenWrt_LAN_Client_serial.sock` | `/tmp/OpenWrt_LAN_Client_serial.pty` |

Baud rate for both: **115200 8N1**.

Why **NIC1 = LAN** on the router: the factory image puts **`br-lan` on `eth0`**. The first VirtualBox adapter is usually `eth0`, so LAN must be NIC1.

---

## 3. Serial / COM connections

Both VMs expose **COM1 → guest `ttyS0`**. Ports differ so router and client can be attached at the same time.

**Expected window layout (3 terminals):**

1. **Host shell** — where you run lab commands (stays free)
2. **OpenWrt router serial** — TCP **2324**
3. **LAN client serial** — TCP **2323**

Open both serial windows from the host (does not take over this shell). Each COM opens in its **own window** (not a tab):

```bash
python VM/open_lab_serials.py
```

Or one at a time (still opens a **new** window by default):

```bash
python VM/create_VM_OpenWrt_router.py --serial-only      # router → new window :2324
python VM/create_VM_client_browser_pipe.py --serial-only  # client → new window :2323
```

Attach **in the current terminal** only if you want that (used by the window spawner):

```bash
python VM/create_VM_OpenWrt_router.py --serial-here
python VM/create_VM_client_browser_pipe.py --serial-here
```

Enable COM1 on an **existing** router (no full recreate; powers off briefly if running):

```bash
python VM/create_VM_OpenWrt_router.py --enable-serial
# then start the VM in GUI, then:
python VM/open_lab_serials.py
```

`showvminfo` should include something like:

```text
uart1="0x03f8,4"
```

If `uart1="off"`, serial is not enabled. Press **Enter** once if the serial console is blank (OpenWrt ash askfirst / client getty). Detach with **Ctrl+]**.

---

## 4. DNS (Mullvad DoT via the router)

Clients do **not** talk to Mullvad directly. They use OpenWrt as their only DNS server.

```text
LAN client
  └─ UDP/TCP 53 → 192.168.1.1 (dnsmasq on OpenWrt)
                    └─ 127.0.0.1:5453 (stubby)
                         └─ DoT :853 → Mullvad
                              • 194.242.2.2  dns.mullvad.net       (unfiltered)
                              • 194.242.2.4  base.dns.mullvad.net  (ads/trackers/malware)
```

| Fact | Detail |
|------|--------|
| What DHCP advertises | Option 6 → **`192.168.1.1`** (OpenWrt), not Mullvad IPs |
| Client `/etc/resolv.conf` | Expect `nameserver 192.168.1.1` (or systemd-resolved stub `127.0.0.53` with that uplink) |
| Why not plain Mullvad `:53` | Mullvad public DNS **refuses** unencrypted UDP/TCP 53; DoT/DoH only |
| Bootstrap | VBox `--natdnshostresolver2 on` on router WAN NAT so `apk`/`opkg` can install **stubby** before DoT is up |
| Apply script | `VM/apply_mullvad_dot.sh` (also `/root/apply_mullvad_dot.sh` in the guest when injected) |

**OpenWrt checks:**

```sh
uci show dhcp.@dnsmasq[0].server      # expect 127.0.0.1#5453
uci show dhcp.@dnsmasq[0].noresolv    # expect '1'
uci show stubby
ls /etc/overdrive-mullvad-dot.done
nslookup google.com 192.168.1.1
```

**Manual apply if first-boot missed it:**

```sh
sh /root/apply_mullvad_dot.sh
# or paste from host: VM/apply_mullvad_dot.sh
```

**Client checks:**

```bash
cat /etc/resolv.conf
dig @192.168.1.1 google.com +short
ping -c2 google.com
lab-net-troubleshoot
```

| Symptom on client | Meaning |
|-------------------|---------|
| No IPv4 on `enp0s3` / only `lo` | Link/DHCP — `sudo ip link set enp0s3 up && sudo dhclient -v -1 enp0s3` |
| `ping 192.168.1.1` OK, `ping 8.8.8.8` OK, `ping google.com` fails | DNS path / stubby not up — check OpenWrt DoT setup |
| `ping 192.168.1.1` OK, `ping 8.8.8.8` fails | WAN/NAT/routing, not just DNS |
| Empty or wrong nameserver | DHCP DNS missing, or static IP without `nameserver 192.168.1.1` |

---

## 5. What you see where (examples)

### 5.1 Host (WSL or Linux) — **cannot** see the LAN subnet on intnet

From the host you can:

- Run VirtualBox: `VBoxManage list vms`, `showvminfo`.
- Run this repo’s check: `python VM/verify_lab_from_host.py`
- Attach serial: `--serial-only` on the create scripts above.

You **cannot** reliably `ping 192.168.1.1` from WSL just because the router uses `192.168.1.1` on **LAN**. That address lives on the **internal network** visible only to VMs plugged into **`openwrt-lan`**.

### 5.2 Router `showvminfo` (excerpt)

```text
nic1="intnet"
intnet1="openwrt-lan"
nic2="nat"
uart1="0x03f8,4"
```

If **WAN** is bridged instead of NAT:

```text
nic2="bridged"
bridgeadapter2="Intel(R) Ethernet ..."
```

### 5.3 Client `showvminfo` (excerpt)

```text
nic1="intnet"
intnet1="openwrt-lan"
uart1="0x03f8,4"
```

### 5.4 OpenWrt guest — stock network UCI (first boot)

```text
network.@device[0].name='br-lan'
network.@device[0].ports='eth0'
network.lan.device='br-lan'
network.lan.ipaddr='192.168.1.1/24'
network.wan.device='eth1'
network.wan.proto='dhcp'
```

- **`eth0`**: `master br-lan` (LAN on intnet)
- **`eth1`**: WAN (NAT or bridged)

### 5.5 Client guest — working LAN leg

```text
$ ip -br -4 addr
enp0s3           UP             192.168.1.232/24

$ ip route
default via 192.168.1.1 dev enp0s3

$ ping -c2 192.168.1.1
2 packets transmitted, 2 received, 0% packet loss
```

`create_VM_client_browser_pipe.py` primes the client VDI with **netplan DHCP on `en*`** plus **`lab-net-up.service`** (link up + `dhclient`) so a fresh boot should not leave `enp0s3` with no address. If the guest only shows `lo`:

```bash
sudo ip link set enp0s3 up
sudo dhclient -v -1 enp0s3
# or: lab-net-troubleshoot
```

---

## 6. Common confusions

| Confusion | Reality |
|-----------|---------|
| “WSL has internet, so the client should too” | Client uses **intnet**, not WSL’s interfaces. Internet needs OpenWrt **WAN** + routing/NAT. |
| “I’ll ping 192.168.1.1 from WSL to test the router” | **LAN** IP is on **intnet**; use guest serial/console or verify VBox NICs. |
| “Router says bridged — is that wrong?” | **OpenWrt `br-lan`** is a Linux bridge (normal). **VBox bridged** on NIC2 is optional WAN. Default WAN is **NAT**. |
| “Client has no `eth0`” | Predictable names (`enp0s3`) are normal. |
| “Router isn’t providing DNS” | DHCP gives `192.168.1.1`; upstream should be **Mullvad DoT** via stubby after `apply_mullvad_dot.sh`. |
| “Is DNS using TLS?” | Only after stubby + Mullvad DoT is configured. Client→router is still plain `:53` on the lab LAN. |
| “Serial on 2323 doesn’t reach OpenWrt” | **2323 = client**, **2324 = router**. |
| “Static IP still can’t ping google” | Also set `nameserver 192.168.1.1` in `/etc/resolv.conf`. |

---

## 7. Host-side verification

```bash
python VM/verify_lab_from_host.py
python VM/verify_lab_from_host.py -v
```

- **Pass** = VirtualBox NIC/intnet (and related) wiring matches this document.
- **Fail** = VM missing or NIC/intnet wrong — fix in Manager or recreate with the `create_VM_*.py` scripts.

---

## 8. Boot order

1. Start **OpenWrt_2026_Router** (DHCP + DNS on LAN).
2. Start **OpenWrt_LAN_Client** (DHCP on `openwrt-lan`).
3. Open serial windows (host shell stays free): `python VM/open_lab_serials.py`
   - Router COM1 → TCP **2324**
   - Client COM1 → TCP **2323**

If the client starts first, it may get no lease until DHCP retries or you run `lab-net-troubleshoot` / `dhclient` again inside the guest.
