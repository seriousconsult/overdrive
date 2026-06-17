# OpenWrt VirtualBox lab topology

This document matches the behavior of:

- `create_VM_OpenWrt_router.py` — VM name **`OpenWrt_2026_Router`**
- `create_VM_client_browser.py` — VM name **`OpenWrt_LAN_Client`**
- Internal network name (must be identical on router LAN and client): **`openwrt-lan`**

If any name or NIC order drifts, the lab breaks in subtle ways (DHCP works on the wrong segment, or not at all).

---

## 1. One diagram (source of truth)

VirtualBox runs on **Windows**. Guests do not share the WSL network namespace; **WSL mirrored mode does not attach your host Linux to `openwrt-lan`**.

```text
                    ┌─────────────────────────────────────────────┐
                    │              Windows host                  │
                    │  VirtualBox hypervisor                      │
                    │                                             │
   Your LAN / ISP   │   ┌──────────────────┐                     │
   (physical or     │   │ OpenWrt_2026_Router                      │
   home router)    │   │  NIC1 → intnet "openwrt-lan"  ←──┐       │
        ▲           │   │         (LAN / br-lan in guest)│       │
        │           │   │  NIC2 → bridged or NAT (WAN)     │       │
        └───────────┼───┤         (wan in guest) ─────────┼───────┘
   bridged cable    │   └──────────────────┘              │
                    │              │ only on intnet         │
                    │              ▼                        │
                    │   ┌──────────────────┐                │
                    │   │ OpenWrt_LAN_Client                │
                    │   │  NIC1 → intnet "openwrt-lan" ─────┘
                    │   └──────────────────┘
                    └─────────────────────────────────────────────┘

WSL / Linux shell on host: runs scripts, calls VBoxManage.exe — NOT on openwrt-lan
```

**Stock OpenWrt x86** maps the **first** guest NIC to **`eth0`**, the second to **`eth1`**. The scripts order VirtualBox NICs so that matches **LAN on `eth0`**, **WAN on `eth1`** without editing UCI.

---

## 2. VirtualBox NIC matrix (what we actually configure)

| Machine | VBox NIC | Mode | Must match | OpenWrt / Ubuntu guest (typical) |
|--------|----------|------|------------|----------------------------------|
| **OpenWrt_2026_Router** | **NIC1** | Internal network **`openwrt-lan`** | Client **NIC1** intnet name | **`eth0`** → **`br-lan`** (e.g. `192.168.1.1/24`) |
| **OpenWrt_2026_Router** | **NIC2** | **NAT** (default) or bridged | Your uplink / internet path | **`eth1`** → **`wan`** / **`wan6`** (DHCP or similar) |
| **OpenWrt_LAN_Client** | **NIC1** | Internal network **`openwrt-lan`** | Router **NIC1** intnet name | **`enp0s3`** (or `eth0` on older images) — DHCP client |

Why **NIC1 = LAN** on the router: the factory image puts **`br-lan` on `eth0`**. The first VirtualBox adapter is usually `eth0`, so LAN must be NIC1.

---

## 3. What you see where (examples)

### 3.1 Host (WSL or Linux) — **cannot** see the LAN subnet on intnet

From the host you can:

- Run VirtualBox: `VBoxManage list vms`, `showvminfo`.
- Run this repo’s check: `python VM/verify_lab_from_host.py`

You **cannot** reliably `ping 192.168.1.1` from WSL just because the router uses `192.168.1.1` on **LAN**. That address lives on the **internal network** visible only to VMs plugged into **`openwrt-lan`**.

**Exception:** if you bridged the router **WAN** to your home LAN and your home LAN also uses `192.168.1.0/24`, you might accidentally ping a *different* device. Do not use that as proof the **intnet lab** works.

### 3.2 Example: `VBoxManage showvminfo OpenWrt_2026_Router --machinereadable` (excerpt)

You should see lines shaped like:

```text
nic1="intnet"
intnet1="openwrt-lan"
nic2="bridged"
bridgeadapter2="Intel(R) Ethernet ..."
```

If **WAN** fell back to NAT:

```text
nic2="nat"
```

### 3.3 Example: `VBoxManage showvminfo OpenWrt_LAN_Client --machinereadable` (excerpt)

```text
nic1="intnet"
intnet1="openwrt-lan"
```

### 3.4 OpenWrt guest (console) — stock UCI after first boot

```text
network.@device[0].name='br-lan'
network.@device[0].ports='eth0'
network.lan.device='br-lan'
network.lan.ipaddr='192.168.1.1/24'
network.wan.device='eth1'
network.wan.proto='dhcp'
```

### 3.5 OpenWrt guest — `ip link` (conceptual)

- **`eth0`**: `master br-lan` (LAN cable to intnet)
- **`eth1`**: not on the bridge (WAN)

### 3.6 Client guest (Ubuntu Server / OSBoxes) — working lab

Interface name is often **`enp0s3`**, not `eth0`:

```text
$ ip addr show enp0s3
inet 192.168.1.197/24 ... dynamic ...
```

```text
$ ip route
default via 192.168.1.1 dev enp0s3
192.168.1.0/24 dev enp0s3 ...
```

```text
$ ping -c2 192.168.1.1
2 packets transmitted, 2 received, 0% packet loss
```

That combination is the **real** end-to-end proof for the **LAN leg**.

---

## 4. Common confusions

| Confusion | Reality |
|-----------|---------|
| “WSL has internet, so the client should too” | Client uses **intnet**, not WSL’s interfaces. Internet on the client requires OpenWrt **WAN** working and routing/NAT configured. |
| “I’ll ping 192.168.1.1 from WSL to test the router” | **LAN** IP is on **intnet**; WSL is not on that segment. Use **guest** console or verify **VBox** NICs + ping **inside** client. |
| “Router says bridged — is that wrong?” | **OpenWrt `br-lan`** is a **Linux bridge** (normal). **VirtualBox “bridged”** on **NIC2** is an optional WAN uplink. The scripts default to **NAT** for WAN because it avoids Wi-Fi bridge issues and subnet overlap with OpenWrt's default `192.168.1.0/24` LAN. |
| “Client has no `eth0`” | **Predictable network names** (`enp0s3`) are normal. Use `ip link` to see the real name. |

---

## 5. Host-side verification script

```bash
# From repo root (WSL paths OK)
python VM/verify_lab_from_host.py
python VM/verify_lab_from_host.py -v
```

- **Pass** = VirtualBox config matches this document.
- **Fail** = VM missing or NIC/intnet names wrong — fix in Manager or recreate with the `create_VM_*.py` scripts.

---

## 6. Boot order

1. Start **OpenWrt_2026_Router** (DHCP server on LAN comes up).
2. Start **OpenWrt_LAN_Client** (requests DHCP on `openwrt-lan`).

If the client starts first, it may get no lease until DHCP retries or you run `lab-net-troubleshoot` / `dhclient` again inside the guest.
