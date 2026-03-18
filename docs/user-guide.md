# CodeRed AI Sensor - User Guide

## Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Deployment Steps](#3-deployment-steps)
4. [Network Mirror/SPAN Configuration](#4-network-mirrorspan-configuration)
5. [First-Time Setup](#5-first-time-setup)
6. [Management Menu Reference](#6-management-menu-reference)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Overview

The CodeRed AI Sensor is a Network Detection and Response (NDR) appliance that passively monitors your network traffic for threats, anomalies, and suspicious behavior.

**How it works:**

```
                    ┌──────────────┐
                    │   Network    │
                    │   Switch     │
                    │              │
                    │  SPAN/Mirror ├──────┐
                    │    Port      │      │
                    └──────────────┘      │
                                          │  (mirrored traffic)
                                          ▼
┌─────────────────────────────────────────────────────────┐
│                  CodeRed AI Sensor                       │
│                                                          │
│   ┌─────────┐    ┌───────────┐    ┌──────────────────┐  │
│   │  ens32   │    │   ens34    │    │                  │  │
│   │  Mgmt    │    │  Monitor   │    │  Zeek + Suricata │  │
│   │  IP      │    │  (SPAN)    │───▶│  Analysis Engine │  │
│   └────┬─────┘    └───────────┘    │                  │  │
│        │                            └────────┬─────────┘  │
│        │                                     │            │
│        │              ┌──────────────────────┘            │
│        │              ▼                                   │
│        │    ┌──────────────────┐                          │
│        │    │  Log Forwarding  │                          │
│        │    │  (to your SIEM)  │                          │
│        │    └────────┬─────────┘                          │
│        │             │                                    │
└────────┼─────────────┼────────────────────────────────────┘
         │             │
         │             ▼
    Management    ┌──────────┐
    Network       │   SIEM   │
                  └──────────┘
```

The sensor has **two network interfaces**:

| Interface | Purpose | IP Address |
|-----------|---------|------------|
| **ens32** (Management) | SSH access, log forwarding to SIEM | Static IP on your management network |
| **ens34** (Monitor) | Receives mirrored traffic from switch | No IP address (promiscuous mode) |

---

## 2. System Requirements

### Sensor VM Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 vCPUs | 8 vCPUs |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB | 500 GB |
| NICs | 2 | 2 |

### Supported Hypervisors

- VMware ESXi 7.0 / 8.0
- VMware Workstation / Fusion
- Proxmox VE 7.x / 8.x
- Microsoft Hyper-V
- KVM / QEMU
- VirtualBox (lab/testing only)

### Network Requirements

- One management IP address (static recommended)
- One SPAN/mirror port on your network switch
- Network access from sensor to your SIEM server (default port 9200)
- DNS and NTP access from sensor

---

## 3. Deployment Steps

### Step 1: Import the OVA

**VMware ESXi:**
1. Log in to vSphere Client
2. Right-click your host → **Deploy OVF Template**
3. Select the `codered-sensor-x.x.x.ova` file
4. Follow the wizard, accept defaults
5. Before powering on, adjust CPU/RAM/disk if needed (see requirements above)

**Proxmox:**
1. Copy the OVA to your Proxmox host
2. Extract: `tar xvf codered-sensor-x.x.x.ova`
3. Import: `qm importdisk <vmid> codered-sensor.vmdk local-lvm`
4. Attach the disk and configure 2 NICs in the VM settings

**VMware Workstation:**
1. File → Open → select the `.ova` file
2. Choose storage location, click Import
3. Adjust settings if needed

### Step 2: Configure Virtual NICs

The sensor requires **two virtual network adapters**:

| Adapter | Connect to | Purpose |
|---------|------------|---------|
| **NIC 1** (ens32) | Your management network (VM Network / bridge) | SSH + SIEM forwarding |
| **NIC 2** (ens34) | SPAN/mirror port group (see Section 4) | Receives mirrored traffic |

**VMware ESXi example:**
1. Edit VM Settings → Network Adapter 1 → select your **Management port group**
2. Network Adapter 2 → select your **SPAN port group** (see Section 4 to create this)
3. For Adapter 2: check **Allow promiscuous mode** on the port group

**Proxmox example:**
1. NIC 1 (net0) → bridge to your management network (e.g., `vmbr0`)
2. NIC 2 (net1) → bridge to your SPAN bridge (e.g., `vmbr1`)

### Step 3: Power On and Configure

1. Power on the VM
2. SSH into the sensor: `ssh coderedai@<dhcp-ip-or-console>`
   - Default credentials: `coderedai` / `coderedai`
3. Follow the first-time setup wizard (see Section 5)
4. The sensor will start monitoring automatically after setup

---

## 4. Network Mirror/SPAN Configuration

The sensor needs to receive a copy of your network traffic. This is done by configuring a **SPAN** (Switched Port Analyzer) or **mirror port** on your network switch.

### What Traffic to Mirror

Mirror traffic from ports or VLANs that you want to monitor:

```
  Recommended SPAN sources:
  ┌──────────────────────────────────────┐
  │                                      │
  │  ● Uplink to firewall/internet ◄──── Most important (north-south)
  │  ● Inter-VLAN trunk ports      ◄──── East-west traffic
  │  ● Server farm switch ports     ◄──── Critical assets
  │  ● DMZ switch ports             ◄──── Exposed services
  │                                      │
  └──────────────────────────────────────┘
```

**At minimum**, mirror your **internet uplink** (the port connecting to your firewall/router). This captures all north-south traffic entering and leaving your network.

### Cisco IOS Switch

```
! Create a SPAN session
! Source = the port(s) or VLAN(s) you want to monitor
! Destination = the port connected to the sensor's monitor NIC

! Example: Mirror the firewall uplink port (Gi0/1) to sensor port (Gi0/24)
configure terminal
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24

! Example: Mirror an entire VLAN
monitor session 1 source vlan 10,20,30 both
monitor session 1 destination interface GigabitEthernet0/24

! Verify
show monitor session 1
```

### Cisco Nexus (NX-OS)

```
configure terminal
monitor session 1 type span
  source interface Ethernet1/1 both
  destination interface Ethernet1/48
  no shut
```

### Arista EOS

```
configure terminal
monitor session 1 source Ethernet1 both
monitor session 1 destination Ethernet48
```

### Juniper EX/QFX

```
set forwarding-options analyzer SPAN input ingress interface ge-0/0/0.0
set forwarding-options analyzer SPAN input egress interface ge-0/0/0.0
set forwarding-options analyzer SPAN output interface ge-0/0/47.0
```

### HP / Aruba ProCurve

```
mirror-port 48
interface 1 monitor
```

### Dell / Force10

```
monitor session 1 source interface tengigabitethernet 0/1 both
monitor session 1 destination interface tengigabitethernet 0/48
```

### Meraki (Dashboard)

1. Go to **Switch → Monitor → Packet Capture**
2. Note: Meraki has limited SPAN support. Use a **network tap** instead if possible.

### MikroTik

```
/interface ethernet switch
set switch1 mirror-source=ether1 mirror-target=ether24
```

### VMware vSwitch / VDS (Virtual Environment)

If the sensor is monitoring **virtual machine traffic**:

**Standard vSwitch:**
1. vSphere Client → Host → Networking → vSwitch properties
2. Select the port group for the sensor's monitor NIC
3. Security tab → set **Promiscuous Mode: Accept**
4. Connect the sensor's NIC 2 to this port group
5. Connect the VMs you want to monitor to the same vSwitch

**Distributed vSwitch (VDS) - Recommended:**
1. Create a new port group for SPAN (e.g., "SPAN-Destination")
2. Configure port mirroring:
   - Go to VDS → Settings → Port Mirroring
   - New Session → **Distributed Port Mirroring**
   - Source: select the port groups / uplinks to mirror
   - Destination: select the sensor's port
3. Set **Allow promiscuous mode: Accept** on the destination port group

```
  VMware VDS Port Mirroring:

  ┌──────────────────────────────────────────────┐
  │              Distributed vSwitch              │
  │                                               │
  │   Source Ports          Destination Port       │
  │  ┌──────────┐         ┌───────────────┐       │
  │  │ VM-Web   ├────┐    │               │       │
  │  └──────────┘    │    │  SPAN Port    │       │
  │  ┌──────────┐    ├───▶│  Group        ├──▶ Sensor NIC 2
  │  │ VM-DB    ├────┘    │  (promisc on) │       │
  │  └──────────┘         │               │       │
  │  ┌──────────┐         └───────────────┘       │
  │  │ Uplink   ├────────▶ (also mirrored)        │
  │  └──────────┘                                  │
  └──────────────────────────────────────────────┘
```

### Proxmox (Linux Bridge)

```bash
# On the Proxmox host, mirror traffic from vmbr0 to vmbr1
# vmbr1 is connected to the sensor's monitor NIC

# Using tc (traffic control):
tc qdisc add dev vmbr0 ingress
tc filter add dev vmbr0 parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress mirror dev vmbr1

# To remove:
tc qdisc del dev vmbr0 ingress
```

### Using a Network TAP (Recommended for Production)

A **network TAP** (Test Access Point) is a passive hardware device that copies traffic without impacting the network. This is more reliable than SPAN for production deployments.

```
                          Network TAP
                    ┌─────────────────────┐
  Firewall ────────▶│  Port A     Port B  │◀──────── Core Switch
                    │                     │
                    │     Monitor Port    │
                    └─────────┬───────────┘
                              │
                              ▼
                      Sensor NIC 2 (ens34)
```

**Recommended TAP vendors:**
- Garland Technology
- Gigamon
- IXIA / Keysight
- Dualcomm (budget option)

**When to use a TAP instead of SPAN:**
- Production environments where switch CPU matters
- When you need guaranteed packet delivery (SPAN can drop packets under load)
- When monitoring 1 Gbps+ links
- Compliance requirements (TAPs are passive and don't alter traffic)

---

## 5. First-Time Setup

After deploying the OVA and configuring the NICs, power on the sensor and SSH in:

```
ssh coderedai@<sensor-ip>
Password: coderedai
```

The setup wizard will ask for:

| Step | Field | Description |
|------|-------|-------------|
| 1 | Hostname | Name for this sensor (e.g., `hq-sensor-01`) |
| 2 | Management interface | Select the NIC for SSH/management (usually ens32) |
| 2 | IP mode | Static (recommended) or DHCP |
| 2 | IP / Netmask / Gateway / DNS | If static, enter your management network details |
| 3 | Monitor interface | Select the NIC receiving SPAN traffic (usually ens34) |
| 4 | Sensor name | Friendly name for identification |
| 5 | SIEM IP | IP address of your SIEM / log collector |
| 5 | SIEM port | Port your SIEM listens on (default: 9200) |

After confirming, the sensor applies the configuration and starts monitoring.

---

## 6. Management Menu Reference

After setup, every SSH login shows the management menu:

| # | Option | What it does |
|---|--------|--------------|
| 1 | Sensor status | CPU, memory, disk, service health, SIEM connection |
| 2 | Network interfaces | Show all NICs, IP addresses, promiscuous status |
| 3 | View logs | Tail Suricata alerts, Zeek DNS/conn/HTTP logs, system log |
| 4 | Diagnostics | Test DNS, gateway, SIEM connectivity, NTP sync, disk health |
| 5 | Network | Change management IP, gateway, DNS |
| 6 | Hostname | Change sensor hostname |
| 7 | Monitor interface | Change which NIC receives SPAN traffic |
| 8 | SIEM destination | Change SIEM IP address and port |
| 9 | Restart services | Restart Zeek, Suricata, or all services |
| 10 | Support bundle | Generate a diagnostic tarball for support |
| 11 | Change password | Change the `coderedai` login password |
| 12 | Reboot | Reboot the sensor |
| 13 | Shutdown | Shut down the sensor (stops all monitoring) |

---

## 7. Troubleshooting

### Sensor is not receiving traffic

1. **Check the monitor interface:**
   - Menu option **2** (Network interfaces) — verify `ens34` shows `PROMISC`
   - If not promiscuous, go to option **7** and re-select the monitor interface

2. **Check SPAN configuration on your switch:**
   - Verify the SPAN session is active: `show monitor session 1` (Cisco)
   - Verify the destination port matches the physical port connected to the sensor

3. **Check VMware promiscuous mode:**
   - The port group connected to the sensor's NIC 2 must have **Promiscuous Mode: Accept**
   - vSphere → Networking → Port Group → Security → Promiscuous Mode → Accept

4. **Check cable/link:**
   - Menu option **2** — verify the monitor interface shows `UP`
   - If `DOWN`, check the physical cable or virtual NIC connection

### Sensor cannot reach SIEM

1. **Run diagnostics:**
   - Menu option **4** — check the SIEM connectivity line
   - If `UNREACHABLE`, verify the SIEM IP and port

2. **Check network:**
   - Can the sensor reach the SIEM IP? (diagnostics will test gateway and DNS)
   - Is there a firewall between the sensor and SIEM? Open port 9200 (or your configured port)

3. **Check SIEM is listening:**
   - On your SIEM server, verify the service is running and listening on the configured port

### High disk usage

- Menu option **1** (Status) — check `/nsm` disk usage
- If above 85%, the sensor will auto-clean old data
- Consider increasing the VM disk size in your hypervisor, then expand the partition

### Services not running

1. Menu option **1** — check which services show as stopped
2. Menu option **9** — restart all services or a specific one
3. If services keep crashing, generate a support bundle (option **10**) and contact support

### Cannot SSH into sensor

- Verify the management IP: check your DHCP server or the VM console
- Verify the management NIC is connected to the correct network
- Default credentials: `coderedai` / `coderedai`
- If password was changed and forgotten, contact your administrator

### Sensor performance issues

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| High CPU | Too much traffic for allocated CPUs | Increase vCPUs to 8+ |
| High memory | Large connection tables | Increase RAM to 16GB+ |
| Packet drops | NIC ring buffer full | Increase vCPUs, check SPAN rate |
| Disk filling fast | High traffic volume | Increase disk, reduce PCAP retention |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│            CodeRed AI Sensor - Quick Reference           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Default login:    coderedai / coderedai                 │
│  SSH:              ssh coderedai@<sensor-ip>             │
│                                                          │
│  Management NIC:   ens32 (needs IP on your network)     │
│  Monitor NIC:      ens34 (connect to SPAN/mirror port)  │
│                                                          │
│  SIEM port:        9200 (default)                       │
│  VM requirements:  4+ CPU, 8GB+ RAM, 100GB+ disk       │
│                                                          │
│  Important:                                              │
│  • SPAN port group must allow promiscuous mode          │
│  • Sensor needs network access to SIEM IP:port          │
│  • Mirror at minimum your internet uplink port          │
│  • Change default password after first login            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```
