# Watchful Eye

[![Build Windows installer](https://github.com/038-Alav/WatchfulEye/actions/workflows/build-windows-installer.yml/badge.svg)](https://github.com/038-Alav/WatchfulEye/actions/workflows/build-windows-installer.yml)
[![Latest Release](https://img.shields.io/github/v/release/038-Alav/WatchfulEye?display_name=tag)](https://github.com/038-Alav/WatchfulEye/releases)

Copyright © 2026. All rights reserved.
Watchful Eye is proprietary software. No license is granted to use, modify, reproduce, or distribute this software.

Version: 0.2.0 — Phase 4 Proof of Concept

Watchful Eye is a native desktop application for discovering devices on one
IPv4 network and maintaining a JSON-backed device inventory. Its design keeps
discovery, identity resolution, fingerprinting, classification, persistence,
and presentation as separate responsibilities.

## Current capabilities

### Discovery and inventory

- Enumerate active IPv4 network interfaces and select a scan interface.
- Discover local devices using ARP.
- Collect passive DHCP hostname evidence.
- Discover advertised mDNS and NetBIOS names/services when devices expose them.
- Resolve MAC addresses through the bundled IEEE OUI registry.
- Perform reverse DNS lookups.
- Associate observations with internal device UUIDs; IP and MAC addresses are
  treated as evidence rather than permanent identity.
- Preserve append-only scan and observation history in JSON.

### Phase 4: fingerprinting and classification

- Probe a curated set of TCP ports on devices associated with the current scan.
- Record open TCP ports as `PORT` observations.
- Infer likely services from known port numbers as `SERVICE` observations.
- Collect ICMP reply TTL values when Scapy packet operations are available.
- Produce cautious OS-family hints from TTL; these are heuristics, not verified
  operating-system identification.
- Combine hostname, manufacturer, port, service, and OS-hint evidence into an
  explainable device classification.
- Store the classification as a `DEVICE_TYPE` observation and its supporting
  rationale as a structured `OTHER` observation.
- Inspect a device's historical evidence and latest classification rationale
  from the Devices tab by selecting a row and opening **View device details**,
  or double-clicking a device.
- Display stored UTC timestamps in the computer's local timezone while keeping
  persisted timestamps timezone-aware and in UTC.
- Keep the full evidence history available in the detail view, including the
  source, observation type, value, timestamp and recorded confidence.

The initial classifier supports computers, servers, mobile devices, network
infrastructure, printers, cameras/video devices, smart-TV/media devices, and
IoT devices. `Unknown` is a valid result when evidence is weak or conflicting.
The confidence value is a heuristic support score, not a calibrated
probability.

### Active-probe safety limits

- Only IPv4 addresses observed and associated with a device during the current
  scan are eligible for fingerprinting.
- Targets must fall inside the selected scan CIDR. Stale inventory IP addresses
  are never probed solely because they remain stored.
- At most 256 device/IP targets are fingerprinted per scan, with at most 32
  concurrent probe tasks. TCP sockets and ICMP packets are bound to the IP
  address of the interface selected for discovery.
- TCP connect timeouts default to 0.4 seconds. The default probe list is curated
  and is not a full 65,535-port scan.
- Only successful TCP connections are recorded as open ports. A closed or
  filtered port does not prove that a service is absent.
- TTL fingerprinting depends on ICMP replies and packet-capture capabilities.
  On Windows, Scapy packet operations require a suitable Npcap installation and
  permissions. If TTL collection fails, TCP probing and discovery can continue.

Only scan networks and devices you own or are authorized to assess.

## Requirements

- Python 3.11 or newer.
- Windows: Npcap installed for Scapy packet operations.
- Linux: raw packet access may require root or `CAP_NET_RAW`.

## Download and install (Windows)

Download the latest `WatchfulEye-Setup-*.exe` from the [GitHub Releases page](https://github.com/038-Alav/WatchfulEye/releases). Run the installer and follow the setup wizard. Python is not required on the target computer.

Watchful Eye uses Npcap for Windows packet operations such as ARP discovery and packet capture. Npcap is a separate prerequisite and must be installed independently from the [official Npcap website](https://npcap.com/#download); it is not bundled with Watchful Eye.

The application stores its inventory and logs under `%LOCALAPPDATA%\WatchfulEye`. Uninstalling the application intentionally preserves this user data.

## Windows setup (development)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m watchfuleye
```

## Tests

Run the automated suite from the project root:

```powershell
python -m pytest -q
```

The tests mock active network probes; they do not require a live target network.

## Data and privacy

The application stores its device inventory, scans, observations, and logs as
local files. On Windows, mutable application data is stored under
`%LOCALAPPDATA%\WatchfulEye` (with `data` and `logs` subdirectories), not in
Program Files. On Linux it uses `~/.local/share/watchful-eye` unless
`XDG_DATA_HOME` is set. These files contain network metadata and should not be
committed to source control or shared without review.

## Windows installer

The supported Windows packaging flow creates a PyInstaller onedir application
and wraps it with Inno Setup. See [`packaging/README.md`](packaging/README.md)
and run `scripts/build_windows_installer.ps1` from PowerShell on Windows.
Python 3.12 x64 and Inno Setup 6 are required. Npcap is installed separately;
it is not bundled with Watchful Eye. The uninstaller deliberately preserves
per-user inventory and history.
