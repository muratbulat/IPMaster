# IPMaster

IPMaster is a portable network scanner and administration toolkit for Windows, Linux and macOS. One executable
provides a desktop application and a command line.

## Key capabilities

- IPv4/IPv6 range scanning (ICMP, ARP, TCP ports) with host names, MAC addresses, vendors and device types.
- Remote queries: WMI, registry, services, performance counters, SNMP v1/v2c/v3, SSH, PowerShell and scripts.
- Discovery: DHCP servers, UPnP, mDNS, WSD, ONVIF, duplicate IP addresses, Wake-on-LAN.
- Continuous operations: live monitoring (latency, loss, jitter), background scanning, device history and notifications.
- Network tools: DNS diagnostics and bulk audit, TCP, TLS, HTTP/API, LDAP, NTP, SMTP, syslog receiver, SNMP tester and
  interface monitor, LLDP/CDP topology, path and MTU analysis, IP calculator, download/transfer calculator, device IP
  discovery with an isolated DHCP server, and a Wi-Fi analyzer (Windows).
- Exports: CSV, TXT, HTML, XML, JSON, SQLite; light and dark themes; keyboard shortcuts and a command navigator.

## Supported operating systems

- Windows 10/11 (x64, Arm64): all features.
- Linux and macOS (x64, Arm64): scanning, exports, CLI and most tools; Windows-only features (WMI, registry, Wi-Fi
  analysis, some management actions) report "unsupported" with a reason.

## Requirements

- Release packages are self-contained: no .NET installation is needed.
- Building from source needs the .NET 10 SDK (see `global.json`).
- Optional: Npcap (Windows) or libpcap for packet capture features; Nmap or Python for their query types.

## Build

```powershell
dotnet build IPMaster.slnx
dotnet test --project tests/IPMaster.Tests
./scripts/dev.ps1                  # development build: artifacts/dev/<runtime>/IPMaster(.exe)
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for details.

## Usage

```powershell
IPMaster                           # desktop application
IPMaster --cli /help               # command-line help
IPMaster --cli /range:192.168.1.0/24 /auto:results.csv
IPMaster /version                  # slash switches select the command line directly
IPMaster --help                    # launcher options
```

The command line writes results to stdout or the given file, diagnostics to stderr, and returns an exit code
(0 success, 1 usage, 2 targets, 3 settings, 4 output, 6 scan failed, 130 cancelled).

## Portable release

```powershell
./scripts/publish.ps1 -Runtimes win-x64     # or -All for Windows, Linux and macOS
```

The package is written to `artifacts/packages/IPMaster-<version>-<runtime>.zip` (Windows) or `.tar.gz` (Linux, macOS);
the unpacked release is in `artifacts/release/<runtime>/`. Unpack and run `IPMaster`; settings are stored next to the
executable when that folder is writable, otherwise in the user's application-data folder.

## License

No license has been published for this project yet. All rights reserved by the author, Murat Bulat.
