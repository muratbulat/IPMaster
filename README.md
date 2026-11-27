# IPMaster

IPMaster is a portable network scanner and administration toolkit for Windows, Linux and macOS. One executable
provides a desktop application and a command line.

## Key capabilities

- IPv4/IPv6 range scanning (ICMP, ARP, TCP ports) with host names, MAC addresses, vendors and device types.
- Remote queries: WMI, registry, services, performance counters, SNMP v1/v2c/v3, SSH, PowerShell and scripts.
- Discovery: DHCP servers, UPnP, mDNS, WSD, ONVIF, duplicate IP addresses, Wake-on-LAN.
- Continuous operations: live monitoring (latency, loss, jitter), background scanning, device history and notifications.
- Network tools: DNS diagnostics and bulk audit, TCP, TLS, HTTP/API, LDAP, NTP, SMTP, syslog receiver, SNMP tester and
  interface monitor, LLDP/CDP topology, path and MTU analysis, iPerf throughput tests (with an installed iperf3 or iperf2), IP calculator, download/transfer calculator, device IP
  discovery with an isolated DHCP server, a Wi-Fi analyzer (Windows) and a KMS activation manager (Windows: Windows and Office
  licence status, official KMS client setup keys, confirmed activation against your own KMS host), a WinGet manager (updates and new installs)
  (Windows) and a read-only Group Policy viewer (Windows).
- Exports: CSV, TXT, HTML, XML, JSON, SQLite; light and dark themes; keyboard shortcuts and a command navigator.

## Supported operating systems

- Windows 10/11 (x64, Arm64): all features.
- Linux and macOS (x64, Arm64): scanning, exports, CLI and most tools; Windows-only features (WMI, registry, Wi-Fi
  analysis, some management actions) report "unsupported" with a reason.

## Requirements

- Release packages come in two flavours: **portable** (`…-portable`, self-contained, no .NET installation needed) and
  **normal** (smaller; needs the [.NET 10 runtime](https://dotnet.microsoft.com/download/dotnet/10.0)). Windows also has
  an MSI installer of the normal flavour.
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

## Release packages

```powershell
./scripts/publish.ps1 -Runtimes win-x64     # or -All for Windows, Linux and macOS
```

The packages are written to `artifacts/packages/`: `IPMaster-<version>-<runtime>-portable.zip` (self-contained) and
`IPMaster-<version>-<runtime>.zip` (needs the .NET 10 runtime); Linux and macOS use `.tar.gz`. The unpacked releases are
in `artifacts/release/<runtime>-portable/` and `artifacts/release/<runtime>/`. Unpack and run `IPMaster`; settings are
stored next to the executable when that folder is writable, otherwise in the user's application-data folder.
Every package (and the MSI) also contains `LICENSE`, `THIRD-PARTY-NOTICES.md`, `licenses/` and `SOURCE.txt`, which
names the source commit the package was built from.

### Windows Installer (MSI)

```powershell
./scripts/publish.ps1 -Format InstallerMSI -Runtimes win-x64   # -All builds the MSIs with the other packages
```

`artifacts/packages/IPMaster-<version>-win-x64-setup-framework-dependent.msi` installs the framework-dependent
`IPMaster.exe` for all users in `Program Files\IPMaster`, adds a Start Menu shortcut and an Installed Apps entry, and
supports repair and major upgrades. It needs the .NET 10 runtime: the installer checks for it and stops with a link
when it is missing; it never downloads anything. Settings and history stay in `%APPDATA%\IPMaster` and are not removed
on uninstall. `SHA256SUMS.txt` lists the checksums of all packages. Built with WiX Toolset v5 (MS-RL).

```powershell
msiexec /i IPMaster-0.9.0-win-x64-setup-framework-dependent.msi                         # interactive
msiexec /i IPMaster-0.9.0-win-x64-setup-framework-dependent.msi /qn /norestart          # silent
msiexec /i IPMaster-0.9.0-win-x64-setup-framework-dependent.msi /qn DESKTOPSHORTCUT=1   # with a desktop shortcut
msiexec /x IPMaster-0.9.0-win-x64-setup-framework-dependent.msi /qn /norestart          # silent uninstall
```

A newer installed version is never replaced by an older MSI; uninstall it first.

## Website

<https://muratbulat.github.io/ipmaster/> is the static site in `website/` (plain HTML, CSS and a small script; no build
step: the folder is published as is), deployed by `.github/workflows/pages.yml` on pushes to `main` that change it.
One-time setup: **Settings → Pages → Source: GitHub Actions**. Preview locally with:

```powershell
python -m http.server 8080 -d website      # then open http://localhost:8080/
```

Custom domain (planned: `getipmaster.xyz`, not configured yet). With an Actions-deployed site no `CNAME` file is needed:
verify the domain for the account (Settings → Pages → Verified domains), enter it under **Settings → Pages → Custom
domain**, create the DNS records listed in GitHub's
[custom-domain guide](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site)
at the registrar, then tick **Enforce HTTPS** once the certificate is issued. Afterwards update the `canonical` and
`og:` URLs in `website/index.html` and `website/license/`.

## License

Copyright (C) 2026 Murat Bulat.

IPMaster is free software, licensed under the **GNU General Public License version 3 only** (SPDX: `GPL-3.0-only`).
The full text is in [LICENSE](LICENSE).

- You may use, study and modify IPMaster under the terms of the GPLv3.
- If you distribute IPMaster or a modified version, you must do so under the GPLv3: keep the copyright and licence
  notices, mark your changes, and provide the corresponding source code.
- IPMaster comes with no warranty, to the extent permitted by law (GPLv3 sections 15 and 16).
- Third-party components keep their own licences: see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Distribution and source details: [docs/LICENSING.md](docs/LICENSING.md). The GPL applies to the source in this
repository from the commit that added `LICENSE`; it does not change the terms of packages published before then.
