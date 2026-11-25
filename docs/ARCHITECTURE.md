# Architecture

## Solution structure

| Project | Responsibility |
|---|---|
| `src/IPMaster.Core` | Domain and application logic without OS I/O: target parsing and planning, the scan engine, results, exports, settings model, monitoring math, tool calculations (IP and transfer calculators, channel planning, path analysis). |
| `src/IPMaster.Infrastructure` | OS and network implementations: probes (ICMP, ARP, TCP, DNS, NetBIOS), remote queries (WMI, SNMP, SSH, scripts), discovery protocols, packet capture, settings and history storage, Wi-Fi access, service registration (`AddIPMaster()`). |
| `src/IPMaster.Cli` | Command-line mode: argument parsing (`CommandLineParser`), `CliApp` and `CliHost` (services, Ctrl+C, exit codes). A library; it never references the UI. |
| `src/IPMaster.Desktop` | The `IPMaster` executable: launcher, Avalonia desktop application (views, view models, design system). |
| `tests/IPMaster.Tests` | xUnit v3 tests: unit, integration with loopback fixtures, headless UI rendering, and process-level tests of the executable. |
| `tools/IPMaster.Bench`, `tools/IPMaster.Probe` | Development utilities: scheduler benchmark and protocol probes. Not shipped. |

## Dependency direction

```
IPMaster.Desktop ──> IPMaster.Cli ──> IPMaster.Infrastructure ──> IPMaster.Core
        └──────────────────────────────────┘
```

Core depends on nothing project-internal. Infrastructure implements Core's interfaces (`IIcmpProbe`,
`IHostNameResolver`, `IWifiProvider`, …). The CLI and the desktop app both compose the same services through
`ServiceRegistration.AddIPMaster()`.

## Main services

- **Scanning:** `ScanPlanner` turns ranges into a lazy, bounded target plan; `ScanEngine` runs a session with bounded
  channels and worker pools (liveness first, then enrichment); results flow to an `IScanResultSink`.
- **Continuous operations:** `LiveMonitor` (per-device ping schedule, ring buffers), `ContinuousOperations` (background
  rounds, events, notifications, per-round files), `HistoryStore` (SQLite device history).
- **Queries:** `QueryManager` with providers per kind (WMI, registry, SNMP, SSH, PowerShell, scripts, Nmap, Python).
- **Tools:** pure calculations in `Core/Tools` and `Core/Wifi`, network access in `Infrastructure/Tools` and
  `Infrastructure/Wifi`.

Unavailable capabilities (platform, privileges, missing drivers) are reported as typed states (`Observation<T>`,
`CapabilityStatus`), never as empty values.

## Entry point and GUI/CLI modes

`Program.Main` asks `LaunchRouter` for the mode:

| Arguments | Mode |
|---|---|
| none, `--gui …`, `--new-window`, `--range …` | desktop application |
| `--cli …`, a first argument starting with `/` (`/help`, `/range:…`), `--version` | command line (`CliHost`) |
| `--help` | launcher help |
| anything else | error message on stderr, exit code 1 |

CLI mode never loads Avalonia. On Windows the executable is a console-subsystem program, so shells wait for it and
receive stdout, stderr and the exit code. Its manifest sets `consoleAllocationPolicy=detached` (Windows 11 24H2 and
later), so starting it from Explorer opens no console window; on older Windows, GUI mode releases a console that no shell
shares (a brief console flash may be visible). Started from a shell, the GUI keeps the shell waiting until it closes;
use `start IPMaster` (cmd) or `Start-Process IPMaster` (PowerShell) to avoid that.

## Desktop application

MVVM with CommunityToolkit.Mvvm. The main window and Options are AXAML; tool windows and dialogs are built in code from
shared helpers (`Ui`, `ToolKit`). Look and feel come from the design system in `src/IPMaster.Desktop/Styling`: colour
tokens for light and dark themes, role classes (`status`, `error`, `hint`, `banner`, …) and `ThemedControl` for
custom-drawn charts. Every menu item is a command, so shortcuts and the navigator are generated from the menu.

## Settings and persistence

- `SettingsStore` reads and writes `ipmaster.settings.json` in `IPMASTER_CONFIG_DIR` if set, else next to the executable
  when that folder is writable (portable mode), else in the user's application-data folder (`IPMaster`).
- Several windows share one file: saves take a lock file and merge concurrent changes property by property.
- Credentials are protected with DPAPI (Windows) or an optional master password (AES-GCM, PBKDF2); secrets are never
  written to logs or exports.
- Device history is an SQLite database, `ipmaster.history.db`, next to the settings.
- Writes are atomic (temporary file and replace).
