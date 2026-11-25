# Development

## Prerequisites

- .NET 10 SDK (version pinned in `global.json`).
- PowerShell 7 for the scripts in `scripts/`.
- Windows for the full feature set; Linux and macOS build and run the cross-platform parts.

## Debug build

```powershell
dotnet build IPMaster.slnx           # warnings are errors
./scripts/dev.ps1                    # framework-dependent build in artifacts/dev/<runtime>/
```

`dev.ps1` prints the executable's full path, for example `artifacts/dev/win-x64/IPMaster.exe`. That folder holds
`IPMaster.exe` with its DLLs and symbols (it needs the .NET runtime); it is not the release package.

## Running

```powershell
./scripts/dev.ps1 -Run               # build and start the desktop app
./scripts/dev.ps1 -Cli /help         # build and run the command line
dotnet run --project src/IPMaster.Desktop                   # desktop app
dotnet run --project src/IPMaster.Desktop -- --cli /help    # command line
```

Set `IPMASTER_CONFIG_DIR` to a scratch folder while developing, so settings and history are not written next to the
build output. To debug, launch `src/IPMaster.Desktop/bin/Debug/net10.0/IPMaster.dll` (or the `IPMaster` executable
beside it) from your IDE, with `--cli <switches>` for the command line.

## Tests

```powershell
dotnet test --project tests/IPMaster.Tests
dotnet test --project tests/IPMaster.Tests -- --filter-class "*TransferCalculatorTests"
```

Tests need no network: protocol tests use loopback fixtures, Wi-Fi tests use synthetic providers, and UI tests render
windows headlessly in both themes (set `IPMASTER_UI_SNAPSHOTS=<folder>` to keep the PNGs). Process-level tests run the
built executable, so build the solution first. Formatting is checked with
`dotnet format IPMaster.slnx --verify-no-changes`.

## Release packages

```powershell
./scripts/publish.ps1 -Runtimes win-x64       # one runtime
./scripts/publish.ps1 -All                    # win, linux and osx, x64 and arm64
```

Each runtime is published in two flavours, both one `IPMaster` executable: **portable** (self-contained, ReadyToRun,
compressed) and **normal** (framework-dependent: needs the .NET 10 runtime; built without ReadyToRun, which made a
framework-dependent single file fail at start-up). Native libraries are extracted at first start where the runtime
needs them. `-Flavor Portable` or `-Flavor Normal` builds only one. The script runs the executable for the build machine's runtime with
`--cli /version` and refuses to overwrite a release folder that contains settings or history written by running it.

## Output directories

| Folder | Contents |
|---|---|
| `artifacts/dev/<runtime>/` | development build (`dev.ps1`) |
| `artifacts/release/<runtime>/`, `artifacts/release/<runtime>-portable/` | unpacked releases (`publish.ps1`); macOS: `IPMaster.app` |
| `artifacts/packages/` | `IPMaster-<version>-<runtime>[-portable].zip` / `.tar.gz` |
| `src/*/bin`, `src/*/obj` | ordinary SDK build output |

`./scripts/clean.ps1` removes all of these (`-WhatIf` lists them first). It stops if a folder contains IPMaster settings
or history unless `-DiscardUserData` is given.

## UI conventions

- Colours come only from `Styling/Tokens.axaml` (via `{DynamicResource}`, role classes from `Styling/Controls.axaml`, or
  `ThemedControl.Brush` in custom drawing); spacing and sizes from `Styling/Theme.cs`. A test rejects colour literals in
  views; a justified exception carries a `// theme-exception: <reason>` comment.
- Rows of actions use `Ui.Row` (it wraps); tool windows use `ToolKit.Layout` (configuration, actions, results, status).
- A new tool is one entry in `ToolEntries` (`Views/MainWindow.Tools.cs`); the menu, shortcuts, navigator and UI tests
  pick it up from there.
- Never point tools at real infrastructure in tests; use the loopback fixtures.
- Tables: every bound column sorts by value when its header is clicked (IP addresses by address, numbers with units by
  value, dates by time, text in natural order, empty values last); long values end in an ellipsis and show in full as a
  tooltip. Bind columns to the displayed text; do not add a custom comparer unless the value needs one.

## UI text

Short, direct English in the spirit of ASD-STE100 Simplified Technical English (an adaptation, not a compliance claim):
one term for one concept, active voice, labels without filler, errors as "Problem. Action." ("Host not found. Check the
name."), and the technical detail after a colon or in a tooltip. Keep standard network terms (DNS, DHCP, SNMP, IPv6,
MAC address, latency, packet loss).

| Action | Term | Not |
|---|---|---|
| begin / end an operation | Start / Stop | Begin, Run, Halt (Go only to navigate to a typed path) |
| suspend / continue | Pause / Resume | |
| read / write a saved configuration or file of IPMaster's own | Load / Save | Open |
| read / write an external file | Import / Export | |
| remove an item for good | Delete | Remove (except taking an item off a list, e.g. an attachment) |
| empty a field, list or selection | Clear | |
| update what is shown | Refresh | Reload |
| show an option or column | Show … | Display … |
| send a single request (HTTP, SNMP, DHCP) | Send | Run |
| detailed information | Properties / Details | |
