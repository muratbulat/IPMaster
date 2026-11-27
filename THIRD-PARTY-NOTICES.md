# Third-party notices

IPMaster is Copyright (C) 2026 Murat Bulat and licensed under the GNU General Public License version 3 only
(GPL-3.0-only, see `LICENSE`). The release packages also contain the third-party components below. Each keeps its own
licence; none is relicensed by IPMaster's licence. This list covers the packages restored for `src/IPMaster.Desktop`
(the one shipped executable) and the files the release packages and MSI add. Licences and copyright lines are taken
from each package's NuGet metadata (`.nuspec`) or the licence file inside the package; see the project for its full
licence file.

## Components

| Component | Version | Licence | Copyright (package metadata) |
|---|---|---|---|
| Avalonia, Avalonia.Desktop, .Themes.Fluent, .Skia, .HarfBuzz, .Win32, .X11, .FreeDesktop, .FreeDesktop.AtSpi, .Native, .Remote.Protocol | 12.1.6 | MIT | Copyright 2013-2026 © The AvaloniaUI Project |
| Avalonia.Controls.DataGrid | 12.1.2 | MIT | Copyright 2013-2026 © The AvaloniaUI Project |
| Avalonia.Angle.Windows.Natives (ANGLE, Windows) | 2.1.27548.20260419 | BSD-3-Clause (`licenses/ANGLE-LICENSE.txt`) | Copyright 2018 The ANGLE Project Authors |
| MicroCom.Runtime | 0.11.6 | MIT | Copyright 2021 © Nikita Tsukanov |
| Tmds.DBus.Protocol | 0.94.1 | MIT | Tom Deseyn |
| SkiaSharp (+ native assets) | 3.119.4 | MIT; bundled native code: `licenses/SkiaSharp-HarfBuzzSharp-THIRD-PARTY-NOTICES.txt` | © Microsoft Corporation |
| HarfBuzzSharp (+ native assets) | 8.3.1.3 | MIT; bundled native code: same notices file | © Microsoft Corporation |
| CommunityToolkit.Mvvm | 8.4.2 | MIT | (c) .NET Foundation and Contributors |
| Microsoft.Extensions.* (Configuration, DependencyInjection, Logging, Options, Primitives) | 10.0.15 | MIT | © Microsoft Corporation |
| Microsoft.Data.Sqlite, Microsoft.Data.Sqlite.Core | 10.0.15 | MIT | © Microsoft Corporation |
| SQLitePCLRaw.bundle_e_sqlite3, .core, .lib.e_sqlite3, .provider.e_sqlite3 | 2.1.13 | Apache-2.0 (`licenses/Apache-2.0.txt`) | Copyright 2014-2024 SourceGear, LLC |
| SQLite (native e_sqlite3, inside SQLitePCLRaw.lib.e_sqlite3) | — | Public domain | — |
| System.Management, .ServiceProcess.ServiceController, .Diagnostics.PerformanceCounter, .Diagnostics.EventLog, .Security.Cryptography.ProtectedData, .DirectoryServices.Protocols, .CodeDom, .Configuration.ConfigurationManager | 10.0.15 | MIT | © Microsoft Corporation |
| System.Security.Cryptography.Pkcs | 10.0.13 | MIT | © Microsoft Corporation |
| Lextm.SharpSnmpLib | 12.5.7 | MIT | Copyright (c) 2008-2024 Malcolm Crowe, Lex Li, and other contributors |
| SSH.NET | 2026.0.1 | MIT | Copyright © Renci 2010-2026 |
| BouncyCastle.Cryptography | 2.7.0 | MIT | Copyright © Legion of the Bouncy Castle Inc. 2000-2026 |
| MailKit, MimeKit | 4.18.2 | MIT | .NET Foundation and Contributors |
| .NET runtime (portable packages only: self-contained) and the .NET application host | 10.0 | MIT; third-party parts: `licenses/dotnet-runtime-THIRD-PARTY-NOTICES.txt` | Copyright (c) .NET Foundation and Contributors |
| WiX Toolset v5 runtime parts in the MSI (the Netfx extension's .NET runtime check) | 5.0.2 | MS-RL | Copyright (c) .NET Foundation and contributors |

Portions of this software are copyright © The FreeType Project (www.freetype.org). All rights reserved.
(FreeType is used under the FreeType License, one of its two offered licences; it is part of the SkiaSharp native code.)

Build and test tools that are not shipped (xunit.v3, Avalonia.Headless, Avalonia.BuildServices, the .NET SDK and the
WiX compiler) are not listed.

## MIT License

The MIT-licensed components above are provided under the following terms, with the copyright notices listed in the
table:

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Microsoft Reciprocal License (MS-RL), WiX Toolset

The MSI contains the WiX Netfx extension's custom action and helper programs for the .NET runtime check
(`Wix4NetFxCA`, `Wix4NetCheck_*` in the MSI's Binary table). Its source code is available from the WiX Toolset
project: https://github.com/wixtoolset/wix (tag v5.0.2), under the Microsoft Reciprocal License:
https://opensource.org/license/ms-rl. It is a separate installer program that IPMaster does not link to.

## Other files

- `licenses/Apache-2.0.txt`: the Apache License 2.0 (SQLitePCLRaw).
- `licenses/ANGLE-LICENSE.txt`: ANGLE's licence, copied unchanged from Avalonia.Angle.Windows.Natives.
- `licenses/SkiaSharp-HarfBuzzSharp-THIRD-PARTY-NOTICES.txt`: copied unchanged from SkiaSharp.NativeAssets.Win32 3.119.4
  (identical in the Linux package and in HarfBuzzSharp.NativeAssets.Win32 8.3.1.3).
- `licenses/dotnet-runtime-THIRD-PARTY-NOTICES.txt`: copied unchanged from Microsoft.NETCore.App.Runtime.win-x64 10.0.15.
