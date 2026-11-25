<#
.SYNOPSIS
  Builds the IPMaster release packages: one executable per platform (GUI and CLI), no installer, in two flavours:
    portable   self-contained: runs without an installed .NET (larger)
    normal     framework-dependent: needs the .NET 10 runtime installed (smaller)
.DESCRIPTION
  Output (relative to -Root, default <repo>/artifacts):
    release/<rid>/ and release/<rid>-portable/   the unpacked packages: IPMaster.exe (Windows) or IPMaster (Linux),
                                                 IPMaster.app (macOS), README.md
    packages/IPMaster-<version>-<rid>[-portable].zip      Windows
    packages/IPMaster-<version>-<rid>[-portable].tar.gz   Linux and macOS (executables keep mode 0755)
  Single-file (portable: self-contained, ReadyToRun and compressed); native libraries are bundled and extracted at first run where
  the runtime needs them (so the app may create files in a temp folder: it is one file to ship, not one file at run time).
  The macOS bundle is not signed or notarised (D-066). The executable built for the machine's own platform is run
  with --cli /version to check it.
.EXAMPLE
  ./scripts/publish.ps1                                   # win-x64 and win-arm64
  ./scripts/publish.ps1 -Runtimes win-x64
  ./scripts/publish.ps1 -All                              # every supported RID
  ./scripts/publish.ps1 -Flavor Portable                  # only the self-contained packages
  Refuses to replace a release folder that holds settings or history written by running the portable build there,
  unless -DiscardUserData is given. User data is never packaged.
#>
param(
    [string[]] $Runtimes = @('win-x64', 'win-arm64'),
    [switch] $All,
    [string] $Configuration = 'Release',
    [string] $Root = (Join-Path $PSScriptRoot '..' 'artifacts'),
    [ValidateSet('Both', 'Portable', 'Normal')] [string] $Flavor = 'Both',
    [switch] $DiscardUserData
)
$ErrorActionPreference = 'Stop'
if ($All) { $Runtimes = @('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64', 'osx-x64', 'osx-arm64') }
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$version = ([xml](Get-Content (Join-Path $repo 'Directory.Build.props'))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$releaseRoot = Join-Path $Root 'release'
$packages = Join-Path $Root 'packages'
New-Item -ItemType Directory -Force $releaseRoot, $packages | Out-Null

# Files the portable app writes next to itself (settings with encrypted credentials, history DB, lock/journal files).
# They belong to whoever ran the build from this folder: never delete them silently, never ship them in an archive.
$userDataPatterns = @('ipmaster.settings.json*', 'ipmaster.history.db*')
function Get-UserData([string] $dir) {
    if (-not (Test-Path $dir)) { return @() }
    @(Get-ChildItem $dir -Recurse -File | Where-Object { $n = $_.Name; $userDataPatterns | Where-Object { $n -like $_ } })
}

# .tar.gz with explicit modes: executables 0755, everything else 0644.
function Write-TarGz([string] $sourceDir, [string] $prefix, [string] $archive, [string[]] $executables) {
    if (Test-Path $archive) { Remove-Item $archive }
    $fs = [System.IO.File]::Create($archive)
    try {
        $gz = [System.IO.Compression.GZipStream]::new($fs, [System.IO.Compression.CompressionLevel]::Optimal)
        $tar = [System.Formats.Tar.TarWriter]::new($gz, [System.Formats.Tar.TarEntryFormat]::Pax, $false)
        try {
            $base = (Resolve-Path $sourceDir).Path.TrimEnd('\', '/')
            $d0 = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::Directory, "$prefix/")
            $d0.Mode = [System.IO.UnixFileMode]493   # 0755
            $tar.WriteEntry($d0)
            foreach ($d in Get-ChildItem $base -Recurse -Directory | Sort-Object FullName) {
                $rel = $d.FullName.Substring($base.Length + 1).Replace('\', '/')
                $e = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::Directory, "$prefix/$rel/")
                $e.Mode = [System.IO.UnixFileMode]493
                $tar.WriteEntry($e)
            }
            foreach ($f in Get-ChildItem $base -Recurse -File | Sort-Object FullName) {
                $rel = $f.FullName.Substring($base.Length + 1).Replace('\', '/')
                $e = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, "$prefix/$rel")
                $e.Mode = if ($executables -contains $rel) { [System.IO.UnixFileMode]493 } else { [System.IO.UnixFileMode]420 } # 0755 / 0644
                $e.ModificationTime = $f.LastWriteTimeUtc
                $stream = [System.IO.File]::OpenRead($f.FullName)
                try { $e.DataStream = $stream; $tar.WriteEntry($e) } finally { $stream.Dispose() }
            }
        }
        finally { $tar.Dispose(); $gz.Dispose() }
    }
    finally { $fs.Dispose() }
}

$hostRid = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier -replace '^(win|linux|osx)[^-]*-', '$1-'
$flavours = @(
    @{ Suffix = '-portable'; SelfContained = $true }
    @{ Suffix = ''; SelfContained = $false }
) | Where-Object { $Flavor -eq 'Both' -or ($Flavor -eq 'Portable') -eq $_.SelfContained }
foreach ($rid in $Runtimes) {
foreach ($fl in $flavours) {
    $suffix = $fl.Suffix
    $sc = if ($fl.SelfContained) { 'true' } else { 'false' }
    $compress = if ($fl.SelfContained) { 'true' } else { 'false' } # compression needs a self-contained build
    # ReadyToRun only for the portable flavour: a framework-dependent single file built with it failed fast at start-up
    # (0xC0000602) on .NET 10.0.15; without it, it starts normally (verified with --cli /version below)
    $r2r = $compress
    $dest = Join-Path $releaseRoot "$rid$suffix"
    $data = Get-UserData $dest
    if ($data.Count -gt 0 -and -not $DiscardUserData) {
        throw "$dest contains user data from running the portable build there ($(($data | ForEach-Object Name) -join ', ')). Move it elsewhere, or pass -DiscardUserData to delete it."
    }
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    $bin = if ($rid -like 'osx-*') { Join-Path $dest 'IPMaster.app' 'Contents' 'MacOS' } else { $dest }
    dotnet publish (Join-Path $repo 'src/IPMaster.Desktop') -c $Configuration -r $rid --self-contained $sc `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none `
        -p:PublishReadyToRun=$r2r -p:EnableCompressionInSingleFile=$compress `
        -o $bin
    if ($LASTEXITCODE -ne 0) { throw "publish failed ($rid$suffix)" }
    # third-party native symbol files (SkiaSharp, HarfBuzz) are not needed at run time and add ~100 MB
    Get-ChildItem $dest -Recurse -Filter *.pdb | Remove-Item -Force
    $exe = if ($rid -like 'win-*') { 'IPMaster.exe' } else { 'IPMaster' }
    $exePath = Join-Path $bin $exe
    if (-not (Test-Path $exePath)) { throw "missing $exe in $bin" }
    $others = @(Get-ChildItem $bin -File | Where-Object { $_.Name -ne $exe -and ($_.Extension -eq '.exe' -or ($rid -notlike 'win-*' -and $_.Extension -eq '' -and $_.Name -ne 'README')) })
    if ($others.Count -gt 0) { throw "more than one executable in ${bin}: $(($others | ForEach-Object Name) -join ', ')" }
    if ($rid -eq $hostRid) {
        $v = & $exePath --cli /version
        if ($LASTEXITCODE -ne 0 -or $v -notmatch '^IPMaster \d+\.\d+\.\d+') { throw "the published executable did not run: $v" }
        Write-Host "Checked: $v"
    }

    if ($rid -like 'win-*') {
        Copy-Item (Join-Path $repo 'README.md') $dest
        $zip = Join-Path $packages "IPMaster-$version-$rid$suffix.zip"
        if (Test-Path $zip) { Remove-Item $zip }
        Compress-Archive -Path (Join-Path $dest '*') -DestinationPath $zip
        Write-Host "Release:  $((Resolve-Path $exePath).Path)"
        Write-Host "Package:  $((Resolve-Path $zip).Path)"
        continue
    }

    if ($rid -like 'osx-*') {
        $contents = Join-Path $dest 'IPMaster.app' 'Contents'
        New-Item -ItemType Directory -Force (Join-Path $contents 'Resources') | Out-Null
        Copy-Item (Join-Path $repo 'src' 'IPMaster.Desktop' 'Assets' 'ipmaster.png') (Join-Path $contents 'Resources')
        @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>IPMaster</string>
  <key>CFBundleDisplayName</key><string>IPMaster</string>
  <key>CFBundleIdentifier</key><string>app.ipmaster.desktop</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>IPMaster</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
"@ | Set-Content -Encoding utf8NoBOM (Join-Path $contents 'Info.plist')
        $execs = @('IPMaster.app/Contents/MacOS/IPMaster')
    }
    else {
        $execs = @('IPMaster')
    }

    Copy-Item (Join-Path $repo 'README.md') $dest
    $archive = Join-Path $packages "IPMaster-$version-$rid$suffix.tar.gz"
    Write-TarGz $dest "IPMaster-$version-$rid$suffix" $archive $execs
    Write-Host "Release:  $((Resolve-Path $exePath).Path)"
    Write-Host "Package:  $((Resolve-Path $archive).Path)"
}
}
