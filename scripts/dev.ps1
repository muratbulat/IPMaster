<#
.SYNOPSIS
  Development build of IPMaster into one predictable folder: artifacts/dev/<rid>/IPMaster(.exe).
.DESCRIPTION
  Framework-dependent (needs the .NET SDK/runtime installed), with debug symbols, so the folder holds IPMaster(.exe) plus
  its DLLs: run or debug that executable. This is not the release package (scripts/publish.ps1 builds the single-file
  release). Files the app writes there (portable settings, history) are never deleted by this script.
.EXAMPLE
  ./scripts/dev.ps1                 # build, print the executable's path
  ./scripts/dev.ps1 -Run            # build and start the desktop app
  ./scripts/dev.ps1 -Cli /help      # build and run the command line
  ./scripts/dev.ps1 -Configuration Release -Runtime linux-x64
#>
param(
    [string] $Configuration = 'Debug',
    [string] $Runtime = ([System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier -replace '^(win|linux|osx)[^-]*-', '$1-'),
    [switch] $Run,
    [string[]] $Cli
)
$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$out = Join-Path $repo 'artifacts' 'dev' $Runtime
dotnet publish (Join-Path $repo 'src/IPMaster.Desktop') -c $Configuration -r $Runtime --self-contained false -o $out -p:PublishSingleFile=false
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
$exe = Join-Path $out ($(if ($Runtime -like 'win-*') { 'IPMaster.exe' } else { 'IPMaster' }))
if (-not (Test-Path $exe)) { throw "missing $exe" }
Write-Host "Executable: $((Resolve-Path $exe).Path)"
if ($Cli) { & $exe --cli @Cli; exit $LASTEXITCODE }
if ($Run) { Start-Process $exe }
