<#
.SYNOPSIS
  Removes generated build output: artifacts/dev, artifacts/release, artifacts/packages, artifacts/ci, the former
  artifacts/portable, and bin/obj under src, tests and tools.
.DESCRIPTION
  User data is never deleted silently. If a folder to be removed contains files the portable app writes next to itself
  (ipmaster.settings.json*, ipmaster.history.db*), the script lists them and stops; move them, or pass
  -DiscardUserData to delete them too. Settings in %APPDATA%\IPMaster (or IPMASTER_CONFIG_DIR) are never touched.
.EXAMPLE
  ./scripts/clean.ps1 -WhatIf       # show what would be removed
  ./scripts/clean.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch] $DiscardUserData)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targets = @('dev', 'release', 'packages', 'ci', 'portable', 'github-release') | ForEach-Object { Join-Path $repo 'artifacts' $_ } | Where-Object { Test-Path $_ }
$targets += @('src', 'tests', 'tools') | ForEach-Object { Join-Path $repo $_ } | Where-Object { Test-Path $_ } |
    ForEach-Object { Get-ChildItem $_ -Recurse -Directory -Include bin, obj -ErrorAction SilentlyContinue } |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/].*[\\/](bin|obj)$' } | Select-Object -ExpandProperty FullName

$patterns = @('ipmaster.settings.json*', 'ipmaster.history.db*')
$userData = @($targets | ForEach-Object { Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue } |
    Where-Object { $n = $_.Name; $patterns | Where-Object { $n -like $_ } })
if ($userData.Count -gt 0 -and -not $DiscardUserData) {
    $userData | ForEach-Object { Write-Host "  user data: $($_.FullName)" }
    throw "Generated folders contain IPMaster user data (above). Move it elsewhere, or pass -DiscardUserData to delete it with the build output."
}

foreach ($t in $targets) {
    if ($PSCmdlet.ShouldProcess($t, 'Remove')) {
        Remove-Item -Recurse -Force $t
        Write-Host "Removed $t"
    }
}
