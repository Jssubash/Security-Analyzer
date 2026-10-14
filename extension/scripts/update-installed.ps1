<#
.SYNOPSIS
  Installs the latest Security Analyzer build into every Mendix app that already has it.

.DESCRIPTION
  Looks for apps under -AppsRoot (by default your Mendix folder, %USERPROFILE%\Mendix): any folder
  with a .mpr file. Apps that already contain extensions\SecurityAnalyzer are updated; with -All,
  every app found gets the extension. Each app is installed with install.ps1, so the files copied
  are exactly the same as installing one app by hand.

  Close Studio Pro first: while an app is open, Studio Pro has the extension loaded and only
  picks up the new build when it starts again.

.EXAMPLE
  .\scripts\update-installed.ps1
  .\scripts\update-installed.ps1 -Build
  .\scripts\update-installed.ps1 -AppsRoot "D:\Projects\Mendix" -All
  .\scripts\update-installed.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$AppsRoot = (Join-Path $env:USERPROFILE 'Mendix'),
  [switch]$All,
  [switch]$Build
)

$ErrorActionPreference = 'Stop'
$install = Join-Path $PSScriptRoot 'install.ps1'

if (-not (Test-Path $AppsRoot)) {
  throw "The folder '$AppsRoot' does not exist. Pass -AppsRoot with the folder that holds your Mendix apps."
}

# An app is a folder holding a .mpr file: the root itself, or a folder directly below it.
$apps = @(Get-Item $AppsRoot) + @(Get-ChildItem -Path $AppsRoot -Directory) |
  Where-Object { Get-ChildItem -Path $_.FullName -Filter *.mpr -File -ErrorAction SilentlyContinue | Select-Object -First 1 }

$targets = $apps | Where-Object { $All -or (Test-Path (Join-Path $_.FullName 'extensions\SecurityAnalyzer')) }
if (-not $targets) {
  $hint = if ($All) { '' } else { ' None of them has the extension yet: run with -All, or install one app with install.ps1.' }
  Write-Host "Found $(@($apps).Count) Mendix app(s) under $AppsRoot.$hint"
  return
}

if (Get-Process -Name studiopro -ErrorAction SilentlyContinue) {
  Write-Warning 'Studio Pro is running. Apps open in it keep the old extension until Studio Pro is restarted.'
}

$built = -not $Build
$ok = 0
$failed = @()
foreach ($app in $targets) {
  if (-not $PSCmdlet.ShouldProcess($app.FullName, 'Install Security Analyzer')) { continue }
  try {
    # Build once, on the first app; the rest reuse that build.
    if ($built) { & $install -AppDirectory $app.FullName 6>$null | Out-Null }
    else { & $install -AppDirectory $app.FullName -Build 6>$null | Out-Null; $built = $true }
    Write-Host "  updated  $($app.Name)"
    $ok++
  }
  catch {
    Write-Host "  FAILED   $($app.Name): $($_.Exception.Message)" -ForegroundColor Red
    $failed += $app.Name
  }
}

Write-Host ''
Write-Host "Installed into $ok app(s)$(if ($failed) { "; failed: $($failed -join ', ')" })."
Write-Host 'Start Studio Pro with --enable-extension-development and open the app to use the new version.'
if ($failed) { exit 1 }
