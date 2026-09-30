<#
.SYNOPSIS
  Installs the Security Analyzer extension into a Mendix app.

.DESCRIPTION
  Copies the built extension (manifest.json, SecurityAnalyzer.dll, wwwroot\) into
  <AppDirectory>\extensions\SecurityAnalyzer\, which is where Studio Pro looks for an app's
  extensions. Run `npm run build` and `npm run build:dotnet` first, or pass -Build.

.EXAMPLE
  .\scripts\install.ps1 -AppDirectory "C:\Mendix\MyApp"
  .\scripts\install.ps1 -AppDirectory "C:\Mendix\MyApp" -Build
#>
param(
  [Parameter(Mandatory = $true)][string]$AppDirectory,
  [switch]$Build
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not (Get-ChildItem -Path $AppDirectory -Filter *.mpr -ErrorAction SilentlyContinue)) {
  throw "No .mpr file found in '$AppDirectory'. Point -AppDirectory at the folder that contains the app's .mpr."
}

if ($Build) {
  # The shared packages (rules, engine, scoring) must be built before the extension can type-check.
  $repoRoot = $root
  while ($repoRoot -and -not (Select-String -Path (Join-Path $repoRoot "package.json") -Pattern '"workspaces"' -Quiet -ErrorAction SilentlyContinue)) {
    $repoRoot = Split-Path -Parent $repoRoot
  }
  if (-not $repoRoot) { throw "Could not find the repository root (a package.json with workspaces)." }
  Push-Location $repoRoot
  try {
    npm run build:packages
    if ($LASTEXITCODE -ne 0) { throw "npm run build:packages failed" }
  } finally { Pop-Location }

  Push-Location $root
  try {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
    dotnet build dotnet\SecurityAnalyzer.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed' }
  } finally { Pop-Location }
}

$output = Join-Path $root 'dotnet\bin\Release\net8.0'
if (-not (Test-Path (Join-Path $output 'SecurityAnalyzer.dll'))) {
  throw "The extension is not built yet. Run this script with -Build."
}

$target = Join-Path $AppDirectory 'extensions\SecurityAnalyzer'
New-Item -ItemType Directory -Force -Path (Join-Path $target 'wwwroot') | Out-Null
Copy-Item (Join-Path $output 'manifest.json') $target -Force
Copy-Item (Join-Path $output 'SecurityAnalyzer.dll') $target -Force
Copy-Item (Join-Path $output 'wwwroot\*') (Join-Path $target 'wwwroot') -Force

Write-Host "Installed to $target"
Write-Host 'Start Studio Pro with --enable-extension-development, open the app, then use Extensions > SecurityAnalyzer > Open Security Analyzer.'
