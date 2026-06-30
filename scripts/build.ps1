#!/usr/bin/env pwsh
# Build the NoMercy SMBLibrary fork into output/managed/.
# SMBLibrary is pure managed (netstandard2.0): one set of DLLs runs on every
# platform and runtime the media server targets, so there is no per-OS build
# step (unlike the native nomercy-libnfs).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root 'src/SMBLibrary/SMBLibrary.csproj'
$out  = Join-Path $root 'output/managed'

New-Item -ItemType Directory -Force -Path $out | Out-Null

dotnet build $proj -c Release -f netstandard2.0 --nologo
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$bin = Join-Path $root 'src/SMBLibrary/bin/Release/netstandard2.0'
Copy-Item (Join-Path $bin 'NoMercy.SMBLibrary.dll')            $out -Force
Copy-Item (Join-Path $bin 'NoMercy.SMBLibrary.Utilities.dll')  $out -Force

Write-Host "Built ->"
Get-ChildItem $out | Format-Table Name, Length
