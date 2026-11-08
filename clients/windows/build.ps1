# Builds the Windows test client with MSYS2 MinGW-w64 (g++, cmake, ninja).
# Output: build\windows-client\vpn_client.exe (+ wintun.dll)
param([string]$MinGW = "C:\msys64\mingw64\bin")

$ErrorActionPreference = "Stop"
$repo = Resolve-Path "$PSScriptRoot\..\.."
if (Test-Path $MinGW) { $env:PATH = "$MinGW;$env:PATH" }

cmake -S "$repo\clients\windows" -B "$repo\build\windows-client" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cmake --build "$repo\build\windows-client"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Built: $repo\build\windows-client\vpn_client.exe" -ForegroundColor Green
