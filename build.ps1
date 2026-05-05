# build.ps1 — Build VPN server binary using Docker (no WSL needed)
param(
    [switch]$Deploy,
    [string]$ServerIP = "",
    [string]$SSHKeyPath = "$HOME\.ssh\gcp_key"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Building VPN Server ===" -ForegroundColor Cyan

# Ensure build directory exists
if (-not (Test-Path "./build")) {
    New-Item -ItemType Directory -Path "./build" | Out-Null
}

# Build in Docker
docker build -t vpn-builder .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Docker build failed." -ForegroundColor Red
    exit 1
}

# Extract binary using a unique container name to avoid collisions
$ContainerName = "vpn-extract-$(Get-Random)"
docker create --name $ContainerName vpn-builder 2>$null
docker cp "${ContainerName}:/vpn_server" ./build/vpn_server
docker rm $ContainerName >$null

if (-not (Test-Path "./build/vpn_server")) {
    Write-Host "[ERROR] Binary extraction failed." -ForegroundColor Red
    exit 1
}

Write-Host "Binary ready at ./build/vpn_server" -ForegroundColor Green

# Deploy if requested
if ($Deploy) {
    if (-not $ServerIP) {
        # Try to get IP from Terraform
        Push-Location "$HOME\Documents\GitHub\vpn-infra"
        $ServerIP = terraform output -raw vpn_server_ip 2>$null
        Pop-Location

        if (-not $ServerIP) {
            Write-Host "[ERROR] No server IP. Use: .\build.ps1 -Deploy -ServerIP 35.x.x.x" -ForegroundColor Red
            exit 1
        }
    }

    # Verify SSH key exists
    if (-not (Test-Path $SSHKeyPath)) {
        Write-Host "[ERROR] SSH key not found at: $SSHKeyPath" -ForegroundColor Red
        Write-Host "        Use -SSHKeyPath to specify your key location." -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "=== Deploying to $ServerIP ===" -ForegroundColor Cyan

    Write-Host "[1/3] Uploading binary..."
    scp -i $SSHKeyPath -o StrictHostKeyChecking=accept-new ./build/vpn_server "vpnadmin@${ServerIP}:/tmp/vpn_server"
    if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Upload failed." -ForegroundColor Red; exit 1 }

    Write-Host "[2/3] Installing..."
    ssh -i $SSHKeyPath "vpnadmin@$ServerIP" "sudo mv /tmp/vpn_server /opt/vpn/vpn_server && sudo chmod +x /opt/vpn/vpn_server"
    if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Install failed." -ForegroundColor Red; exit 1 }

    Write-Host "[3/3] Restarting service..."
    ssh -i $SSHKeyPath "vpnadmin@$ServerIP" "sudo systemctl restart vpn-server && sleep 2 && sudo systemctl status vpn-server --no-pager -l"
    if ($LASTEXITCODE -ne 0) { Write-Host "[WARN] Service may not be running. Check logs." -ForegroundColor Yellow }

    Write-Host ""
    Write-Host "=== Deployed! VPN running at ${ServerIP}:5555/udp ===" -ForegroundColor Green
}
