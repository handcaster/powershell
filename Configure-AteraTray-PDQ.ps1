<#
.SYNOPSIS
    Configures Atera Networks AlphaAgent registry settings and manages TicketingTray.exe process - designed to be ran as a package within PDQ Deploy
.DESCRIPTION
    This script performs the following actions:
    1. Creates/updates registry value 'HelpdeskShortcut' with value 'False' in HKLM\SOFTWARE\Atera Networks\AlphaAgent
    2. Stops all running instances of TicketingTray.exe
    3. Waits 10 seconds
    4. Restarts TicketingTray.exe from the current user's Temp directory
.NOTES
    Author: handcaster
#>

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges."
    exit 1
}

# Part 1: Create registry value
$registryPath = "HKLM:\SOFTWARE\Atera Networks\AlphaAgent"
$registryName = "HelpdeskShortcut"
$registryValue = "False"

try {
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Output "Registry path created: $registryPath"
    }
    
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -Type String -Force
    Write-Output "Registry value set successfully: $registryName = $registryValue"
}
catch {
    Write-Error "Failed to set registry value: $_"
    exit 1
}

# Part 2: Stop and restart TicketingTray.exe

# Get logged in username from explorer.exe processes
$explorerOwner = $null
try {
    $explorerProcess = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
    if ($explorerProcess) {
        $explorerOwner = $explorerProcess.GetOwner().User
    }
} catch {}

if ($explorerOwner -and $explorerOwner -notlike '*$') {
    $currentUser = $explorerOwner
    Write-Output "Found logged in user: $currentUser"
} else {
    # Fallback to checking user profiles
    $userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
        $_.Name -notlike '*$' -and $_.Name -ne 'Public' -and $_.Name -ne 'Default' 
    }
    
    if ($userProfiles) {
        $currentUser = $userProfiles[0].Name
        Write-Output "Using user profile: $currentUser"
    } else {
        Write-Error "Could not determine user"
        exit 1
    }
}

$processPath = "C:\Users\$currentUser\AppData\Local\Temp\TicketingAgentPackage\TicketingTray.exe"

Write-Output "Stopping TicketingTray processes..."
Get-Process -Name "*TicketingTray*" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Output "Waiting 10 seconds..."
Start-Sleep -Seconds 10

Write-Output "Starting TicketingTray from: $processPath"
if (Test-Path $processPath) {
    Start-Process -FilePath $processPath
    Write-Output "TicketingTray started successfully"
} else {
    Write-Error "TicketingTray.exe not found at: $processPath"
}