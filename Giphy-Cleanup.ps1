<#
.SYNOPSIS
    Zoom Process and Giphy Cache Cleanup Utility

.DESCRIPTION
    Terminates all Zoom processes for the current user and cleans up Giphy cache data.
    Useful for resolving Zoom issues or performing clean resets without removing required cache data.

.PARAMETER None
    This script runs without parameters

.EXAMPLE
    .\Giphy-Cleanup.ps1

.AUTHOR
    handcaster

.NOTES
    Requires appropriate permissions to terminate processes and delete files
    Targets only processes owned by the current user for safety
    Designed for Azure Virtual Desktop (VDI) Environment
#>

$currentUser = $env:USERNAME
$zoomProcesses = Get-Process zoom -ErrorAction SilentlyContinue

foreach ($process in $zoomProcesses) {
    try {
        $ownerInfo = $process | Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction SilentlyContinue
        if ($ownerInfo.GetOwner().User -eq $currentUser) {
            Write-Host "Terminating process ID: $($process.Id) for user: $currentUser"
            Stop-Process -Id $process.Id -Force
        }
    } catch {
        Write-Host "Failed to terminate process ID $($process.Id): $_"
    }
}

$basePath = "$env:appdata\zoomvdi\data"
Get-ChildItem -Path $basePath -Recurse -Directory -Filter "giphy" | ForEach-Object { 
    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
}