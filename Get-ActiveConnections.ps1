<#
.SYNOPSIS
    Active Network Connections Monitor

.DESCRIPTION
    Displays all established TCP connections with process information and data transfer statistics.
    Useful for monitoring network activity and identifying processes with active connections.

.PARAMETER None
    This script runs without parameters for quick execution

.EXAMPLE
    .\Get-ActiveConnections.ps1

.OUTPUTS
    Formatted table showing remote addresses, ports, process names, and data transfer metrics

.AUTHOR
    handcaster

.NOTES
    Requires administrative privileges for detailed process information
    Shows only established connections for cleaner output
#>
Get-NetTCPConnection -State Established | 
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess
        [PSCustomObject]@{
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            ProcessName   = $proc.Name
            SentBytes     = $_.BytesSent
            ReceivedBytes = $_.BytesReceived
        }
    } | Format-Table -AutoSize
