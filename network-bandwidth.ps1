<#
.SYNOPSIS
    Network Bandwidth Test (one-liner) for Atera Custom Fields

.DESCRIPTION
    Performs a quick bandwidth test by downloading a test file and calculating Mbps.
    Designed for use in Atera RMM custom fields to monitor endpoint network performance.

.PARAMETER None
    This script runs without parameters for Atera compatibility

.EXAMPLE
    Run directly in Atera custom field or PowerShell console

.OUTPUTS
    String containing bandwidth result in Mbps format

.AUTHOR
    handcaster

.NOTES
    Requires internet access and outbound HTTP connectivity
    Uses CacheFly CDN for reliable testing
    Results cached in temporary directory
#>
$ProgressPreference='SilentlyContinue';$u="http://cachefly.cachefly.net/10mb.test?nc=$(Get-Random)";$st=Get-Date;$tmp=Join-Path $env:TEMP "atera_nettest.bin";Invoke-WebRequest -Uri $u -OutFile $tmp -UseBasicParsing -TimeoutSec 60|Out-Null;$t=(Get-Date)-$st;$sz=(Get-Item $tmp).Length;Remove-Item $tmp -Force;("{0:N2} Mbps" -f (($sz/$t.TotalSeconds/1MB*8)))