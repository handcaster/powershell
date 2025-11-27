<#
.SYNOPSIS
    Configures Atera Networks AlphaAgent registry settings and manages TicketingTray.exe process - designed to be ran as a script within Atera portal

.DESCRIPTION
    This script performs the following actions:
    1. Creates/updates registry value 'HelpdeskShortcut' with value 'False' in HKLM\SOFTWARE\Atera Networks\AlphaAgent
    2. Stops all running instances of TicketingTray.exe for the current user
    3. Waits 10 seconds
    4. Restarts TicketingTray.exe from the most recently active user's Temp directory
    5. Verifies the process is running successfully

.PARAMETER None
    This script does not accept parameters.

.NOTES
    Author: handcaster
    Date:   $(Get-Date -Format "yyyy-MM-dd")
    Requires: PowerShell 5.1 or later, Administrator privileges

.EXAMPLE
    .\Configure-AteraTray-Atera.ps1
    
    Runs the script with default configuration to update registry and restart TicketingTray.exe
#>

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator and try again."
    exit 1
}

# PowerShell script to set registry value, stop TicketingTray.exe, then restart it

# Part 1: Create registry value
$registryPath = "HKLM:\SOFTWARE\Atera Networks\AlphaAgent"
$registryName = "HelpdeskShortcut"
$registryValue = "False"

try {
    # Check if registry path exists, create if it doesn't
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host "Registry path created: $registryPath"
    }
    
    # Set the registry value
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -Type String -Force
    Write-Host "Registry value set successfully: $registryName = $registryValue"
}
catch {
    Write-Error "Failed to set registry value: $_"
    exit 1
}

# Part 2: Stop and restart TicketingTray.exe for the most recently active user

# Function to get the most recently active user with TicketingTray installed
function Get-MostRecentUserWithTicketingTray {
    try {
        Write-Host "Searching for most recently active user with TicketingTray installed..." -ForegroundColor Yellow
        
        # Get all user profiles excluding system accounts
        $userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
            $_.Name -notlike '*$' -and $_.Name -ne 'Public' -and $_.Name -ne 'Default' -and $_.Name -ne 'Administrator'
        }
        
        if ($userProfiles.Count -eq 0) {
            Write-Host "No user profiles found." -ForegroundColor Yellow
            return $null
        }
        
        # Check each user profile for TicketingTray and get last login time
        $usersWithTicketingTray = @()
        
        foreach ($userProfile in $userProfiles) {
            $ticketingPath = "C:\Users\$($userProfile.Name)\AppData\Local\Temp\TicketingAgentPackage\TicketingTray.exe"
            if (Test-Path $ticketingPath) {
                # Method 1: Check registry for last login time
                $lastLogin = $null
                $profileLoaded = $false
                
                # Try to get last login time from registry
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                try {
                    $lastLoggedOnUser = Get-ItemProperty -Path $regPath -Name "LastLoggedOnUser" -ErrorAction SilentlyContinue
                    if ($lastLoggedOnUser -and $lastLoggedOnUser.LastLoggedOnUser -like "*$($userProfile.Name)*") {
                        $lastLogin = [DateTime]::Now
                        Write-Host "User $($userProfile.Name) is the last logged on user" -ForegroundColor Green
                    }
                } catch { }
                
                # Method 2: Check if user profile is currently loaded (most reliable for active sessions)
                try {
                    $profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | 
                                  Where-Object { $_.ProfileImagePath -like "*$($userProfile.Name)" }
                    if ($profileList) {
                        foreach ($profile in $profileList) {
                            # Check if profile is loaded (State = 0 means loaded)
                            if ($profile.State -eq 0) {
                                $profileLoaded = $true
                                $lastLogin = [DateTime]::Now
                                Write-Host "User $($userProfile.Name) profile is currently loaded" -ForegroundColor Green
                                break
                            }
                        }
                    }
                } catch { }
                
                # Method 3: Check NTUSER.DAT last write time (indicates profile activity)
                if (-not $lastLogin) {
                    $ntuserPath = "C:\Users\$($userProfile.Name)\NTUSER.DAT"
                    if (Test-Path $ntuserPath) {
                        $ntuserInfo = Get-Item $ntuserPath -ErrorAction SilentlyContinue
                        if ($ntuserInfo) {
                            $lastLogin = $ntuserInfo.LastWriteTime
                            Write-Host "User $($userProfile.Name) NTUSER.DAT last modified: $lastLogin" -ForegroundColor Yellow
                        }
                    }
                }
                
                # Method 4: Fallback to user folder's last write time
                if (-not $lastLogin) {
                    $lastLogin = $userProfile.LastWriteTime
                    Write-Host "User $($userProfile.Name) folder last modified: $lastLogin" -ForegroundColor Gray
                }
                
                $userInfo = @{
                    Username = $userProfile.Name
                    Path = $ticketingPath
                    LastLogin = $lastLogin
                    ProfileLoaded = $profileLoaded
                    IsActive = $profileLoaded
                }
                $usersWithTicketingTray += $userInfo
            }
        }
        
        if ($usersWithTicketingTray.Count -eq 0) {
            Write-Host "No users with TicketingTray installation found." -ForegroundColor Yellow
            return $null
        }
        
        # Sort by active profiles first, then by last login time (most recent first)
        $mostRecentUser = $usersWithTicketingTray | Sort-Object @{
            Expression = {$_.IsActive -as [int]} 
            Descending = $true
        }, @{
            Expression = {$_.LastLogin} 
            Descending = $true
        } | Select-Object -First 1
        
        Write-Host "Selected user: $($mostRecentUser.Username) (Last Activity: $($mostRecentUser.LastLogin), Profile Loaded: $($mostRecentUser.ProfileLoaded))" -ForegroundColor Cyan
        return $mostRecentUser
    }
    catch {
        Write-Error "Error finding most recent user: $_"
        return $null
    }
}

# Function to get currently logged in user via explorer.exe processes
function Get-CurrentLoggedInUser {
    try {
        Write-Host "Checking for currently logged in users..." -ForegroundColor Yellow
        $explorerProcesses = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" | Where-Object { 
            $_.GetOwner().User -and $_.GetOwner().User -notlike '*$' 
        }
        
        if ($explorerProcesses.Count -gt 0) {
            $loggedInUsers = @()
            foreach ($process in $explorerProcesses) {
                $owner = $process.GetOwner().User
                if ($owner -and $owner -notlike '*$' -and $owner -ne 'SYSTEM') {
                    $loggedInUsers += $owner
                }
            }
            
            if ($loggedInUsers.Count -gt 0) {
                $uniqueUsers = $loggedInUsers | Sort-Object -Unique
                Write-Host "Currently logged in users: $($uniqueUsers -join ', ')" -ForegroundColor Green
                
                # Check if any logged in users have TicketingTray installed
                foreach ($user in $uniqueUsers) {
                    $ticketingPath = "C:\Users\$user\AppData\Local\Temp\TicketingAgentPackage\TicketingTray.exe"
                    if (Test-Path $ticketingPath) {
                        Write-Host "Found TicketingTray for currently logged in user: $user" -ForegroundColor Cyan
                        return @{
                            Username = $user
                            Path = $ticketingPath
                            IsCurrentlyLoggedIn = $true
                            LastLogin = [DateTime]::Now
                        }
                    }
                }
            }
        }
        
        Write-Host "No currently logged in users with TicketingTray found." -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Error "Error checking logged in users: $_"
        return $null
    }
}

# Function to stop TicketingTray processes for all users
function Stop-TicketingTray {
    try {
        Write-Host "Searching for TicketingTray processes to stop..." -ForegroundColor Yellow
        
        # Get all processes with the name TicketingTray regardless of user
        $processes = Get-Process -Name "*TicketingTray*" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($proc in $processes) {
                $userName = "Unknown"
                try {
                    # Try to get the process owner
                    $ownerInfo = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($proc.Id)" | Select-Object -First 1
                    if ($ownerInfo) {
                        $ownerUser = $ownerInfo.GetOwner().User
                        if ($ownerUser) {
                            $userName = $ownerUser
                        }
                    }
                } catch {
                    # If we can't get owner, use Unknown
                    $userName = "Unknown"
                }
                
                Write-Host "Stopping process: $($proc.ProcessName) (PID: $($proc.Id)) for user: $userName"
                $proc | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            Write-Host "All TicketingTray processes stopped successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "No TicketingTray processes found running" -ForegroundColor Yellow
            return $true
        }
    }
    catch {
        Write-Error "Error stopping TicketingTray processes: $_"
        return $false
    }
}

# Function to start TicketingTray for specific user
function Start-TicketingTrayForUser {
    param([string]$Username, [string]$Path)
    
    try {
        Write-Host "Starting TicketingTray.exe for user $Username from: $Path" -ForegroundColor Yellow
        
        # Start the process
        $process = Start-Process -FilePath $Path -PassThru -ErrorAction Stop
        Write-Host "TicketingTray.exe started for user $Username with PID: $($process.Id)" -ForegroundColor Green
        return $process
    }
    catch {
        Write-Error "Failed to start TicketingTray.exe for user $Username : $_"
        return $null
    }
}

# Function to verify TicketingTray is running
function Test-TicketingTrayRunning {
    try {
        # Wait a moment for the process to fully start
        Write-Host "Waiting for process to initialize..." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        
        $runningProcesses = Get-Process -Name "*TicketingTray*" -ErrorAction SilentlyContinue
        
        if ($runningProcesses) {
            Write-Host "✓ Verification SUCCESSFUL - TicketingTray is running:" -ForegroundColor Green
            foreach ($proc in $runningProcesses) {
                Write-Host "  - Process: $($proc.ProcessName), PID: $($proc.Id)" -ForegroundColor Green
            }
            return $true
        } else {
            Write-Host "✗ Verification FAILED - TicketingTray is not running" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Error "Error during verification: $_"
        return $false
    }
}

# Main execution flow
Write-Host "Beginning TicketingTray restart process..." -ForegroundColor Cyan

# Step 1: Try to find currently logged in user with TicketingTray first (highest priority)
Write-Host "Step 1: Checking for currently logged in users..." -ForegroundColor Yellow
$currentUser = Get-CurrentLoggedInUser

# Step 2: If no currently logged in user found, get the most recently active user
if (-not $currentUser) {
    Write-Host "Step 2: Finding most recently active user..." -ForegroundColor Yellow
    $currentUser = Get-MostRecentUserWithTicketingTray
}

if (-not $currentUser) {
    Write-Host "❌ FAILED: Could not find any user with TicketingTray installed." -ForegroundColor Red
    Write-Host "Expected path: C:\Users\[Username]\AppData\Local\Temp\TicketingAgentPackage\TicketingTray.exe" -ForegroundColor Yellow
    exit 1
}

Write-Host "Selected user for TicketingTray restart: $($currentUser.Username)" -ForegroundColor Cyan

# Stop the process for all users
if (Stop-TicketingTray) {
    # Wait 10 seconds
    Write-Host "Waiting 10 seconds before restarting..." -ForegroundColor Yellow
    for ($i = 10; $i -gt 0; $i--) {
        Write-Host "  $i..." -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host "`n"
    
    # Restart the process for the selected user only
    Write-Host "Attempting to restart TicketingTray for user: $($currentUser.Username)" -ForegroundColor Yellow
    $startedProcess = Start-TicketingTrayForUser -Username $currentUser.Username -Path $currentUser.Path
    
    if ($startedProcess) {
        # Verify it's running
        Write-Host "`nVerifying TicketingTray is running..." -ForegroundColor Yellow
        $isRunning = Test-TicketingTrayRunning
        
        if ($isRunning) {
            Write-Host "`n✅ SUCCESS: TicketingTray has been successfully restarted for user: $($currentUser.Username)" -ForegroundColor Green
        } else {
            Write-Host "`n⚠️ WARNING: TicketingTray was started but verification failed. Process may not be running properly." -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n❌ FAILED: Could not start TicketingTray.exe for user: $($currentUser.Username)" -ForegroundColor Red
    }
} else {
    Write-Host "`n❌ FAILED: Could not stop TicketingTray processes" -ForegroundColor Red
}

Write-Host "`nScript execution completed." -ForegroundColor Cyan