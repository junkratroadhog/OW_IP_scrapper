# Version 1.2.0 - Adds Game Server Candidate Filter feature (v1.2.0)
# All features from v1.1.0 are preserved
# New: Test-GameServerCandidate + game_ip.csv and infra_ip.csv
# Default packet limit = 600 (preserved)
# ====================================================================

# --- Enable bypass execution policy for this session ---
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Configuration and setup ---
$configFile = Join-Path $PSScriptRoot "tshark_config.json"
$logsDir   = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }

$ipGeoCache = @{}  # Cache for geo-location

# =====================================================================
# FEATURE: Game Server Candidate Filter (v1.2.0)
# Purpose: Classify Google/GCP IPs into probable game servers vs infra
# - Uses reverse DNS + ping heuristic
# - Adds properties GameServerCandidate (bool) and CandidateReason (string)
# - Exports two CSVs: game_ip.csv and infra_ip.csv (in logs directory)
# =====================================================================
function Test-GameServerCandidate {
    param($IP)

    $candidate = $true
    $reason    = "Unknown"

    try {
        # Reverse DNS lookup (may throw)
        $hostEntry = [System.Net.Dns]::GetHostEntry($IP)
        $hostname = $hostEntry.HostName
        $reason = "DNS:$hostname"

        # If hostname indicates GCP generic host, use ping heuristic
        if ($hostname -like "*.googleusercontent.com" -or $hostname -like "*.bc.googleusercontent.com" -or $hostname -like "*.compute.amazonaws.com" -or $hostname -like "*google*") {
            # Ping test (ICMP). If it responds -> likely infra; if it does NOT respond -> candidate server
            $ping = Test-Connection -ComputerName $IP -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) {
                $candidate = $false
                $reason = "$reason;PingResponded"
            } else {
                $reason = "$reason;NoPing"
            }
        } else {
            # Hostname does not look like generic cloud infra — keep as candidate but record host
            $reason = "$reason;NonGenericHost"
        }
    } catch {
        # DNS failed or threw; fallback to ping only
        $ping = Test-Connection -ComputerName $IP -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $candidate = $false
            $reason = "NoDNS;PingResponded"
        } else {
            $reason = "NoDNS;NoPing"
        }
    }

    return [PSCustomObject]@{
        IsCandidate = $candidate
        Reason      = $reason
    }
}
# =====================================================================

# --- Functions ---

function Get-TsharkPath {
    $tsharkPath = (Get-Command tshark.exe -ErrorAction SilentlyContinue).Source
    if ($null -ne $tsharkPath) { return $tsharkPath }

    $defaultPaths = @(
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe"
    )
    foreach ($path in $defaultPaths) {
        if (Test-Path $path) { return $path }
    }

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark"
    )
    foreach ($reg in $regPaths) {
        $installPath = (Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue).InstallLocation
        if ($null -ne $installPath) {
            $exe = Join-Path $installPath "tshark.exe"
            if (Test-Path $exe) { return $exe }
        }
    }

    return $null
}

function Test-Tshark {
    param($TsharkPath)
    try {
        & $TsharkPath -D > $null
        return $true
    } catch {
        return $false
    }
}

function Select-NetworkAdapter {
    param($TsharkPath)
    $interfaces = & $TsharkPath -D
    Write-Host "Available network adapters:"
    foreach ($line in $interfaces) { Write-Host $line }
    do {
        $selection = Read-Host "Enter the adapter number to use"
        $valid = $interfaces | Where-Object { $_ -match "^\s*$selection\." }
        if ($null -eq $valid) { Write-Host "Invalid selection. Try again." }
    } until ($null -ne $valid)
    $interfaceIndex = ($valid -split "\.")[0].Trim()
    $adapterName    = ($valid -split "\.")[1].Trim()
    return @{ Index = $interfaceIndex; Name = $adapterName }
}

# --- Geo-location ---
function Get-GeoLocation {
    param($IP)
    try {
        $url = "https://ipwhois.app/json/$IP"
        $resp = Invoke-RestMethod -Uri $url -Method Get -UseBasicParsing -ErrorAction Stop
        if ($null -ne $resp -and $resp.success -eq $true) {
            return "$($resp.city),$($resp.region),$($resp.country),$($resp.org)"
        } else {
            return "Unknown,Unknown,Unknown,Unknown"
        }
    } catch {
        return "Unknown,Unknown,Unknown,Unknown"
    }
}

function Get-CachedGeoLocation {
    param($IP)
    $IP = $IP.Trim()
    if ($ipGeoCache.ContainsKey($IP)) { return $ipGeoCache[$IP] }
    $geo = Get-GeoLocation $IP
    $ipGeoCache[$IP] = $geo
    return $geo
}

# --- Load or create config ---
$config = @{ }
if (Test-Path $configFile) { $config = Get-Content $configFile | ConvertFrom-Json }

# Detect Tshark (only ask if not found)
if ($null -eq $config.TsharkPath -or -not (Test-Path $config.TsharkPath) -or -not (Test-Tshark $config.TsharkPath)) {
    Write-Host "Detecting Tshark..."
    $config.TsharkPath = Get-TsharkPath
    if ($null -eq $config.TsharkPath) {
        $config.TsharkPath = Read-Host "Tshark not found. Enter full path manually"
    }
    if (-not (Test-Tshark $config.TsharkPath)) { Write-Error "Tshark detected but failed to run."; exit }
}

# Adapter selection (ask if not present)
if ($null -eq $config.AdapterIndex -or $null -eq $config.AdapterName) {
    $adapter = Select-NetworkAdapter $config.TsharkPath
    $config.AdapterIndex = $adapter.Index
    $config.AdapterName = $adapter.Name
}

# Capture duration (default 60)
if ($null -eq $config.CaptureDuration -or $config.CaptureDuration -le 0) { $config.CaptureDuration = 60 }

# Packet limit (new for v1.1.0)
if ($null -eq $config.PacketLimit -or $config.PacketLimit -le 0) { $config.PacketLimit = 600 }

# Save config
$config | ConvertTo-Json | Out-File $configFile -Force

# --- Parameters ---
$TsharkPath     = $config.TsharkPath
$interfaceIndex = $config.AdapterIndex
$adapterName    = $config.AdapterName
$duration       = [int]$config.CaptureDuration
$packetLimit    = [int]$config.PacketLimit
$captureCounter = 0

# CSV for remote IPs and locations (master log, preserved)
$csvFile = Join-Path $logsDir "ip_locations.csv"
if (-not (Test-Path $csvFile)) {
    "RemoteIP,Direction,RemotePort,LocalPort,City,Region,Country,Org" | Out-File $csvFile -Encoding UTF8
}

# Prepare new CSVs for feature (if not exist, create headers)
$gameCsvFile  = Join-Path $logsDir "game_ip.csv"
$infraCsvFile = Join-Path $logsDir "infra_ip.csv"

if (-not (Test-Path $gameCsvFile)) {
    "RemoteIP,Direction,RemotePort,LocalPort,City,Region,Country,Org,GameServerCandidate,CandidateReason,Count,TotalBytes" | Out-File $gameCsvFile -Encoding UTF8
}
if (-not (Test-Path $infraCsvFile)) {
    "RemoteIP,Direction,RemotePort,LocalPort,City,Region,Country,Org,GameServerCandidate,CandidateReason,Count,TotalBytes" | Out-File $infraCsvFile -Encoding UTF8
}

# --- Menu UI ---
function Show-Menu {
    Write-Host ""
    Write-Host "===== Packet Capture Menu ====="
    Write-Host "1. Run Capture"
    Write-Host "2. Choose Network Adapter"
    Write-Host "3. Choose Tshark Location"
    Write-Host "4. Set Capture Duration"
    Write-Host "5. Set Packet Limit"
    Write-Host "6. Exit"
}

function Start-Capture {
    Write-Host "Using network adapter: $adapterName"
    Write-Host "Capture duration: $duration seconds"
    Write-Host "Packet limit: $packetLimit"

    while ($true) {
        $captureCounter++
        $dateStamp = Get-Date -Format "yyyy-MM-dd"
        $logFile   = Join-Path $logsDir "packet_stats_$dateStamp.txt"
        $tmpFile   = Join-Path $env:TEMP ("tshark_capture_{0}.pcap" -f (Get-Random))

        Write-Host "Starting capture #$captureCounter for $duration seconds..."

        # Start tshark capture (UDP only)
        $job = Start-Job -ScriptBlock {
            param($TsharkPath, $interfaceIndex, $tmpFile, $duration)
            & $TsharkPath -i $interfaceIndex -f "udp" -a duration:$duration -w $tmpFile -F pcap *> $null
        } -ArgumentList $TsharkPath, $interfaceIndex, $tmpFile, $duration

        # Live countdown
        for ($i = 1; $i -le $duration; $i++) {
            Write-Host -NoNewline ("`rCapturing... $i / $duration sec")
            Start-Sleep -Seconds 1
        }
        Write-Host "`rCapture completed.            "

        Wait-Job $job
        Remove-Job $job

        # Parse packets: ip.src, ip.dst, udp.srcport, udp.dstport, frame.len
        if (-not (Test-Path $tmpFile)) { continue }

        $raw = & $TsharkPath -r $tmpFile -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e frame.len |
            Where-Object { $_ -match "\S" }

        # Build packet objects with direction + ports + len + mask local IPs
        $packets = @()
        foreach ($line in $raw) {
            $parts = $line -split "`t"

            $src    = if ($parts.Count -ge 1) { $parts[0] } else { "" }
            $dst    = if ($parts.Count -ge 2) { $parts[1] } else { "" }
            $udpSrc = if ($parts.Count -ge 3) { $parts[2] } else { "" }
            $udpDst = if ($parts.Count -ge 4) { $parts[3] } else { "" }
            $len    = 0
            if ($parts.Count -ge 5) {
                try { $len = [int]$parts[4] } catch { $len = 0 }
            }

            $isSrcLocal = $false
            $isDstLocal = $false
            if ($src -match '^192\.168\.') { $isSrcLocal = $true }
            if ($dst -match '^192\.168\.') { $isDstLocal = $true }

            if ($isSrcLocal -and -not $isDstLocal) {
                $direction   = "Sent"
                $remoteIP    = $dst
                $remotePort  = $udpDst
                $localPort   = $udpSrc
            } elseif ($isDstLocal -and -not $isSrcLocal) {
                $direction   = "Received"
                $remoteIP    = $src
                $remotePort  = $udpSrc
                $localPort   = $udpDst
            } else { continue }

            if ($null -eq $remotePort) { $remotePort = "" }
            if ($null -eq $localPort)  { $localPort  = "" }

            $packets += [PSCustomObject]@{
                RemoteIP   = $remoteIP
                Direction  = $direction
                RemotePort = $remotePort
                LocalPort  = $localPort
                Len        = [int]$len
            }
        }

        if ($packets.Count -eq 0) {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
            continue
        }

        # Group packets
        $groups = $packets |
            Group-Object -Property @{ Expression = { $_.RemoteIP } },
                                    @{ Expression = { $_.Direction } },
                                    @{ Expression = { $_.RemotePort } },
                                    @{ Expression = { $_.LocalPort } }

        $remotePackets = $groups | ForEach-Object {
            $sample = $_.Group[0]
            $count  = $_.Count
            $sumLen = ($_.Group | Measure-Object Len -Sum).Sum
            [PSCustomObject]@{
                RemoteIP   = $sample.RemoteIP
                Direction  = $sample.Direction
                RemotePort = $sample.RemotePort
                LocalPort  = $sample.LocalPort
                Count      = $count
                TotalBytes = $sumLen
                DstGeo     = Get-CachedGeoLocation($sample.RemoteIP)
            }
        } | Sort-Object -Property TotalBytes -Descending

        # Filter by packet limit
        $remotePackets = $remotePackets | Where-Object { $_.Count -ge $packetLimit }

        # =====================================================================
        # FEATURE: Game Server Candidate Filter (v1.2.0) - Integration
        # Add GameServerCandidate and CandidateReason to each remotePackets item
        # =====================================================================
        $remotePackets = $remotePackets | ForEach-Object {
            $gsCheck = Test-GameServerCandidate $_.RemoteIP
            $_ | Add-Member -NotePropertyName GameServerCandidate -NotePropertyValue ($gsCheck.IsCandidate) -Force
            $_ | Add-Member -NotePropertyName CandidateReason   -NotePropertyValue ($gsCheck.Reason) -Force
            $_
        }
        # =====================================================================

        # Write log and CSV
        if ($remotePackets.Count -gt 0) {
            "===============================" | Out-File $logFile -Append
            "Capture #$captureCounter at $(Get-Date -Format 'HH:mm:ss')" | Out-File $logFile -Append

            $remotePackets |
                Select-Object RemoteIP, Direction, RemotePort, LocalPort, DstGeo, Count, TotalBytes |
                Format-Table -AutoSize | Out-String -Width 4096 | Out-File $logFile -Append
            "" | Out-File $logFile -Append

            # CSV append with duplicate check for master CSV
            $existingKeys = @()
            if (Test-Path $csvFile) {
                $csvContent = Import-Csv $csvFile
                if ($null -ne $csvContent) {
                    foreach ($r in $csvContent) {
                        $existingKeys += ($r.RemoteIP + "_" + $r.Direction + "_" + $r.RemotePort + "_" + $r.LocalPort)
                    }
                }
            }

            # Also load existing keys for game and infra CSVs to avoid duplicates
            $existingGameKeys  = @()
            $existingInfraKeys = @()
            if (Test-Path $gameCsvFile) {
                $gcontent = Import-Csv $gameCsvFile
                if ($null -ne $gcontent) {
                    foreach ($r in $gcontent) {
                        $existingGameKeys += ($r.RemoteIP + "_" + $r.Direction + "_" + $r.RemotePort + "_" + $r.LocalPort)
                    }
                }
            }
            if (Test-Path $infraCsvFile) {
                $icontent = Import-Csv $infraCsvFile
                if ($null -ne $icontent) {
                    foreach ($r in $icontent) {
                        $existingInfraKeys += ($r.RemoteIP + "_" + $r.Direction + "_" + $r.RemotePort + "_" + $r.LocalPort)
                    }
                }
            }

            foreach ($entry in $remotePackets) {
                $key = ($entry.RemoteIP + "_" + $entry.Direction + "_" + $entry.RemotePort + "_" + $entry.LocalPort)
                if ($existingKeys -notcontains $key) {
                    $geoParts = $entry.DstGeo -split ","
                    while ($geoParts.Length -lt 4) { $geoParts += "Unknown" }
                    $City    = ($geoParts[0]).Trim() -replace '"','""'
                    $Region  = ($geoParts[1]).Trim() -replace '"','""'
                    $Country = ($geoParts[2]).Trim() -replace '"','""'
                    $Org     = ($geoParts[3]).Trim() -replace '"','""'

                    $line = "$($entry.RemoteIP),$($entry.Direction),$($entry.RemotePort),$($entry.LocalPort),""$City"",""$Region"",""$Country"",""$Org"""
                    Add-Content -Path $csvFile -Value $line
                    $existingKeys += $key
                }

                # Now, append to game_ip.csv or infra_ip.csv (no removal, just split)
                # Build fields for extended CSVs: include CandidateReason, Count, TotalBytes
                $geoParts = $entry.DstGeo -split ","
                while ($geoParts.Length -lt 4) { $geoParts += "Unknown" }
                $City    = ($geoParts[0]).Trim() -replace '"','""'
                $Region  = ($geoParts[1]).Trim() -replace '"','""'
                $Country = ($geoParts[2]).Trim() -replace '"','""'
                $Org     = ($geoParts[3]).Trim() -replace '"','""'

                $extendedLine = "$($entry.RemoteIP),$($entry.Direction),$($entry.RemotePort),$($entry.LocalPort),""$City"",""$Region"",""$Country"",""$Org"",""$($entry.GameServerCandidate)"",""$($entry.CandidateReason)"",$($entry.Count),$($entry.TotalBytes)"

                if ($entry.GameServerCandidate -eq $true) {
                    if ($existingGameKeys -notcontains $key) {
                        Add-Content -Path $gameCsvFile -Value $extendedLine
                        $existingGameKeys += $key
                    }
                } else {
                    if ($existingInfraKeys -notcontains $key) {
                        Add-Content -Path $infraCsvFile -Value $extendedLine
                        $existingInfraKeys += $key
                    }
                }
            }
        }

        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
    }
}

# --- Menu loop ---
do {
    Show-Menu
    $choice = Read-Host "Select an option (1-6)"
    switch ($choice) {
        "1" {
            Start-Capture
        }
        "2" {
            $adapter = Select-NetworkAdapter $TsharkPath
            $interfaceIndex = $adapter.Index
            $adapterName    = $adapter.Name
            $config.AdapterIndex = $interfaceIndex
            $config.AdapterName  = $adapterName
            $config | ConvertTo-Json | Out-File $configFile -Force
        }
        "3" {
            $path = Read-Host "Enter full Tshark path"
            if (Test-Path $path) {
                $TsharkPath = $path
                $config.TsharkPath = $TsharkPath
                $config | ConvertTo-Json | Out-File $configFile -Force
            } else { Write-Host "Invalid path" }
        }
        "4" {
            $durationInput = Read-Host "Enter capture duration in seconds"
            if ([int]::TryParse($durationInput, [ref]$null)) {
                $duration = [int]$durationInput
                $config.CaptureDuration = $duration
                $config | ConvertTo-Json | Out-File $configFile -Force
            } else { Write-Host "Invalid duration" }
        }
        "5" {
            $limitInput = Read-Host "Enter packet count threshold (Packet Limit)"
            if ([int]::TryParse($limitInput, [ref]$null)) {
                $packetLimit = [int]$limitInput
                $config.PacketLimit = $packetLimit
                $config | ConvertTo-Json | Out-File $configFile -Force
            } else { Write-Host "Invalid number" }
        }
        "6" { exit }
        default { Write-Host "Invalid choice" }
    }
} while ($true)
