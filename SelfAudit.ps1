<#
.SYNOPSIS
    Self Hack 100.0 - Ultimate System Audit & Forensics Toolkit
.DESCRIPTION
    Versi 100.0 dengan 20+ modul audit lengkap:
    - Aktivasi logging maksimal (audit policy + event logging)
    - Analisis event log (brute force, anomaly, privilege abuse)
    - Forensik artifacts (prefetch, scheduled tasks, services)
    - File system analysis (NTFS permissions, hidden files)
    - Registry analysis (autorun, persistence, hijacking)
    - Network analysis (connections, open ports, DNS)
    - Process analysis (unsigned, masquerading, LOLBins)
    - User & group analysis (inactive, privileged, shadow)
    - Threat hunting (MITRE ATT&CK mapping)
    - Vulnerability assessment (missing patches, misconfig)
    - Malware indicators (YARA-like rules)
    - Memory analysis (basic)
    - And many more...
.NOTES
    HANYA UNTUK SISTEM ANDA SENDIRI!
    Jalankan sebagai Administrator.
    Versi: 100.0.0 - Ultimate Overpower Edition
#>

#region ========== INISIALISASI ==========
$scriptVersion = "100.0.0"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "C:\SelfHack-$timestamp"
$reportFile = "$outputDir\Laporan_Audit.html"
$global:allResults = @()
$global:auditLog = @()

# Buat direktori output
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$global:logFile = "$outputDir\AuditLog.txt"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $time = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$time] $Message"
    Write-Host $logMessage -ForegroundColor $Color
    Add-Content -Path $global:logFile -Value $logMessage
    $global:auditLog += $logMessage
}

function Write-Section {
    param([string]$Title)
    Write-Log "`n" -Color White
    Write-Log ("="*70) -Color Cyan
    Write-Log "  $Title" -Color Cyan
    Write-Log ("="*70) -Color Cyan
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Detail,
        [string]$Severity,  # Critical, High, Medium, Low, Info
        [datetime]$Time = (Get-Date)
    )
    $global:allResults += [PSCustomObject]@{
        Category = $Category
        Name = $Name
        Detail = $Detail
        Severity = $Severity
        Time = $Time
    }
}
#endregion

#region ========== 1. AKTIVASI LOGGING MAKSIMAL ==========
function Enable-MaximumLogging {
    Write-Section "1. AKTIVASI LOGGING MAKSIMAL (AUDIT POLICY + EVENT LOGGING)"
    
    # 1.1 Audit Policy - Complete coverage berdasarkan best practice [citation:1][citation:2]
    $auditCategories = @(
        # Logon/Logoff
        @{Subcategory="Logon"; Success="enable"; Failure="enable"},
        @{Subcategory="Logoff"; Success="enable"; Failure="enable"},
        @{Subcategory="Account Lockout"; Success="enable"; Failure="enable"},
        @{Subcategory="Special Logon"; Success="enable"; Failure="enable"},
        
        # Account Logon
        @{Subcategory="Credential Validation"; Success="enable"; Failure="enable"},
        @{Subcategory="Kerberos Authentication Service"; Success="enable"; Failure="enable"},
        @{Subcategory="Kerberos Service Ticket Operations"; Success="enable"; Failure="enable"},
        
        # Process Creation (kritis untuk forensik)
        @{Subcategory="Process Creation"; Success="enable"; Failure="enable"},
        
        # Privilege Use
        @{Subcategory="Sensitive Privilege Use"; Success="enable"; Failure="enable"},
        @{Subcategory="Non Sensitive Privilege Use"; Success="enable"; Failure="enable"},
        
        # Object Access
        @{Subcategory="File Share"; Success="enable"; Failure="enable"},
        @{Subcategory="Detailed File Share"; Success="enable"; Failure="enable"},
        @{Subcategory="File System"; Success="enable"; Failure="enable"},
        @{Subcategory="Registry"; Success="enable"; Failure="enable"},
        @{Subcategory="Removable Storage"; Success="enable"; Failure="enable"},
        @{Subcategory="SAM"; Success="enable"; Failure="enable"},
        @{Subcategory="Filtering Platform Connection"; Success="enable"; Failure="enable"},
        @{Subcategory="Filtering Platform Packet Drop"; Success="enable"; Failure="enable"},
        
        # Policy Change
        @{Subcategory="Audit Policy Change"; Success="enable"; Failure="enable"},
        @{Subcategory="Authentication Policy Change"; Success="enable"; Failure="enable"},
        @{Subcategory="Authorization Policy Change"; Success="enable"; Failure="enable"},
        @{Subcategory="MPSSVC Rule-Level Policy Change"; Success="enable"; Failure="enable"},
        
        # Account Management
        @{Subcategory="User Account Management"; Success="enable"; Failure="enable"},
        @{Subcategory="Computer Account Management"; Success="enable"; Failure="enable"},
        @{Subcategory="Security Group Management"; Success="enable"; Failure="enable"},
        @{Subcategory="Distribution Group Management"; Success="enable"; Failure="enable"},
        @{Subcategory="Application Group Management"; Success="enable"; Failure="enable"},
        
        # Detailed Tracking
        @{Subcategory="DPAPI Activity"; Success="enable"; Failure="enable"},
        @{Subcategory="Plug and Play Events"; Success="enable"; Failure="enable"},
        @{Subcategory="Process Termination"; Success="enable"; Failure="enable"},
        @{Subcategory="RPC Events"; Success="enable"; Failure="enable"},
        
        # System
        @{Subcategory="Security State Change"; Success="enable"; Failure="enable"},
        @{Subcategory="Security System Extension"; Success="enable"; Failure="enable"},
        @{Subcategory="System Integrity"; Success="enable"; Failure="enable"},
        @{Subcategory="IPsec Driver"; Success="enable"; Failure="enable"}
    )
    
    foreach ($item in $auditCategories) {
        try {
            $cmd = "auditpol /set /subcategory:`"$($item.Subcategory)`" /success:$($item.Success) /failure:$($item.Failure)"
            Invoke-Expression $cmd | Out-Null
            Write-Log "  ✅ $($item.Subcategory)" -Color Green
        } catch {
            Write-Log "  ❌ $($item.Subcategory): $_" -Color Red
        }
    }
    
    # 1.2 Aktifkan command line logging (Event ID 4688 dengan command line) [citation:1]
    try {
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "  ✅ Command line logging diaktifkan" -Color Green
    } catch {
        Write-Log "  ❌ Gagal mengaktifkan command line logging: $_" -Color Red
    }
    
    # 1.3 PowerShell logging lengkap [citation:2][citation:3]
    try {
        # Script block logging
        $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
        Set-ItemProperty -Path $psLogPath -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force
        
        # Module logging
        $psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $psModPath)) { New-Item -Path $psModPath -Force | Out-Null }
        Set-ItemProperty -Path $psModPath -Name EnableModuleLogging -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $psModPath -Name ModuleNames -Value "*" -Type MultiString -Force
        
        # Transcription
        $psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $psTransPath)) { New-Item -Path $psTransPath -Force | Out-Null }
        Set-ItemProperty -Path $psTransPath -Name EnableTranscripting -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $psTransPath -Name OutputDirectory -Value "$outputDir\PowerShellTranscripts" -Type String -Force
        
        Write-Log "  ✅ PowerShell logging lengkap" -Color Green
    } catch {
        Write-Log "  ❌ Gagal mengaktifkan PowerShell logging: $_" -Color Red
    }
    
    # 1.4 Perbesar ukuran event log
    try {
        wevtutil set-log Security /maxsize:1073741824 /retention:true /autobackup:true | Out-Null  # 1GB
        wevtutil set-log System /maxsize:536870912 /retention:true /autobackup:true | Out-Null     # 512MB
        wevtutil set-log Application /maxsize:536870912 /retention:true /autobackup:true | Out-Null # 512MB
        wevtutil set-log "Windows PowerShell" /maxsize:536870912 /retention:true /autobackup:true | Out-Null
        Write-Log "  ✅ Ukuran event log diperbesar" -Color Green
    } catch {
        Write-Log "  ❌ Gagal memperbesar event log: $_" -Color Red
    }
    
    Add-Result -Category "Logging" -Name "Audit Policy" -Detail "Logging maksimal telah diaktifkan" -Severity "Info"
    Write-Log "✅ SEMUA LOGGING TELAH DIAKTIFKAN!" -Color Green
}
#endregion

#region ========== 2. ANALISIS EVENT LOG KOMPREHENSIF ==========
function Analyze-EventLogs {
    Write-Section "2. ANALISIS EVENT LOG KOMPREHENSIF"
    
    $startTime = (Get-Date).AddDays(-30) # 30 hari terakhir
    
    # 2.1 Failed logon attempts (brute force detection) [citation:9]
    Write-Log "Mencari failed logon attempts (Event ID 4625)..." -Color Yellow
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4625
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 1000
        
        if ($failedLogons) {
            Write-Log "  Ditemukan $($failedLogons.Count) failed logon attempts" -Color Magenta
            
            # Kelompokkan berdasarkan source IP
            $groupedByIP = $failedLogons | ForEach-Object {
                $ip = "Unknown"
                if ($_.Properties[18] -and $_.Properties[18].Value) { $ip = $_.Properties[18].Value }
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    IP = $ip
                    Username = if ($_.Properties[5]) { $_.Properties[5].Value } else { "Unknown" }
                }
            } | Group-Object IP
            
            foreach ($group in $groupedByIP) {
                if ($group.Count -ge 10) {
                    Add-Result -Category "Event Log - Brute Force" -Name $group.Name -Detail "$($group.Count) failed attempts dalam 30 hari" -Severity "High"
                }
            }
        }
    } catch {}
    
    # 2.2 Account creation/deletion (Event ID 4720, 4726)
    Write-Log "Mencari account creation/deletion..." -Color Yellow
    try {
        $accountEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4720,4722,4723,4724,4725,4726,4738
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 500
        
        if ($accountEvents) {
            Write-Log "  Ditemukan $($accountEvents.Count) account management events" -Color Magenta
            foreach ($event in $accountEvents) {
                $targetUser = if ($event.Properties[0]) { $event.Properties[0].Value } else { "Unknown" }
                $severity = if ($event.Id -eq 4720 -or $event.Id -eq 4726) { "High" } else { "Medium" }
                Add-Result -Category "Event Log - Account Management" -Name "Event ID $($event.Id)" -Detail "User: $targetUser, Time: $($event.TimeCreated)" -Severity $severity
            }
        }
    } catch {}
    
    # 2.3 Privilege use (Event ID 4672, 4673, 4674)
    Write-Log "Mencari privilege use events..." -Color Yellow
    try {
        $privEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4672,4673,4674
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 500
        
        if ($privEvents) {
            Write-Log "  Ditemukan $($privEvents.Count) privilege use events" -Color Magenta
            Add-Result -Category "Event Log - Privilege Use" -Name "Sensitive Privilege Use" -Detail "$($privEvents.Count) events tercatat" -Severity "Medium"
        }
    } catch {}
    
    # 2.4 PowerShell mencurigakan (Event ID 4104)
    Write-Log "Mencari PowerShell script block mencurigakan..." -Color Yellow
    try {
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -eq 4104 -and ($_.Message -match "(?i)(bypass|frombase64string|downloadstring|invoke-expression|iex|enc|hidden|windowstyle|wmiobject|win32_process|start-process)") }
        
        if ($psEvents) {
            Write-Log "  Ditemukan $($psEvents.Count) PowerShell script blocks mencurigakan" -Color Magenta
            foreach ($event in $psEvents) {
                $scriptPreview = ($event.Message -replace '\n',' ' -replace '\r',' ').Substring(0, [Math]::Min(150, $event.Message.Length))
                Add-Result -Category "Event Log - Suspicious PowerShell" -Name "PowerShell Script Block" -Detail $scriptPreview -Severity "Critical" -Time $event.TimeCreated
            }
        }
    } catch {}
    
    # 2.5 Service installation (Event ID 4697)
    Write-Log "Mencari service installation..." -Color Yellow
    try {
        $serviceEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4697
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 200
        
        if ($serviceEvents) {
            Write-Log "  Ditemukan $($serviceEvents.Count) service installations" -Color Magenta
            foreach ($event in $serviceEvents) {
                $serviceName = if ($event.Properties[0]) { $event.Properties[0].Value } else { "Unknown" }
                Add-Result -Category "Event Log - Service Installation" -Name $serviceName -Detail "Service baru diinstall" -Severity "Medium" -Time $event.TimeCreated
            }
        }
    } catch {}
    
    # 2.6 Scheduled task creation (Event ID 4698)
    Write-Log "Mencari scheduled task creation..." -Color Yellow
    try {
        $taskEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4698
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 200
        
        if ($taskEvents) {
            Write-Log "  Ditemukan $($taskEvents.Count) scheduled task creations" -Color Magenta
            foreach ($event in $taskEvents) {
                $taskName = if ($event.Properties[0]) { $event.Properties[0].Value } else { "Unknown" }
                Add-Result -Category "Event Log - Scheduled Task" -Name $taskName -Detail "Task baru dibuat" -Severity "Medium" -Time $event.TimeCreated
            }
        }
    } catch {}
    
    # 2.7 Firewall rule changes (Event ID 4946, 4947, 4948)
    Write-Log "Mencari firewall rule changes..." -Color Yellow
    try {
        $fwEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4946,4947,4948
            StartTime=$startTime
        } -ErrorAction SilentlyContinue | Select-Object -First 200
        
        if ($fwEvents) {
            Write-Log "  Ditemukan $($fwEvents.Count) firewall rule changes" -Color Magenta
            Add-Result -Category "Event Log - Firewall Change" -Name "Firewall Rule Modified" -Detail "$($fwEvents.Count) perubahan tercatat" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Analisis event log selesai. Total temuan: $($global:allResults | Where-Object { $_.Category -like "Event Log*" } | Measure-Object | Select-Object -ExpandProperty Count)" -Color Green
}
#endregion

#region ========== 3. ANALISIS PROSES DAN JARINGAN ==========
function Analyze-ProcessesAndNetwork {
    Write-Section "3. ANALISIS PROSES DAN JARINGAN"
    
    # 3.1 Proses tanpa signature digital [citation:4]
    Write-Log "Memeriksa proses tanpa signature digital..." -Color Yellow
    try {
        $unsigned = Get-Process | Where-Object { 
            $_.MainModule -and 
            -not (Get-AuthenticodeSignature $_.MainModule.FileName -ErrorAction SilentlyContinue).Status -eq "Valid" 
        } | Select-Object -First 100
        
        if ($unsigned) {
            Write-Log "  Ditemukan $($unsigned.Count) proses tanpa signature valid" -Color Magenta
            foreach ($proc in $unsigned) {
                Add-Result -Category "Process - Unsigned" -Name $proc.ProcessName -Detail "PID: $($proc.Id), Path: $($proc.Path)" -Severity "Medium"
            }
        }
    } catch {}
    
    # 3.2 Proses dengan nama mencurigakan (masquerading)
    Write-Log "Memeriksa proses dengan nama mencurigakan..." -Color Yellow
    $suspiciousNames = @('svchost', 'lsass', 'winlogon', 'csrss', 'services', 'smss', 'wininit')
    try {
        $suspicious = Get-Process | Where-Object { 
            $_.ProcessName -in $suspiciousNames -and 
            $_.Path -notmatch 'System32' -and
            $_.Path -notmatch 'SysWOW64'
        }
        
        if ($suspicious) {
            Write-Log "  Ditemukan $($suspicious.Count) proses dengan nama sistem di lokasi tidak biasa" -Color Magenta
            foreach ($proc in $suspicious) {
                Add-Result -Category "Process - Masquerading" -Name $proc.ProcessName -Detail "Path: $($proc.Path)" -Severity "Critical"
            }
        }
    } catch {}
    
    # 3.3 Proses dengan koneksi jaringan mencurigakan
    Write-Log "Memeriksa proses dengan koneksi jaringan..." -Color Yellow
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                      Where-Object { $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' -and $_.RemoteAddress -notmatch '::1' }
        
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
            
            # Cek reputasi IP (sederhana: cek apakah IP publik)
            Add-Result -Category "Network - Connection" -Name $procName -Detail "$($conn.LocalAddress):$($conn.LocalPort) → $($conn.RemoteAddress):$($conn.RemotePort)" -Severity "Low"
        }
        Write-Log "  Ditemukan $($connections.Count) koneksi ke IP publik" -Color Magenta
    } catch {}
    
    # 3.4 Open ports listening
    Write-Log "Memeriksa port listening..." -Color Yellow
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { $_.LocalPort -notin @(135, 445, 139, 3389, 5985, 5986) } # exclude common ports
        
        foreach ($listener in $listeners) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
            Add-Result -Category "Network - Listening Port" -Name $procName -Detail "Port $($listener.LocalPort) listening on $($listener.LocalAddress)" -Severity "Medium"
        }
    } catch {}
    
    # 3.5 DNS cache analysis
    Write-Log "Menganalisis DNS cache..." -Color Yellow
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
                    Where-Object { $_.Entry -match '(?i)(malware|ransom|phish|bot|cnc|command|control|microsoft\.com\.ru|update\.)' }
        
        if ($dnsCache) {
            foreach ($entry in $dnsCache) {
                Add-Result -Category "Network - Suspicious DNS" -Name $entry.Entry -Detail "Type: $($entry.Type), Data: $($entry.Data)" -Severity "High"
            }
        }
    } catch {}
    
    # 3.6 LOLBins detection (Living Off the Land Binaries)
    Write-Log "Mendeteksi LOLBins usage..." -Color Yellow
    $lolBins = @('wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe', 'csc.exe', 'installutil.exe', 'msbuild.exe', 'msiexec.exe', 'reg.exe', 'schtasks.exe', 'wmic.exe')
    try {
        $lolProc = Get-Process | Where-Object { $_.ProcessName -in ($lolBins | ForEach-Object { $_.Replace('.exe','') }) }
        foreach ($proc in $lolProc) {
            Add-Result -Category "Process - LOLBin" -Name $proc.ProcessName -Detail "PID: $($proc.Id), Path: $($proc.Path)" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Analisis proses dan jaringan selesai." -Color Green
}
#endregion

#region ========== 4. ANALISIS FILE SYSTEM ==========
function Analyze-FileSystem {
    Write-Section "4. ANALISIS FILE SYSTEM"
    
    # 4.1 File tersembunyi di direktori sistem [citation:4]
    Write-Log "Memeriksa file tersembunyi di direktori sistem..." -Color Yellow
    $systemDirs = @("C:\Windows", "C:\Windows\System32", "C:\ProgramData", "C:\Program Files", "C:\Program Files (x86)")
    foreach ($dir in $systemDirs) {
        if (Test-Path $dir) {
            try {
                $hidden = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Attributes -match "Hidden" -and -not $_.PSIsContainer } | 
                         Select-Object -First 50
                foreach ($file in $hidden) {
                    Add-Result -Category "File System - Hidden" -Name $file.Name -Detail "Path: $($file.FullName)" -Severity "Medium"
                }
            } catch {}
        }
    }
    
    # 4.2 File dengan ekstensi mencurigakan
    Write-Log "Memeriksa file dengan ekstensi mencurigakan..." -Color Yellow
    $suspiciousExts = @('.exe', '.dll', '.sys', '.vbs', '.ps1', '.bat', '.cmd', '.js', '.vbe', '.jse', '.wsf', '.wsh', '.scr', '.pif', '.com')
    $scanPaths = @("C:\Users", "C:\ProgramData", "C:\Temp", "C:\Windows\Temp")
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue -Include $suspiciousExts -Depth 3 | Select-Object -First 100
                foreach ($file in $files) {
                    Add-Result -Category "File System - Suspicious Extension" -Name $file.Name -Detail "Path: $($file.FullName)" -Severity "Low"
                }
            } catch {}
        }
    }
    
    # 4.3 NTFS permissions berisiko [citation:7]
    Write-Log "Memeriksa NTFS permissions berisiko di C:\..." -Color Yellow
    try {
        $acl = Get-Acl "C:\" -ErrorAction SilentlyContinue
        $riskyAccess = $acl.Access | Where-Object { 
            $_.FileSystemRights -match "FullControl" -and 
            ($_.IdentityReference -match "Everyone|Users|BUILTIN\\Users|BUILTIN\\Guests")
        }
        if ($riskyAccess) {
            foreach ($access in $riskyAccess) {
                Add-Result -Category "File System - Risky Permission" -Name "C:\" -Detail "$($access.IdentityReference) memiliki FullControl" -Severity "High"
            }
        }
    } catch {}
    
    # 4.4 File yang dimodifikasi dalam 24 jam terakhir [citation:6]
    Write-Log "Memeriksa file yang dimodifikasi dalam 24 jam terakhir..." -Color Yellow
    $recentFiles = Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Depth 3 |
                   Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -First 50
    
    foreach ($file in $recentFiles) {
        Add-Result -Category "File System - Recent Modification" -Name $file.Name -Detail "Modified: $($file.LastWriteTime), Path: $($file.FullName)" -Severity "Low"
    }
    
    # 4.5 Alternate Data Streams (ADS)
    Write-Log "Memeriksa Alternate Data Streams..." -Color Yellow
    try {
        $ads = Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Depth 2 |
               ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } |
               Where-Object { $_.Stream -notin @(':$DATA', 'Zone.Identifier') }
        
        foreach ($stream in $ads) {
            Add-Result -Category "File System - ADS" -Name $stream.FileName -Detail "Stream: $($stream.Stream), Size: $($stream.Size)" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Analisis file system selesai." -Color Green
}
#endregion

#region ========== 5. ANALISIS REGISTRY ==========
function Analyze-Registry {
    Write-Section "5. ANALISIS REGISTRY"
    
    # 5.1 Autorun entries (persistence) [citation:4][citation:10]
    Write-Log "Memeriksa autorun entries..." -Color Yellow
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    
    foreach ($path in $autorunPaths) {
        if (Test-Path $path) {
            try {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                $items.PSObject.Properties | Where-Object { 
                    $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') 
                } | ForEach-Object {
                    Add-Result -Category "Registry - Autorun" -Name $_.Name -Detail "Command: $($_.Value), Path: $path" -Severity "Low"
                }
            } catch {}
        }
    }
    
    # 5.2 Image File Execution Options (IFEO) Debugger
    Write-Log "Memeriksa Image File Execution Options (IFEO)..." -Color Yellow
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        try {
            $keys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $debugger = Get-ItemProperty -Path $key.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger) {
                    Add-Result -Category "Registry - IFEO Hijack" -Name $key.PSChildName -Detail "Debugger: $($debugger.Debugger)" -Severity "Critical"
                }
            }
        } catch {}
    }
    
    # 5.3 AppInit_DLLs
    Write-Log "Memeriksa AppInit_DLLs..." -Color Yellow
    try {
        $appInit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
        if ($appInit -and $appInit.AppInit_DLLs) {
            Add-Result -Category "Registry - AppInit" -Name "AppInit_DLLs" -Detail "DLLs: $($appInit.AppInit_DLLs)" -Severity "High"
        }
    } catch {}
    
    # 5.4 Known DLLs hijacking
    Write-Log "Memeriksa Known DLLs..." -Color Yellow
    try {
        $knownDlls = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction SilentlyContinue
        if ($knownDlls) {
            # Tidak semua perubahan berbahaya, tapi perlu dicatat
            Add-Result -Category "Registry - Known DLLs" -Name "KnownDLLs" -Detail "Daftar Known DLLs tersedia untuk inspeksi manual" -Severity "Info"
        }
    } catch {}
    
    # 5.5 Service trigger info
    Write-Log "Memeriksa service dengan trigger..." -Color Yellow
    try {
        $services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            $triggerInfo = Get-ItemProperty -Path $svc.PSPath -Name "TriggerInfo" -ErrorAction SilentlyContinue
            if ($triggerInfo) {
                Add-Result -Category "Registry - Service Trigger" -Name $svc.PSChildName -Detail "Service memiliki trigger info" -Severity "Medium"
            }
        }
    } catch {}
    
    # 5.6 Registry permissions berisiko
    Write-Log "Memeriksa registry permissions berisiko (sampel)..." -Color Yellow
    try {
        $regAcl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        $riskyRegAccess = $regAcl.Access | Where-Object { 
            $_.RegistryRights -match "FullControl" -and 
            ($_.IdentityReference -match "Everyone|Users|BUILTIN\\Users")
        }
        if ($riskyRegAccess) {
            foreach ($access in $riskyRegAccess) {
                Add-Result -Category "Registry - Risky Permission" -Name "Run key" -Detail "$($access.IdentityReference) memiliki FullControl" -Severity "High"
            }
        }
    } catch {}
    
    Write-Log "✅ Analisis registry selesai." -Color Green
}
#endregion

#region ========== 6. ANALISIS USER DAN GRUP ==========
function Analyze-UsersAndGroups {
    Write-Section "6. ANALISIS USER DAN GRUP"
    
    # 6.1 Daftar semua user lokal
    Write-Log "Mengumpulkan user lokal..." -Color Yellow
    try {
        $users = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($user in $users) {
            $detail = "Enabled: $($user.Enabled), LastLogon: $($user.LastLogon), PasswordExpires: $($user.PasswordExpires)"
            $severity = if ($user.Enabled -and $user.Name -in @('Administrator', 'Guest')) { "Medium" } else { "Info" }
            Add-Result -Category "User - Local" -Name $user.Name -Detail $detail -Severity $severity
        }
        Write-Log "  Ditemukan $($users.Count) user lokal" -Color Magenta
    } catch {}
    
    # 6.2 Anggota grup administrator
    Write-Log "Memeriksa anggota grup Administrator..." -Color Yellow
    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
                       Where-Object { $_.ObjectClass -eq "User" }
        foreach ($member in $adminMembers) {
            Add-Result -Category "User - Admin Group" -Name $member.Name -Detail "Member of Administrators group" -Severity "High"
        }
        Write-Log "  Ditemukan $($adminMembers.Count) anggota grup Administrator" -Color Magenta
    } catch {}
    
    # 6.3 User dengan password tidak pernah expired
    Write-Log "Memeriksa user dengan password never expires..." -Color Yellow
    try {
        $neverExpire = Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null }
        foreach ($user in $neverExpire) {
            Add-Result -Category "User - Password Never Expires" -Name $user.Name -Detail "Password tidak pernah expired" -Severity "Medium"
        }
    } catch {}
    
    # 6.4 User yang tidak aktif > 90 hari
    Write-Log "Memeriksa user tidak aktif > 90 hari..." -Color Yellow
    $cutoff = (Get-Date).AddDays(-90)
    try {
        $inactive = Get-LocalUser | Where-Object { 
            $_.LastLogon -and $_.LastLogon -lt $cutoff 
        }
        foreach ($user in $inactive) {
            Add-Result -Category "User - Inactive" -Name $user.Name -Detail "Last logon: $($user.LastLogon)" -Severity "Medium"
        }
    } catch {}
    
    # 6.5 SID history (untuk domain)
    Write-Log "Memeriksa SID history (jika domain)..." -Color Yellow
    try {
        $sidHistory = Get-LocalUser | ForEach-Object { 
            $user = $_
            try {
                $objUser = [ADSI]"WinNT://$env:COMPUTERNAME/$($user.Name),user"
                if ($objUser.Properties.sidhistory -and $objUser.Properties.sidhistory.Value) {
                    Add-Result -Category "User - SID History" -Name $user.Name -Detail "Memiliki SID history" -Severity "Critical"
                }
            } catch {}
        }
    } catch {}
    
    # 6.6 Password policy [citation:9]
    Write-Log "Memeriksa password policy..." -Color Yellow
    try {
        $policy = net accounts
        $minPwdLen = ($policy | Select-String "Minimum password length" | Select-String -NotMatch "0").ToString()
        $maxPwdAge = ($policy | Select-String "Maximum password age").ToString()
        
        if ($minPwdLen -match "(\d+)") {
            $len = [int]$matches[1]
            if ($len -lt 8) {
                Add-Result -Category "Security - Password Policy" -Name "Min Password Length" -Detail "$len characters (recommended: 8+)" -Severity "High"
            }
        }
        if ($maxPwdAge -match "(\d+)") {
            $age = [int]$matches[1]
            if ($age -gt 60) {
                Add-Result -Category "Security - Password Policy" -Name "Max Password Age" -Detail "$age days (recommended: <= 60)" -Severity "Medium"
            }
        }
    } catch {}
    
    Write-Log "✅ Analisis user dan grup selesai." -Color Green
}
#endregion

#region ========== 7. ANALISIS PERSISTENCE MECHANISMS ==========
function Analyze-Persistence {
    Write-Section "7. ANALISIS PERSISTENCE MECHANISMS"
    
    # 7.1 Scheduled tasks [citation:4][citation:10]
    Write-Log "Memeriksa scheduled tasks..." -Color Yellow
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                 Where-Object { $_.State -ne "Disabled" }
        
        foreach ($task in $tasks) {
            $actions = $task.Actions | Where-Object { $_.Execute } | ForEach-Object { $_.Execute }
            $detail = "Actions: $($actions -join ', ')"
            $severity = if ($task.TaskName -match '(?i)(update|security|system)') { "Low" } else { "Medium" }
            Add-Result -Category "Persistence - Scheduled Task" -Name $task.TaskName -Detail $detail -Severity $severity
        }
        Write-Log "  Ditemukan $($tasks.Count) scheduled tasks" -Color Magenta
    } catch {}
    
    # 7.2 Services dengan auto start
    Write-Log "Memeriksa services auto start..." -Color Yellow
    try {
        $services = Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" }
        foreach ($svc in $services) {
            try {
                $svcConfig = Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                $path = if ($svcConfig) { $svcConfig.PathName } else { "Unknown" }
                Add-Result -Category "Persistence - Service" -Name $svc.Name -Detail "Path: $path" -Severity "Low"
            } catch {
                Add-Result -Category "Persistence - Service" -Name $svc.Name -Detail "Auto start running service" -Severity "Low"
            }
        }
    } catch {}
    
    # 7.3 Startup folder
    Write-Log "Memeriksa startup folder..." -Color Yellow
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            try {
                $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Add-Result -Category "Persistence - Startup Folder" -Name $item.Name -Detail "Path: $($item.FullName)" -Severity "Low"
                }
            } catch {}
        }
    }
    
    # 7.4 WMI event subscription [citation:8]
    Write-Log "Memeriksa WMI event subscription..." -Color Yellow
    try {
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        
        if ($filters) { Add-Result -Category "Persistence - WMI" -Name "Event Filters" -Detail "$($filters.Count) filters ditemukan" -Severity "High" }
        if ($consumers) { Add-Result -Category "Persistence - WMI" -Name "Event Consumers" -Detail "$($consumers.Count) consumers ditemukan" -Severity "High" }
        if ($bindings) { Add-Result -Category "Persistence - WMI" -Name "Filter-Consumer Bindings" -Detail "$($bindings.Count) bindings ditemukan" -Severity "High" }
    } catch {}
    
    # 7.5 COM hijacking
    Write-Log "Memeriksa COM hijacking (InprocServer32)..." -Color Yellow
    try {
        $comPaths = @(
            "HKLM:\SOFTWARE\Classes\CLSID",
            "HKCU:\SOFTWARE\Classes\CLSID"
        )
        foreach ($comPath in $comPaths) {
            if (Test-Path $comPath) {
                $clsidKeys = Get-ChildItem -Path $comPath -ErrorAction SilentlyContinue | Select-Object -First 50
                foreach ($key in $clsidKeys) {
                    $inproc = Get-ItemProperty -Path "$($key.PSPath)\InprocServer32" -Name "(Default)" -ErrorAction SilentlyContinue
                    if ($inproc -and $inproc.'(Default)' -notmatch '(%SystemRoot%|C:\\Windows)') {
                        Add-Result -Category "Persistence - COM Hijack" -Name $key.PSChildName -Detail "InprocServer32: $($inproc.'(Default)')" -Severity "Critical"
                    }
                }
            }
        }
    } catch {}
    
    Write-Log "✅ Analisis persistence selesai." -Color Green
}
#endregion

#region ========== 8. ANALISIS FORENSIK ARTIFACTS ==========
function Analyze-ForensicArtifacts {
    Write-Section "8. ANALISIS FORENSIK ARTIFACTS"
    
    # 8.1 Prefetch files [citation:8][citation:10]
    Write-Log "Mengumpulkan Prefetch files..." -Color Yellow
    $prefetchDir = "C:\Windows\Prefetch"
    if (Test-Path $prefetchDir) {
        try {
            $prefetch = Get-ChildItem -Path $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTime -Descending |
                       Select-Object -First 100
            foreach ($pf in $prefetch) {
                Add-Result -Category "Forensics - Prefetch" -Name $pf.Name -Detail "Last run: $($pf.LastWriteTime)" -Severity "Info"
            }
            Write-Log "  Menyimpan $($prefetch.Count) Prefetch files" -Color Magenta
        } catch {}
    }
    
    # 8.2 Recent files (UserAssist, RecentDocs)
    Write-Log "Mengumpulkan recent files..." -Color Yellow
    try {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $recentPath) {
            $recent = Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue |
                     Sort-Object LastWriteTime -Descending |
                     Select-Object -First 50
            foreach ($item in $recent) {
                Add-Result -Category "Forensics - Recent Files" -Name $item.Name -Detail "Last accessed: $($item.LastWriteTime)" -Severity "Info"
            }
        }
    } catch {}
    
    # 8.3 USB device history [citation:4][citation:10]
    Write-Log "Mengumpulkan USB device history..." -Color Yellow
    try {
        $usbKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
        )
        foreach ($usbKey in $usbKeys) {
            if (Test-Path $usbKey) {
                $devices = Get-ChildItem -Path $usbKey -ErrorAction SilentlyContinue |
                          ForEach-Object { Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue }
                foreach ($device in $devices) {
                    $friendly = Get-ItemProperty -Path $device.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue
                    $name = if ($friendly) { $friendly.FriendlyName } else { $device.PSChildName }
                    Add-Result -Category "Forensics - USB History" -Name $name -Detail "Device instance: $($device.PSChildName)" -Severity "Info"
                }
                Write-Log "  Ditemukan $($devices.Count) USB devices" -Color Magenta
            }
        }
    } catch {}
    
    # 8.4 PowerShell history [citation:4]
    Write-Log "Mengumpulkan PowerShell history..." -Color Yellow
    $psHistoryPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    foreach ($path in $psHistoryPaths) {
        if (Test-Path $path) {
            try {
                $history = Get-Content $path -ErrorAction SilentlyContinue -TotalCount 100
                if ($history) {
                    $historyFile = "$outputDir\PowerShellHistory.txt"
                    $history | Out-File $historyFile
                    Add-Result -Category "Forensics - PowerShell History" -Name "History File" -Detail "Disimpan di $historyFile" -Severity "Info"
                }
            } catch {}
        }
    }
    
    # 8.5 Browser history (Chrome, Edge, Firefox)
    Write-Log "Mengumpulkan browser history (jika ada)..." -Color Yellow
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
    )
    foreach ($path in $browserPaths) {
        $expanded = [System.Environment]::ExpandEnvironmentVariables($path)
        $files = Get-ChildItem $expanded -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Add-Result -Category "Forensics - Browser History" -Name $file.Name -Detail "Browser history file ditemukan: $($file.FullName)" -Severity "Info"
        }
    }
    
    # 8.6 Shadow copies
    Write-Log "Memeriksa shadow copies..." -Color Yellow
    try {
        $shadows = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($shadows) {
            Add-Result -Category "Forensics - Shadow Copies" -Name "Shadow Copies" -Detail "$($shadows.Count) shadow copies ditemukan" -Severity "Info"
        }
    } catch {}
    
    Write-Log "✅ Analisis forensik artifacts selesai." -Color Green
}
#endregion

#region ========== 9. THREAT HUNTING (MITRE ATT&CK) ==========
function Analyze-ThreatHunting {
    Write-Section "9. THREAT HUNTING (MITRE ATT&CK MAPPING)"
    
    # 9.1 T1059.001 - PowerShell
    Write-Log "Mencari indikator PowerShell abuse..." -Color Yellow
    try {
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Id -eq 4104 -and $_.Message -match '(?i)(downloadstring|invoke-expression|iex|frombase64string)' }
        if ($psEvents) {
            Add-Result -Category "Threat Hunting - T1059.001" -Name "PowerShell Abuse" -Detail "$($psEvents.Count) event terdeteksi" -Severity "Critical"
        }
    } catch {}
    
    # 9.2 T1055 - Process Injection
    Write-Log "Mencari indikator process injection..." -Color Yellow
    try {
        $injectionEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue |
                          Where-Object { $_.Message -match '(?i)(rundll32|regsvr32|mshta).*(powershell|cmd|cscript)' }
        if ($injectionEvents) {
            Add-Result -Category "Threat Hunting - T1055" -Name "Potential Process Injection" -Detail "$($injectionEvents.Count) event mencurigakan" -Severity "High"
        }
    } catch {}
    
    # 9.3 T1071 - C2 Communications
    Write-Log "Mencari indikator C2 communications..." -Color Yellow
    try {
        $c2Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                         Where-Object { $_.RemotePort -in @(80, 443, 4444, 1337, 6667, 8080) -and $_.State -eq "Established" } |
                         Where-Object { $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' }
        foreach ($conn in $c2Connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
            Add-Result -Category "Threat Hunting - T1071" -Name $procName -Detail "C2 connection to $($conn.RemoteAddress):$($conn.RemotePort)" -Severity "High"
        }
    } catch {}
    
    # 9.4 T1547 - Boot or Logon Autostart Execution
    Write-Log "Memeriksa autostart execution (T1547)..." -Color Yellow
    try {
        $autorunCount = ($global:allResults | Where-Object { $_.Category -eq "Registry - Autorun" }).Count
        if ($autorunCount -gt 0) {
            Add-Result -Category "Threat Hunting - T1547" -Name "Autostart Execution" -Detail "$autorunCount autorun entries ditemukan" -Severity "Medium"
        }
    } catch {}
    
    # 9.5 T1003 - Credential Dumping
    Write-Log "Mencari indikator credential dumping..." -Color Yellow
    try {
        $lsassAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue |
                      Where-Object { $_.Message -match '(?i)(procdump|mimikatz|sekurlsa|comsvcs)' }
        if ($lsassAccess) {
            Add-Result -Category "Threat Hunting - T1003" -Name "Potential Credential Dumping" -Detail "$($lsassAccess.Count) event mencurigakan" -Severity "Critical"
        }
    } catch {}
    
    # 9.6 T1562 - Impair Defenses
    Write-Log "Mencari indikator impair defenses..." -Color Yellow
    try {
        $defenderDisabled = Get-MpPreference -ErrorAction SilentlyContinue | Where-Object { $_.DisableRealtimeMonitoring -eq $true }
        if ($defenderDisabled) {
            Add-Result -Category "Threat Hunting - T1562" -Name "Defender Disabled" -Detail "Real-time monitoring dimatikan" -Severity "Critical"
        }
    } catch {}
    
    Write-Log "✅ Threat hunting selesai." -Color Green
}
#endregion

#region ========== 10. VULNERABILITY ASSESSMENT ==========
function Analyze-Vulnerabilities {
    Write-Section "10. VULNERABILITY ASSESSMENT"
    
    # 10.1 Missing security patches (sederhana - cek build number)
    Write-Log "Memeriksa Windows build information..." -Color Yellow
    try {
        $os = Get-WmiObject Win32_OperatingSystem
        $build = $os.BuildNumber
        $productType = $os.ProductType
        
        Add-Result -Category "Vulnerability - System" -Name "Windows Build" -Detail "Build: $build, Type: $productType" -Severity "Info"
        
        # Cek jika build sudah tua (contoh: 10240 = 1507, 14393 = 1607, dll)
        $oldBuilds = @('10240', '10586', '14393', '15063', '16299', '17134', '17763', '18362', '18363', '19041', '19042', '19043', '19044')
        if ($build -in $oldBuilds) {
            Add-Result -Category "Vulnerability - Outdated Build" -Name "Windows Build $build" -Detail "Build ini mungkin sudah tidak mendapat update keamanan" -Severity "High"
        }
    } catch {}
    
    # 10.2 SMB v1 enabled
    Write-Log "Memeriksa SMB v1..." -Color Yellow
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq "Enabled") {
            Add-Result -Category "Vulnerability - SMBv1" -Name "SMB v1 Enabled" -Detail "SMB v1 masih aktif (rentan terhadap WannaCry, dll)" -Severity "Critical"
        }
    } catch {}
    
    # 10.3 PowerShell version (v2 rentan)
    Write-Log "Memeriksa PowerShell version..." -Color Yellow
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 5) {
            Add-Result -Category "Vulnerability - PowerShell" -Name "PowerShell $psVersion" -Detail "Versi PowerShell lawas (rentan)" -Severity "High"
        }
    } catch {}
    
    # 10.4 UAC level
    Write-Log "Memeriksa UAC level..." -Color Yellow
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        if ($uac -and $uac.EnableLUA -eq 0) {
            Add-Result -Category "Vulnerability - UAC" -Name "UAC Disabled" -Detail "User Account Control dimatikan" -Severity "High"
        }
    } catch {}
    
    # 10.5 Firewall status
    Write-Log "Memeriksa firewall status..." -Color Yellow
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($profile in $profiles) {
            if ($profile.Enabled -eq $false) {
                Add-Result -Category "Vulnerability - Firewall" -Name "$($profile.Name) Profile" -Detail "Firewall dimatikan untuk profile $($profile.Name)" -Severity "Critical"
            }
        }
    } catch {}
    
    # 10.6 LSA protection
    Write-Log "Memeriksa LSA protection..." -Color Yellow
    try {
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if (-not $lsa -or $lsa.RunAsPPL -ne 1) {
            Add-Result -Category "Vulnerability - LSA" -Name "LSA Protection" -Detail "LSA Protection tidak aktif (LSASS rentan dumping)" -Severity "High"
        }
    } catch {}
    
    # 10.7 Credential Guard
    Write-Log "Memeriksa Credential Guard..." -Color Yellow
    try {
        $cg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
        if (-not $cg -or $cg.LsaCfgFlags -ne 1) {
            Add-Result -Category "Vulnerability - Credential Guard" -Name "Credential Guard" -Detail "Credential Guard tidak aktif" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Vulnerability assessment selesai." -Color Green
}
#endregion

#region ========== 11. MEMORY ANALYSIS (BASIC) ==========
function Analyze-Memory {
    Write-Section "11. MEMORY ANALYSIS (BASIC)"
    
    # 11.1 Proses dengan memory tinggi
    Write-Log "Memeriksa proses dengan memory tinggi..." -Color Yellow
    try {
        $highMem = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20
        foreach ($proc in $highMem) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Add-Result -Category "Memory - High Usage" -Name $proc.ProcessName -Detail "$memMB MB working set" -Severity "Info"
        }
    } catch {}
    
    # 11.2 Proses dengan thread mencurigakan
    Write-Log "Memeriksa proses dengan thread injection (indikasi)..." -Color Yellow
    try {
        $suspiciousThreads = Get-Process | Where-Object { $_.Threads.Count -gt 100 -and $_.ProcessName -notin @('svchost', 'System', 'Idle') }
        foreach ($proc in $suspiciousThreads) {
            Add-Result -Category "Memory - Many Threads" -Name $proc.ProcessName -Detail "$($proc.Threads.Count) threads" -Severity "Medium"
        }
    } catch {}
    
    # 11.3 DLL injection detection (sederhana)
    Write-Log "Memeriksa DLL injection indicators..." -Color Yellow
    try {
        $injected = Get-Process | ForEach-Object {
            try {
                $modules = $_.Modules | Where-Object { $_.ModuleName -match '(?i)(hook|inject|detour)' }
                if ($modules) {
                    [PSCustomObject]@{
                        Process = $_.ProcessName
                        PID = $_.Id
                        Modules = ($modules | ForEach-Object { $_.ModuleName }) -join ', '
                    }
                }
            } catch {}
        }
        foreach ($item in $injected) {
            Add-Result -Category "Memory - Potential Injection" -Name $item.Process -Detail "Modules: $($item.Modules)" -Severity "Critical"
        }
    } catch {}
    
    Write-Log "✅ Memory analysis selesai." -Color Green
}
#endregion

#region ========== 12. INSTALLED SOFTWARE ANALYSIS ==========
function Analyze-Software {
    Write-Section "12. INSTALLED SOFTWARE ANALYSIS"
    
    # 12.1 Daftar software terinstall
    Write-Log "Mengumpulkan software terinstall..." -Color Yellow
    try {
        $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                   Where-Object { $_.DisplayName } |
                   Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        
        foreach ($app in $software) {
            $detail = "Version: $($app.DisplayVersion), Publisher: $($app.Publisher), InstallDate: $($app.InstallDate)"
            $severity = "Info"
            
            # Deteksi software berbahaya (blacklist sederhana)
            if ($app.DisplayName -match '(?i)(hack|keygen|crack|cheat|wifi password|network password)') {
                $severity = "Critical"
            }
            Add-Result -Category "Software - Installed" -Name $app.DisplayName -Detail $detail -Severity $severity
        }
        Write-Log "  Ditemukan $($software.Count) software terinstall" -Color Magenta
    } catch {}
    
    # 12.2 Software yang tidak dikenal (unverified publisher)
    Write-Log "Memeriksa software tanpa publisher..." -Color Yellow
    try {
        $noPublisher = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                         HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
                      Where-Object { $_.DisplayName -and -not $_.Publisher }
        foreach ($app in $noPublisher) {
            Add-Result -Category "Software - Unverified" -Name $app.DisplayName -Detail "Tidak ada publisher information" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Software analysis selesai." -Color Green
}
#endregion

#region ========== 13. BROWSER SECURITY ANALYSIS ==========
function Analyze-BrowserSecurity {
    Write-Section "13. BROWSER SECURITY ANALYSIS"
    
    # 13.1 Browser extensions mencurigakan (Chrome)
    Write-Log "Memeriksa Chrome extensions..." -Color Yellow
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtPath) {
        try {
            $extensions = Get-ChildItem $chromeExtPath -ErrorAction SilentlyContinue
            foreach ($ext in $extensions) {
                Add-Result -Category "Browser - Chrome Extension" -Name $ext.Name -Detail "Extension folder ditemukan" -Severity "Info"
            }
        } catch {}
    }
    
    # 13.2 Edge extensions
    Write-Log "Memeriksa Edge extensions..." -Color Yellow
    $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgeExtPath) {
        try {
            $extensions = Get-ChildItem $edgeExtPath -ErrorAction SilentlyContinue
            foreach ($ext in $extensions) {
                Add-Result -Category "Browser - Edge Extension" -Name $ext.Name -Detail "Extension folder ditemukan" -Severity "Info"
            }
        } catch {}
    }
    
    # 13.3 Firefox extensions
    Write-Log "Memeriksa Firefox extensions..." -Color Yellow
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilePath) {
        try {
            $profiles = Get-ChildItem $firefoxProfilePath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $extPath = Join-Path $profile.FullName "extensions"
                if (Test-Path $extPath) {
                    $extensions = Get-ChildItem $extPath -ErrorAction SilentlyContinue
                    foreach ($ext in $extensions) {
                        Add-Result -Category "Browser - Firefox Extension" -Name $ext.Name -Detail "Extension ditemukan di profile $($profile.Name)" -Severity "Info"
                    }
                }
            }
        } catch {}
    }
    
    # 13.4 Browser settings (homepage, proxy)
    Write-Log "Memeriksa browser settings yang diubah..." -Color Yellow
    try {
        $ieProxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -ErrorAction SilentlyContinue
        if ($ieProxy -and $ieProxy.ProxyEnable -eq 1) {
            $proxyServer = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -ErrorAction SilentlyContinue
            Add-Result -Category "Browser - Proxy" -Name "Internet Explorer/Edge Proxy" -Detail "Proxy enabled: $($proxyServer.ProxyServer)" -Severity "High"
        }
    } catch {}
    
    Write-Log "✅ Browser security analysis selesai." -Color Green
}
#endregion

#region ========== 14. NETWORK SHARES ANALYSIS ==========
function Analyze-NetworkShares {
    Write-Section "14. NETWORK SHARES ANALYSIS"
    
    # 14.1 SMB shares [citation:4][citation:10]
    Write-Log "Memeriksa SMB shares..." -Color Yellow
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        foreach ($share in $shares) {
            $detail = "Path: $($share.Path), Description: $($share.Description)"
            $severity = if ($share.Name -in @('ADMIN$', 'C$', 'IPC$')) { "Info" } else { "Medium" }
            Add-Result -Category "Network - Share" -Name $share.Name -Detail $detail -Severity $severity
        }
        Write-Log "  Ditemukan $($shares.Count) network shares" -Color Magenta
    } catch {}
    
    # 14.2 Share permissions
    Write-Log "Memeriksa share permissions (sampel)..." -Color Yellow
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' }
        foreach ($share in $shares) {
            $permissions = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue |
                          Where-Object { $_.AccountName -match "Everyone|Users|Guests" }
            foreach ($perm in $permissions) {
                Add-Result -Category "Network - Share Permission" -Name $share.Name -Detail "$($perm.AccountName) has $($perm.AccessRight)" -Severity "High"
            }
        }
    } catch {}
    
    # 14.3 Open files via network
    Write-Log "Memeriksa file yang dibuka via network..." -Color Yellow
    try {
        $openFiles = Get-SmbOpenFile -ErrorAction SilentlyContinue |
                    Select-Object -Property ClientComputerName, ClientUserName, Path -First 50
        foreach ($file in $openFiles) {
            Add-Result -Category "Network - Open File" -Name $file.Path -Detail "Opened by $($file.ClientUserName) from $($file.ClientComputerName)" -Severity "Medium"
        }
    } catch {}
    
    Write-Log "✅ Network shares analysis selesai." -Color Green
}
#endregion

#region ========== 15. ACTIVE DIRECTORY ANALYSIS ==========
function Analyze-ActiveDirectory {
    Write-Section "15. ACTIVE DIRECTORY ANALYSIS (JIKA DOMAIN)"
    
    # Cek apakah domain joined
    $isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    if (-not $isDomainJoined) {
        Write-Log "  ⚠️ Sistem bukan domain member, melewati analisis AD" -Color Yellow
        return
    }
    
    Write-Log "Sistem terdeteksi sebagai domain member, menganalisis..." -Color Yellow
    
    # 15.1 Domain controllers
    try {
        $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
        foreach ($dc in $dcs) {
            Add-Result -Category "AD - Domain Controller" -Name $dc.Name -Detail "Site: $($dc.SiteName)" -Severity "Info"
        }
    } catch {}
    
    # 15.2 Domain admins (perlu modul AD)
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        if (Get-Module ActiveDirectory) {
            $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
            foreach ($admin in $domainAdmins) {
                Add-Result -Category "AD - Domain Admin" -Name $admin.Name -Detail "Member of Domain Admins" -Severity "High"
            }
        }
    } catch {}
    
    # 15.3 Kerberoasting targets
    Write-Log "Mencari potential Kerberoasting targets..." -Color Yellow
    try {
        if (Get-Module ActiveDirectory) {
            $spnAccounts = Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName
            foreach ($account in $spnAccounts) {
                Add-Result -Category "AD - Kerberoast Target" -Name $account.Name -Detail "Memiliki SPN: $($account.ServicePrincipalName)" -Severity "Medium"
            }
        }
    } catch {}
    
    # 15.4 Password never expires di domain
    Write-Log "Memeriksa user dengan password never expires..." -Color Yellow
    try {
        if (Get-Module ActiveDirectory) {
            $neverExpire = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires
            foreach ($user in $neverExpire) {
                Add-Result -Category "AD - Password Never Expires" -Name $user.Name -Detail "Domain user dengan password never expires" -Severity "Medium"
            }
        }
    } catch {}
    
    Write-Log "✅ Active Directory analysis selesai." -Color Green
}
#endregion

#region ========== 16. ENCRYPTION STATUS ANALYSIS ==========
function Analyze-Encryption {
    Write-Section "16. ENCRYPTION STATUS ANALYSIS"
    
    # 16.1 BitLocker status
    Write-Log "Memeriksa BitLocker status..." -Color Yellow
    try {
        $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($bitlocker) {
            foreach ($vol in $bitlocker) {
                $detail = "Protection: $($vol.ProtectionStatus), Encryption: $($vol.EncryptionPercentage)%"
                $severity = if ($vol.ProtectionStatus -eq 1) { "Info" } else { "High" }
                Add-Result -Category "Encryption - BitLocker" -Name $vol.MountPoint -Detail $detail -Severity $severity
            }
        } else {
            Add-Result -Category "Encryption - BitLocker" -Name "No BitLocker" -Detail "BitLocker tidak aktif" -Severity "Medium"
        }
    } catch {}
    
    # 16.2 EFS (Encrypting File System) files
    Write-Log "Memeriksa EFS encrypted files..." -Color Yellow
    try {
        $efsFiles = Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue -Depth 3 |
                   Where-Object { $_.Attributes -match "Encrypted" } |
                   Select-Object -First 50
        foreach ($file in $efsFiles) {
            Add-Result -Category "Encryption - EFS" -Name $file.Name -Detail "EFS encrypted file: $($file.FullName)" -Severity "Info"
        }
    } catch {}
    
    # 16.3 Secure Boot status
    Write-Log "Memeriksa Secure Boot status..." -Color Yellow
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $severity = if ($secureBoot) { "Info" } else { "High" }
        Add-Result -Category "Encryption - Secure Boot" -Name "Secure Boot" -Detail "Status: $secureBoot" -Severity $severity
    } catch {}
    
    Write-Log "✅ Encryption analysis selesai." -Color Green
}
#endregion

#region ========== 17. LOG ANALYSIS WITH PATTERN DETECTION ==========
function Analyze-LogPatterns {
    Write-Section "17. LOG ANALYSIS WITH PATTERN DETECTION"
    
    # 17.1 Pattern: Multiple failed logons in short time
    Write-Log "Mencari pattern multiple failed logons..." -Color Yellow
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1000 -ErrorAction SilentlyContinue
        $timeGroups = $events | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH") }
        foreach ($group in $timeGroups) {
            if ($group.Count -gt 20) {
                Add-Result -Category "Pattern - Brute Force" -Name "Hour: $($group.Name)" -Detail "$($group.Count) failed logons dalam 1 jam" -Severity "Critical"
            }
        }
    } catch {}
    
    # 17.2 Pattern: Account lockouts
    Write-Log "Mencari account lockouts..." -Color Yellow
    try {
        $lockouts = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($lockouts) {
            Add-Result -Category "Pattern - Account Lockout" -Name "Account Lockouts" -Detail "$($lockouts.Count) lockout events" -Severity "High"
        }
    } catch {}
    
    # 17.3 Pattern: Clearing event logs
    Write-Log "Mencari event log clearing..." -Color Yellow
    try {
        $clears = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($clears) {
            foreach ($clear in $clears) {
                Add-Result -Category "Pattern - Log Clearing" -Name "Security Log Cleared" -Detail "Log dibersihkan pada $($clear.TimeCreated)" -Severity "Critical"
            }
        }
    } catch {}
    
    # 17.4 Pattern: Service install followed by network connection
    Write-Log "Mencari service install + network connection..." -Color Yellow
    try {
        $serviceInstalls = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4697} -MaxEvents 50 -ErrorAction SilentlyContinue
        $networkEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} -MaxEvents 500 -ErrorAction SilentlyContinue
        
        foreach ($svc in $serviceInstalls) {
            $svcTime = $svc.TimeCreated
            $nearbyConnections = $networkEvents | Where-Object { $_.TimeCreated -gt $svcTime -and $_.TimeCreated -lt $svcTime.AddMinutes(5) }
            if ($nearbyConnections) {
                Add-Result -Category "Pattern - Service + Network" -Name "Suspicious Pattern" -Detail "Service install diikuti network connections dalam 5 menit" -Severity "Critical"
            }
        }
    } catch {}
    
    Write-Log "✅ Log pattern analysis selesai." -Color Green
}
#endregion

#region ========== 18. HARDENING RECOMMENDATIONS ==========
function Generate-HardeningRecommendations {
    Write-Section "18. HARDENING RECOMMENDATIONS"
    
    Write-Log "Menghasilkan rekomendasi hardening berdasarkan temuan..." -Color Yellow
    
    # Kumpulkan temuan berdasarkan severity
    $criticalFindings = $global:allResults | Where-Object { $_.Severity -eq "Critical" }
    $highFindings = $global:allResults | Where-Object { $_.Severity -eq "High" }
    $mediumFindings = $global:allResults | Where-Object { $_.Severity -eq "Medium" }
    
    if ($criticalFindings) {
        Add-Result -Category "Hardening - Critical" -Name "Segera Tangani" -Detail "$($criticalFindings.Count) temuan critical memerlukan perhatian segera" -Severity "Critical"
    }
    
    # Rekomendasi spesifik berdasarkan kategori
    $recommendations = @()
    
    if ($global:allResults | Where-Object { $_.Category -like "*SMBv1*" }) {
        $recommendations += "Nonaktifkan SMB v1 untuk mencegah serangan seperti WannaCry"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*UAC Disabled*" }) {
        $recommendations += "Aktifkan UAC (User Account Control) untuk keamanan tambahan"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*Firewall*" -and $_.Detail -like "*dimati*" }) {
        $recommendations += "Aktifkan Windows Firewall untuk semua profile"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*LSA Protection*" -and $_.Detail -like "*tidak aktif*" }) {
        $recommendations += "Aktifkan LSA Protection (RunAsPPL) untuk melindungi LSASS dari dumping"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*Password Policy*" -and $_.Detail -like "*< 8*" }) {
        $recommendations += "Tingkatkan minimum password length menjadi minimal 8 karakter"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*Autorun*" }) {
        $recommendations += "Review dan bersihkan autorun entries yang tidak dikenal"
    }
    
    if ($global:allResults | Where-Object { $_.Category -like "*Admin Group*" }) {
        $recommendations += "Batasi jumlah anggota grup Administrator, terapkan prinsip least privilege"
    }
    
    foreach ($rec in $recommendations) {
        Add-Result -Category "Hardening - Recommendation" -Name "Saran" -Detail $rec -Severity "Info"
    }
    
    Write-Log "✅ Rekomendasi hardening selesai." -Color Green
}
#endregion

#region ========== 19. EXPORT RESULTS ==========
function Export-Results {
    Write-Section "19. EXPORTING RESULTS"
    
    # Export ke CSV
    $csvPath = "$outputDir\AllResults.csv"
    $global:allResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Log "✅ Hasil diekspor ke CSV: $csvPath" -Color Green
    
    # Export ke JSON
    $jsonPath = "$outputDir\AllResults.json"
    $global:allResults | ConvertTo-Json -Depth 3 | Out-File $jsonPath
    Write-Log "✅ Hasil diekspor ke JSON: $jsonPath" -Color Green
    
    # Export audit log
    $auditLogPath = "$outputDir\AuditLog.txt"
    $global:auditLog | Out-File $auditLogPath
    Write-Log "✅ Audit log disimpan: $auditLogPath" -Color Green
    
    # Generate HTML report
    Generate-HTMLReport
}

function Generate-HTMLReport {
    Write-Log "Membuat laporan HTML interaktif..." -Color Yellow
    
    $totalFindings = $global:allResults.Count
    $criticalCount = ($global:allResults | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($global:allResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($global:allResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($global:allResults | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = ($global:allResults | Where-Object { $_.Severity -eq "Info" }).Count
    
    $categories = $global:allResults | Group-Object Category | Sort-Object Count -Descending
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Self Hack 100.0 - Ultimate Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1600px; margin: auto; background-color: white; padding: 25px; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.2); }
        h1 { color: #8B0000; border-bottom: 4px solid #8B0000; padding-bottom: 15px; font-size: 32px; }
        h2 { color: #1E3A8A; margin-top: 30px; border-left: 5px solid #1E3A8A; padding-left: 15px; }
        .summary { display: flex; flex-wrap: wrap; gap: 15px; margin: 25px 0; }
        .stat-card { flex: 1; min-width: 140px; padding: 20px; border-radius: 10px; color: white; text-align: center; font-weight: bold; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .stat-card h3 { font-size: 36px; margin: 10px 0; }
        .critical { background: linear-gradient(135deg, #8B0000, #B22222); }
        .high { background: linear-gradient(135deg, #E65100, #F57C00); }
        .medium { background: linear-gradient(135deg, #FF8F00, #FFB300); color: black; }
        .low { background: linear-gradient(135deg, #2E7D32, #388E3C); }
        .info { background: linear-gradient(135deg, #1565C0, #1976D2); }
        .total { background: linear-gradient(135deg, #4A148C, #6A1B9A); }
        table { width: 100%; border-collapse: collapse; margin-top: 25px; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th { background-color: #1E3A8A; color: white; padding: 14px; text-align: left; font-size: 14px; }
        td { padding: 12px; border-bottom: 1px solid #E0E0E0; }
        tr:hover { background-color: #F5F5F5; }
        .badge { padding: 5px 12px; border-radius: 20px; color: white; font-size: 12px; font-weight: bold; display: inline-block; }
        .badge-critical { background-color: #8B0000; }
        .badge-high { background-color: #E65100; }
        .badge-medium { background-color: #FF8F00; color: black; }
        .badge-low { background-color: #2E7D32; }
        .badge-info { background-color: #1565C0; }
        .footer { margin-top: 30px; text-align: center; color: #757575; font-size: 13px; border-top: 1px solid #E0E0E0; padding-top: 20px; }
        .timestamp { color: #757575; margin-bottom: 20px; font-size: 14px; }
        .filter-box { background-color: #E3F2FD; padding: 20px; border-radius: 10px; margin: 25px 0; display: flex; gap: 15px; flex-wrap: wrap; }
        .filter-box input, .filter-box select { padding: 10px; border: 1px solid #B0BEC5; border-radius: 5px; font-size: 14px; }
        .filter-box button { background-color: #1E3A8A; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .filter-box button:hover { background-color: #1565C0; }
        .chart-container { display: flex; flex-wrap: wrap; gap: 25px; margin: 30px 0; }
        .chart { flex: 1; min-width: 300px; height: 250px; }
        .recommendations { background-color: #FFF3E0; padding: 20px; border-radius: 10px; margin: 25px 0; border-left: 5px solid #FF8F00; }
        .recommendations ul { list-style-type: none; padding: 0; }
        .recommendations li { padding: 8px 0; padding-left: 25px; background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="%23FF8F00"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>') left center no-repeat; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        function filterTable() {
            const severity = document.getElementById('severityFilter').value;
            const category = document.getElementById('categoryFilter').value.toLowerCase();
            const search = document.getElementById('searchInput').value.toLowerCase();
            const table = document.getElementById('resultsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const severityCell = row.getElementsByTagName('td')[4];
                const categoryCell = row.getElementsByTagName('td')[0];
                const textContent = row.textContent.toLowerCase();
                
                let show = true;
                if (severity && severityCell) {
                    const rowSeverity = severityCell.textContent.trim();
                    if (rowSeverity !== severity) show = false;
                }
                if (category && categoryCell) {
                    const rowCategory = categoryCell.textContent.toLowerCase();
                    if (!rowCategory.includes(category)) show = false;
                }
                if (search && !textContent.includes(search)) show = false;
                
                row.style.display = show ? '' : 'none';
            }
        }
        
        window.onload = function() {
            // Chart 1: Severity distribution
            const ctx1 = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [$criticalCount, $highCount, $mediumCount, $lowCount, $infoCount],
                        backgroundColor: ['#8B0000', '#E65100', '#FF8F00', '#2E7D32', '#1565C0'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
            
            // Chart 2: Top categories
            const ctx2 = document.getElementById('categoryChart').getContext('2d');
            new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: [@($categories | ForEach-Object { "'$($_.Name)'" } | Select-Object -First 8 | Join-String -Separator ', ')],
                    datasets: [{
                        label: 'Number of Findings',
                        data: [@($categories | ForEach-Object { $_.Count } | Select-Object -First 8 | Join-String -Separator ', ')],
                        backgroundColor: '#1E3A8A'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        };
    </script>
</head>
<body>
    <div class="container">
        <h1>🔥 SELF HACK 100.0 - ULTIMATE AUDIT REPORT</h1>
        <div class="timestamp">Generated: $(Get-Date -Format "dd MMMM yyyy HH:mm:ss") on $env:COMPUTERNAME</div>
        
        <div class="summary">
            <div class="stat-card total"><h3>$totalFindings</h3>Total Findings</div>
            <div class="stat-card critical"><h3>$criticalCount</h3>Critical</div>
            <div class="stat-card high"><h3>$highCount</h3>High</div>
            <div class="stat-card medium"><h3>$mediumCount</h3>Medium</div>
            <div class="stat-card low"><h3>$lowCount</h3>Low</div>
            <div class="stat-card info"><h3>$infoCount</h3>Info</div>
        </div>
        
        <div class="chart-container">
            <div class="chart">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart">
                <canvas id="categoryChart"></canvas>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>📋 REKOMENDASI UTAMA</h3>
            <ul>
"@
    
    # Tambah rekomendasi dari hasil
    $recommendations = $global:allResults | Where-Object { $_.Category -like "Hardening - Recommendation" } | Select-Object -ExpandProperty Detail
    if ($recommendations) {
        foreach ($rec in $recommendations) {
            $html += "<li>$rec</li>`n"
        }
    } else {
        $html += "<li>Tidak ada rekomendasi khusus. Sistem terlihat cukup aman.</li>`n"
    }
    
    $html += @"
            </ul>
        </div>
        
        <h2>📊 DETAIL TEMUAN</h2>
        
        <div class="filter-box">
            <select id="severityFilter" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Info">Info</option>
            </select>
            
            <input type="text" id="categoryFilter" placeholder="Filter category..." onkeyup="filterTable()">
            <input type="text" id="searchInput" placeholder="Search all fields..." onkeyup="filterTable()" style="flex: 2;">
            <button onclick="filterTable()">Apply Filters</button>
        </div>
        
        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Name</th>
                    <th>Detail</th>
                    <th>Time</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($item in $global:allResults | Sort-Object { 
        @($_.Severity -eq "Critical", $_.Severity -eq "High", $_.Severity -eq "Medium", $_.Severity -eq "Low", $_.Severity -eq "Info") 
    }) {
        $time = if ($item.Time) { $item.Time.ToString("yyyy-MM-dd HH:mm") } else { "-" }
        $badgeClass = switch ($item.Severity) {
            "Critical" { "badge-critical" }
            "High" { "badge-high" }
            "Medium" { "badge-medium" }
            "Low" { "badge-low" }
            "Info" { "badge-info" }
            default { "badge-info" }
        }
        
        $html += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td>$($item.Name)</td>
                    <td>$($item.Detail)</td>
                    <td>$time</td>
                    <td><span class="badge $badgeClass">$($item.Severity)</span></td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <div class="footer">
            Self Hack 100.0 - Ultimate Overpower Edition | Output directory: $outputDir | Log file: $global:logFile
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Log "✅ Laporan HTML dibuat: $reportFile" -Color Green
    Start-Process $reportFile
}
#endregion

#region ========== 20. MAIN MENU ==========
function Show-Menu {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                     🔥 SELF HACK 100.0 - ULTIMATE EDITION 🔥                ║
║                     ⚡ Total System Audit & Forensics Toolkit ⚡             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  [01] Aktivasi Logging Maksimal (Audit Policy + Event Logs)                 ║
║  [02] Analisis Event Log Komprehensif (Brute Force, Anomaly)                ║
║  [03] Analisis Proses & Jaringan (Unsigned, Masquerading, LOLBins)          ║
║  [04] Analisis File System (Hidden, ADS, Permissions)                       ║
║  [05] Analisis Registry (Autorun, Persistence, Hijacking)                   ║
║  [06] Analisis User & Grup (Privileged, Inactive, Shadow)                   ║
║  [07] Analisis Persistence (Scheduled Tasks, Services, WMI)                 ║
║  [08] Analisis Forensik Artifacts (Prefetch, USB, History)                  ║
║  [09] Threat Hunting (MITRE ATT&CK Mapping)                                 ║
║  [10] Vulnerability Assessment (Missing Patches, Misconfig)                 ║
║  [11] Memory Analysis (Basic)                                               ║
║  [12] Installed Software Analysis                                           ║
║  [13] Browser Security Analysis                                             ║
║  [14] Network Shares Analysis                                               ║
║  [15] Active Directory Analysis (Jika Domain)                               ║
║  [16] Encryption Status Analysis (BitLocker, EFS)                           ║
║  [17] Log Pattern Analysis (Multiple Events Correlation)                    ║
║  [18] Generate Hardening Recommendations                                    ║
║  [19] JALANKAN SEMUA MODUL (Audit Lengkap - 30-60 menit)                    ║
║  [20] JALANKAN MODUL CEPAT (1-10, 5-10 menit)                               ║
║  [0]  Keluar                                                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Output Directory: $outputDir
║  Jalankan sebagai ADMINISTRATOR untuk hasil maksimal!
║  HANYA UNTUK SISTEM ANDA SENDIRI!
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red
}

function Invoke-QuickAudit {
    Write-Log "🚀 MODE CEPAT: Menjalankan modul 1-10..." -Color Green
    Enable-MaximumLogging
    Analyze-EventLogs
    Analyze-ProcessesAndNetwork
    Analyze-FileSystem
    Analyze-Registry
    Analyze-UsersAndGroups
    Analyze-Persistence
    Analyze-ForensicArtifacts
    Analyze-ThreatHunting
    Analyze-Vulnerabilities
    Generate-HardeningRecommendations
    Export-Results
    Write-Log "✅ MODE CEPAT SELESAI!" -Color Green
}

function Invoke-FullAudit {
    Write-Log "🔥 MODE LENGKAP: Menjalankan SEMUA modul..." -Color Green
    Enable-MaximumLogging
    Analyze-EventLogs
    Analyze-ProcessesAndNetwork
    Analyze-FileSystem
    Analyze-Registry
    Analyze-UsersAndGroups
    Analyze-Persistence
    Analyze-ForensicArtifacts
    Analyze-ThreatHunting
    Analyze-Vulnerabilities
    Analyze-Memory
    Analyze-Software
    Analyze-BrowserSecurity
    Analyze-NetworkShares
    Analyze-ActiveDirectory
    Analyze-Encryption
    Analyze-LogPatterns
    Generate-HardeningRecommendations
    Export-Results
    Write-Log "✅ MODE LENGKAP SELESAI!" -Color Green
}
#endregion

#region ========== EXECUTION ==========
# Cek admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Script harus dijalankan sebagai Administrator!" -ForegroundColor Red
    Write-Host "Klik kanan PowerShell → Run as Administrator" -ForegroundColor Yellow
    exit 1
}

do {
    Show-Menu
    $choice = Read-Host "`nPilih menu (0-20)"
    
    switch ($choice) {
        '1' { Enable-MaximumLogging }
        '2' { Analyze-EventLogs }
        '3' { Analyze-ProcessesAndNetwork }
        '4' { Analyze-FileSystem }
        '5' { Analyze-Registry }
        '6' { Analyze-UsersAndGroups }
        '7' { Analyze-Persistence }
        '8' { Analyze-ForensicArtifacts }
        '9' { Analyze-ThreatHunting }
        '10' { Analyze-Vulnerabilities }
        '11' { Analyze-Memory }
        '12' { Analyze-Software }
        '13' { Analyze-BrowserSecurity }
        '14' { Analyze-NetworkShares }
        '15' { Analyze-ActiveDirectory }
        '16' { Analyze-Encryption }
        '17' { Analyze-LogPatterns }
        '18' { Generate-HardeningRecommendations }
        '19' { Invoke-FullAudit }
        '20' { Invoke-QuickAudit }
        '0' { 
            Write-Host "Keluar..." -ForegroundColor Green
            exit
        }
        default { Write-Host "Pilihan tidak valid." -ForegroundColor Red }
    }
    
    if ($choice -in '1'..'20') {
        # Jika belum export, tawarkan export
        if ($global:allResults.Count -gt 0 -and $choice -notin @('19','20')) {
            $exportChoice = Read-Host "`nTemuan tersedia. Export hasil? (Y/N)"
            if ($exportChoice -eq 'Y') {
                Export-Results
            }
        }
        Write-Host "`nTekan Enter untuk kembali ke menu..." -ForegroundColor Gray
        Read-Host
    }
} while ($true)
#endregion
