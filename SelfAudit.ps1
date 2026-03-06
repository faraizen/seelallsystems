<#
.SINOPSIS
    Alat audit keamanan total untuk sistem sendiri (ethical hacking overpower).
.DESCRIPTION
    Script ini melakukan audit menyeluruh terhadap sistem Windows:
    - Mengaktifkan logging maksimal (audit policy, process creation, command line)
    - Menganalisis event log untuk aktivitas mencurigakan
    - Memindai proses, koneksi jaringan, dan file tanpa signature
    - Memeriksa file dan folder tersembunyi
    - Menganalisis permission NTFS yang berisiko
    - Mendeteksi backdoor dan persistence mechanism
    - Membuat laporan HTML interaktif
.NOTES
    HANYA UNTUK SISTEM ANDA SENDIRI!
    Jalankan sebagai Administrator.
    Versi: 2.0 - Overpower Mode
#>

#region Inisialisasi
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "C:\SelfHack-$timestamp"
$reportFile = "$outputDir\Laporan_Audit.html"
$csvFile = "$outputDir\Hasil_Audit.csv"
$logFile = "$outputDir\AuditLog.txt"

# Buat direktori output
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Fungsi untuk menulis log
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $time = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$time] $Message"
    Write-Host $logMessage -ForegroundColor $Color
    Add-Content -Path $logFile -Value $logMessage
}

# Fungsi untuk menulis section header
function Write-Section {
    param([string]$Title)
    Write-Log "`n" -Color White
    Write-Log "="*60 -Color Cyan
    Write-Log "  $Title" -Color Cyan
    Write-Log "="*60 -Color Cyan
}
#endregion

#region 1. Aktivasi Logging Maksimal (Audit Policy)
function Enable-MaximumLogging {
    Write-Section "MENGAKTIFKAN LOGGING MAKSIMAL"
    
    # 1.1 Audit Policy - Logon/Logoff
    Write-Log "Mengaktifkan audit logon/logoff..." -Color Yellow
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
    
    # 1.2 Audit Policy - Account Logon
    Write-Log "Mengaktifkan audit credential validation..." -Color Yellow
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
    
    # 1.3 Audit Policy - Process Creation (kritis untuk forensik) [citation:2]
    Write-Log "Mengaktifkan audit process creation..." -Color Yellow
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    
    # 1.4 Aktifkan command line logging [citation:2]
    Write-Log "Mengaktifkan command line logging..." -Color Yellow
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    
    # 1.5 Audit Policy - Privilege Use
    Write-Log "Mengaktifkan audit privilege use..." -Color Yellow
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
    
    # 1.6 Audit Policy - Object Access
    Write-Log "Mengaktifkan audit file share..." -Color Yellow
    auditpol /set /subcategory:"File Share" /success:enable | Out-Null
    auditpol /set /subcategory:"Detailed File Share" /success:enable | Out-Null
    
    # 1.7 Audit Policy - Filtering Platform Connection [citation:2]
    Write-Log "Mengaktifkan audit network connections..." -Color Yellow
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable | Out-Null
    
    # 1.8 Audit Policy - Account Management
    Write-Log "Mengaktifkan audit account management..." -Color Yellow
    auditpol /set /subcategory:"User Account Management" /success:enable | Out-Null
    auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null
    
    # 1.9 PowerShell Script Block Logging [citation:1][citation:7]
    Write-Log "Mengaktifkan PowerShell script block logging..." -Color Yellow
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
    Set-ItemProperty -Path $psLogPath -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force
    
    # 1.10 PowerShell Module Logging
    $psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $psModPath)) { New-Item -Path $psModPath -Force | Out-Null }
    Set-ItemProperty -Path $psModPath -Name EnableModuleLogging -Value 1 -Type DWord -Force
    
    Write-Log "✅ Logging maksimal telah diaktifkan!" -Color Green
}
#endregion

#region 2. Analisis Event Log Mencurigakan
function Analyze-SuspiciousEvents {
    Write-Section "ANALISIS EVENT LOG MENCURIGAKAN"
    
    $results = @()
    $startTime = (Get-Date).AddDays(-30) # 30 hari terakhir
    
    # 2.1 Failed logon attempts (brute force)
    Write-Log "Mencari failed logon attempts..." -Color Yellow
    $failedLogons = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Select-Object -First 100
    
    if ($failedLogons) {
        Write-Log "  Ditemukan $($failedLogons.Count) failed logon attempts" -Color Magenta
        foreach ($event in $failedLogons) {
            $results += [PSCustomObject]@{
                EventID = 4625
                Time = $event.TimeCreated
                Type = "Failed Logon"
                Detail = "User: $($event.Properties[5].Value), IP: $($event.Properties[18].Value)"
                Severity = "High"
            }
        }
    }
    
    # 2.2 Account created/deleted [citation:9]
    Write-Log "Mencari account creation/deletion..." -Color Yellow
    $accountEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4720,4722,4723,4724,4725,4726,4738
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Select-Object -First 100
    
    if ($accountEvents) {
        Write-Log "  Ditemukan $($accountEvents.Count) account management events" -Color Magenta
        foreach ($event in $accountEvents) {
            $results += [PSCustomObject]@{
                EventID = $event.Id
                Time = $event.TimeCreated
                Type = "Account Management"
                Detail = "User: $($event.Properties[0].Value), Action: $($event.Message -replace '\n',' ' -replace '\r',' ')"
                Severity = "High"
            }
        }
    }
    
    # 2.3 Privilege use [citation:2]
    Write-Log "Mencari privilege use events..." -Color Yellow
    $privilegeEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4672,4673,4674
        StartTime=$startTime
    } -ErrorAction SilentlyContinue | Select-Object -First 100
    
    if ($privilegeEvents) {
        Write-Log "  Ditemukan $($privilegeEvents.Count) privilege use events" -Color Magenta
        foreach ($event in $privilegeEvents) {
            $results += [PSCustomObject]@{
                EventID = $event.Id
                Time = $event.TimeCreated
                Type = "Privilege Use"
                Detail = $event.Message -replace '\n',' ' -replace '\r',' '
                Severity = "Medium"
            }
        }
    }
    
    # 2.4 PowerShell script block logging mencurigakan [citation:7]
    Write-Log "Mencari PowerShell script block mencurigakan..." -Color Yellow
    $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue | 
                Where-Object { $_.Id -eq 4104 -and ($_.Message -match "frombase64string" -or $_.Message -match "system.net.webclient" -or $_.Message -match "-enc") }
    
    if ($psEvents) {
        Write-Log "  Ditemukan $($psEvents.Count) PowerShell script blocks mencurigakan" -Color Magenta
        foreach ($event in $psEvents) {
            $results += [PSCustomObject]@{
                EventID = 4104
                Time = $event.TimeCreated
                Type = "Suspicious PowerShell"
                Detail = ($event.Message -replace '\n',' ' -replace '\r',' ').Substring(0, [Math]::Min(200, $event.Message.Length))
                Severity = "Critical"
            }
        }
    }
    
    Write-Log "✅ Analisis event log selesai. Total temuan: $($results.Count)" -Color Green
    return $results
}
#endregion

#region 3. Analisis Proses dan Jaringan
function Analyze-ProcessesAndNetwork {
    Write-Section "ANALISIS PROSES DAN JARINGAN"
    
    $results = @()
    
    # 3.1 Proses tanpa signature digital [citation:6]
    Write-Log "Memeriksa proses tanpa signature digital..." -Color Yellow
    $unsigned = Get-Process | Where-Object { $_.MainModule -and -not (Get-AuthenticodeSignature $_.MainModule.FileName).Status -eq "Valid" } |
                Select-Object -First 50
    
    if ($unsigned) {
        Write-Log "  Ditemukan $($unsigned.Count) proses tanpa signature valid" -Color Magenta
        foreach ($proc in $unsigned) {
            $results += [PSCustomObject]@{
                Category = "Unsigned Process"
                Name = $proc.ProcessName
                Detail = "PID: $($proc.Id), Path: $($proc.Path)"
                Severity = "Medium"
            }
        }
    }
    
    # 3.2 Koneksi jaringan mencurigakan [citation:6]
    Write-Log "Memeriksa koneksi jaringan aktif..." -Color Yellow
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' }
    
    if ($connections) {
        Write-Log "  Ditemukan $($connections.Count) koneksi ke IP publik" -Color Magenta
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }
            $results += [PSCustomObject]@{
                Category = "Network Connection"
                Name = $procName
                Detail = "$($conn.LocalAddress):$($conn.LocalPort) → $($conn.RemoteAddress):$($conn.RemotePort)"
                Severity = "Low"
            }
        }
    }
    
    # 3.3 Proses dengan nama mencurigakan (masquerading)
    Write-Log "Memeriksa proses dengan nama mencurigakan..." -Color Yellow
    $suspiciousNames = @('svchost', 'lsass', 'winlogon', 'csrss', 'services', 'smss')
    $suspicious = Get-Process | Where-Object { $_.ProcessName -in $suspiciousNames -and $_.Path -notmatch 'System32' }
    
    if ($suspicious) {
        Write-Log "  Ditemukan $($suspicious.Count) proses dengan nama sistem di lokasi tidak biasa" -Color Magenta
        foreach ($proc in $suspicious) {
            $results += [PSCustomObject]@{
                Category = "Masquerading Process"
                Name = $proc.ProcessName
                Detail = "Path: $($proc.Path)"
                Severity = "Critical"
            }
        }
    }
    
    Write-Log "✅ Analisis proses dan jaringan selesai." -Color Green
    return $results
}
#endregion

#region 4. Analisis File dan Registry
function Analyze-FilesAndRegistry {
    Write-Section "ANALISIS FILE DAN REGISTRY"
    
    $results = @()
    
    # 4.1 File tersembunyi di direktori sistem [citation:3]
    Write-Log "Memeriksa file tersembunyi di direktori sistem..." -Color Yellow
    $systemDirs = @("C:\Windows", "C:\Windows\System32", "C:\ProgramData")
    foreach ($dir in $systemDirs) {
        if (Test-Path $dir) {
            $hidden = Get-ChildItem -Path $dir -Force | Where-Object { $_.Attributes -match "Hidden" -and -not $_.PSIsContainer } | Select-Object -First 20
            foreach ($file in $hidden) {
                $results += [PSCustomObject]@{
                    Category = "Hidden System File"
                    Name = $file.Name
                    Detail = "Path: $($file.FullName), Size: $([math]::Round($file.Length/1KB,2)) KB"
                    Severity = "Medium"
                }
            }
        }
    }
    
    # 4.2 Autorun entries (persistence) [citation:6]
    Write-Log "Memeriksa autorun entries (persistence)..." -Color Yellow
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $autorunPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path
            $items.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } | ForEach-Object {
                $results += [PSCustomObject]@{
                    Category = "Autorun Entry"
                    Name = $_.Name
                    Detail = "Command: $($_.Value), Registry: $path"
                    Severity = "Low"
                }
            }
        }
    }
    
    # 4.3 File dengan permission berisiko [citation:4]
    Write-Log "Memeriksa file dengan permission berisiko (contoh: C:\)..." -Color Yellow
    try {
        $acl = Get-Acl "C:\" -ErrorAction SilentlyContinue
        $riskyAccess = $acl.Access | Where-Object { $_.FileSystemRights -match "FullControl" -and $_.IdentityReference -match "Everyone|Users" }
        if ($riskyAccess) {
            $results += [PSCustomObject]@{
                Category = "Risky Permission"
                Name = "C:\"
                Detail = "$($riskyAccess.IdentityReference) has FullControl"
                Severity = "High"
            }
        }
    } catch {}
    
    Write-Log "✅ Analisis file dan registry selesai." -Color Green
    return $results
}
#endregion

#region 5. Analisis User dan Grup
function Analyze-UsersAndGroups {
    Write-Section "ANALISIS USER DAN GRUP"
    
    $results = @()
    
    # 5.1 User yang tidak aktif [citation:6]
    Write-Log "Memeriksa user yang tidak pernah login..." -Color Yellow
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $inactiveUsers = @()
    foreach ($user in $users) {
        $lastLogon = (Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1 -ErrorAction SilentlyContinue | 
                      Where-Object { $_.Properties[5].Value -eq $user.Name }).TimeCreated
        if (-not $lastLogon) {
            $inactiveUsers += $user.Name
        }
    }
    
    if ($inactiveUsers) {
        Write-Log "  Ditemukan $($inactiveUsers.Count) user yang tidak pernah login" -Color Magenta
        foreach ($u in $inactiveUsers) {
            $results += [PSCustomObject]@{
                Category = "Inactive User"
                Name = $u
                Detail = "User has never logged in"
                Severity = "Low"
            }
        }
    }
    
    # 5.2 Grup admin yang mencurigakan
    Write-Log "Memeriksa anggota grup administrator..." -Color Yellow
    $adminMembers = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }
    Write-Log "  Anggota Administrators: $($adminMembers.Name -join ', ')" -Color Gray
    
    # 5.3 Password policy [citation:2]
    Write-Log "Memeriksa kebijakan password..." -Color Yellow
    $policy = net accounts
    $minPwdLen = ($policy | Select-String "Minimum password length" | Select-String -NotMatch "0").ToString()
    if ($minPwdLen -match "(\d+)") {
        $len = [int]$matches[1]
        if ($len -lt 8) {
            $results += [PSCustomObject]@{
                Category = "Weak Password Policy"
                Name = "Min Password Length"
                Detail = "$len characters (recommended: 8+)"
                Severity = "Medium"
            }
        }
    }
    
    Write-Log "✅ Analisis user dan grup selesai." -Color Green
    return $results
}
#endregion

#region 6. Generate HTML Report [citation:4]
function Generate-HTMLReport {
    param(
        [array]$EventResults,
        [array]$ProcessResults,
        [array]$FileResults,
        [array]$UserResults
    )
    
    Write-Section "MEMBUAT LAPORAN HTML INTERAKTIF"
    
    $allResults = $EventResults + $ProcessResults + $FileResults + $UserResults
    
    # Hitung statistik
    $totalFindings = $allResults.Count
    $criticalCount = ($allResults | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($allResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($allResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($allResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    # Buat HTML
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Self Hack Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }
        h2 { color: #1976d2; margin-top: 30px; }
        .summary { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .stat-card { flex: 1; min-width: 150px; padding: 20px; border-radius: 8px; color: white; text-align: center; }
        .critical { background-color: #d32f2f; }
        .high { background-color: #f57c00; }
        .medium { background-color: #fbc02d; color: black; }
        .low { background-color: #388e3c; }
        .total { background-color: #1976d2; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .badge { padding: 3px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }
        .badge-critical { background-color: #d32f2f; }
        .badge-high { background-color: #f57c00; }
        .badge-medium { background-color: #fbc02d; color: black; }
        .badge-low { background-color: #388e3c; }
        .footer { margin-top: 30px; text-align: center; color: #777; font-size: 12px; }
        .timestamp { color: #777; margin-bottom: 20px; }
        .filter-box { margin: 20px 0; padding: 10px; background-color: #e3f2fd; border-radius: 5px; }
        input, select { padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 4px; }
    </style>
    <script>
        function filterTable() {
            const severity = document.getElementById('severityFilter').value;
            const search = document.getElementById('searchInput').value.toLowerCase();
            const table = document.getElementById('resultsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const severityCell = row.getElementsByTagName('td')[4];
                const textContent = row.textContent.toLowerCase();
                
                let show = true;
                if (severity && severityCell) {
                    const rowSeverity = severityCell.textContent.trim();
                    if (rowSeverity !== severity) show = false;
                }
                if (search && !textContent.includes(search)) show = false;
                
                row.style.display = show ? '' : 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🔍 SELF HACK AUDIT REPORT</h1>
        <div class="timestamp">Generated: $(Get-Date -Format "dd MMM yyyy HH:mm:ss")</div>
        
        <div class="summary">
            <div class="stat-card total">Total Findings<br><h2>$totalFindings</h2></div>
            <div class="stat-card critical">Critical<br><h2>$criticalCount</h2></div>
            <div class="stat-card high">High<br><h2>$highCount</h2></div>
            <div class="stat-card medium">Medium<br><h2>$mediumCount</h2></div>
            <div class="stat-card low">Low<br><h2>$lowCount</h2></div>
        </div>
        
        <h2>📋 Detail Temuan</h2>
        
        <div class="filter-box">
            <label>Filter Severity:</label>
            <select id="severityFilter" onchange="filterTable()">
                <option value="">All</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
            </select>
            
            <label>Search:</label>
            <input type="text" id="searchInput" placeholder="Search..." onkeyup="filterTable()">
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
    
    foreach ($item in $allResults | Sort-Object { @($_.Severity -eq "Critical", $_.Severity -eq "High", $_.Severity -eq "Medium", $_.Severity -eq "Low") }) {
        $time = if ($item.Time) { $item.Time.ToString("yyyy-MM-dd HH:mm") } else { "-" }
        $badgeClass = switch ($item.Severity) {
            "Critical" { "badge-critical" }
            "High" { "badge-high" }
            "Medium" { "badge-medium" }
            "Low" { "badge-low" }
            default { "badge-low" }
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
        
        <h2>📊 Rekomendasi Keamanan</h2>
        <ul>
"@
    
    if ($criticalCount -gt 0) {
        $html += "<li><b>CRITICAL:</b> Segera investigasi proses masquerading, PowerShell mencurigakan, dan privilege abuse.</li>"
    }
    if ($highCount -gt 0) {
        $html += "<li><b>HIGH:</b> Periksa failed logon attempts, permission berisiko, dan unsigned processes.</li>"
    }
    if ($mediumCount -gt 0) {
        $html += "<li><b>MEDIUM:</b> Evaluasi kebijakan password, hidden system files, dan privilege use events.</li>"
    }
    if ($lowCount -gt 0) {
        $html += "<li><b>LOW:</b> Review autorun entries, inactive users, dan network connections.</li>"
    }
    
    $html += @"
        </ul>
        
        <div class="footer">
            Self Hack Overpower Tool | Generated from $env:COMPUTERNAME | Logs saved to $outputDir
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Log "✅ Laporan HTML dibuat: $reportFile" -Color Green
}
#endregion

#region 7. Fungsi Forensik Tambahan
function Get-ForensicArtifacts {
    Write-Section "MENGUMPULKAN ARTIFAK FORENSIK"
    
    # 7.1 Prefetch files (program yang pernah dijalankan)
    Write-Log "Mengumpulkan Prefetch files..." -Color Yellow
    $prefetchDir = "C:\Windows\Prefetch"
    if (Test-Path $prefetchDir) {
        $prefetch = Get-ChildItem -Path $prefetchDir -Filter "*.pf" | Sort-Object LastWriteTime -Descending | Select-Object -First 50
        $prefetch | ForEach-Object {
            Add-Content -Path "$outputDir\Prefetch.txt" -Value "$($_.LastWriteTime) - $($_.Name)"
        }
        Write-Log "  Menyimpan 50 Prefetch files terbaru" -Color Gray
    }
    
    # 7.2 Scheduled tasks
    Write-Log "Mengumpulkan scheduled tasks..." -Color Yellow
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, State, LastRunTime, NextRunTime
    $tasks | Export-Csv -Path "$outputDir\ScheduledTasks.csv" -NoTypeInformation
    
    # 7.3 Services
    Write-Log "Mengumpulkan services..." -Color Yellow
    $services = Get-Service | Where-Object { $_.Status -eq "Running" -and $_.StartType -eq "Automatic" }
    $services | Export-Csv -Path "$outputDir\Services.csv" -NoTypeInformation
    
    # 7.4 Installed programs
    Write-Log "Mengumpulkan installed programs..." -Color Yellow
    $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                   HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                   HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $installed | Export-Csv -Path "$outputDir\InstalledPrograms.csv" -NoTypeInformation
    
    Write-Log "✅ Artifak forensik telah dikumpulkan." -Color Green
}
#endregion

#region 8. Main Menu
function Show-Menu {
    Clear-Host
    Write-Host @"

╔════════════════════════════════════════════════════════════╗
║     🔥 SELF HACK OVERPOWER TOOL v2.0 🔥                    ║
║     Total System Audit & Forensics                          ║
╠════════════════════════════════════════════════════════════╣
║  HANYA UNTUK SISTEM ANDA SENDIRI!                          ║
║  Jalankan sebagai Administrator                             ║
╚════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Red
    
    Write-Host "Output akan disimpan di: $outputDir" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Pilih mode audit:" -ForegroundColor Yellow
    Write-Host "  [1] Audit CEPAT (15-30 detik) - Ringkasan utama"
    Write-Host "  [2] Audit LENGKAP (5-10 menit) - Semua analisis + forensik"
    Write-Host "  [3] Audit MAXIMUM (30+ menit) - Deep scan + semua event log"
    Write-Host "  [4] Aktifkan Logging Maksimal (reboot mungkin diperlukan)"
    Write-Host "  [0] Keluar"
    Write-Host ""
}

function Start-Audit {
    param([string]$Mode)
    
    $eventResults = @()
    $processResults = @()
    $fileResults = @()
    $userResults = @()
    
    switch ($Mode) {
        "quick" {
            Write-Log "MODE CEPAT: Memulai audit ringkasan..." -Color Green
            $processResults = Analyze-ProcessesAndNetwork
            $userResults = Analyze-UsersAndGroups
        }
        "full" {
            Write-Log "MODE LENGKAP: Memulai audit komprehensif..." -Color Green
            $eventResults = Analyze-SuspiciousEvents
            $processResults = Analyze-ProcessesAndNetwork
            $fileResults = Analyze-FilesAndRegistry
            $userResults = Analyze-UsersAndGroups
            Get-ForensicArtifacts
        }
        "maximum" {
            Write-Log "MODE MAXIMUM: Memulai deep scan..." -Color Green
            Write-Log "Ini akan memakan waktu lama. Sabar..." -Color Yellow
            
            # Full + extended time range
            $eventResults = Analyze-SuspiciousEvents # sudah 30 hari
            $processResults = Analyze-ProcessesAndNetwork
            $fileResults = Analyze-FilesAndRegistry
            
            # Scan lebih banyak direktori
            Write-Log "Memindai semua file tersembunyi di C:\..." -Color Yellow
            $allHidden = Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Attributes -match "Hidden" -and -not $_.PSIsContainer } | 
                        Select-Object -First 200
            foreach ($file in $allHidden) {
                $fileResults += [PSCustomObject]@{
                    Category = "Hidden File (Deep Scan)"
                    Name = $file.Name
                    Detail = $file.FullName
                    Severity = "Low"
                }
            }
            
            $userResults = Analyze-UsersAndGroups
            Get-ForensicArtifacts
        }
    }
    
    # Generate report
    Generate-HTMLReport -EventResults $eventResults -ProcessResults $processResults -FileResults $fileResults -UserResults $userResults
    
    # Buka laporan
    Start-Process $reportFile
    
    Write-Log "`n✅ AUDIT SELESAI!" -Color Green
    Write-Log "Laporan: $reportFile" -Color Cyan
    Write-Log "Data mentah: $outputDir" -Color Cyan
}
#endregion

#region Execution
# Cek admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Script harus dijalankan sebagai Administrator!" -ForegroundColor Red
    Write-Host "Klik kanan PowerShell → Run as Administrator" -ForegroundColor Yellow
    exit 1
}

do {
    Show-Menu
    $choice = Read-Host "Pilih menu (0-4)"
    
    switch ($choice) {
        '1' { Start-Audit -Mode "quick" }
        '2' { Start-Audit -Mode "full" }
        '3' { Start-Audit -Mode "maximum" }
        '4' { Enable-MaximumLogging }
        '0' { 
            Write-Host "Keluar..." -ForegroundColor Green
            exit
        }
        default { Write-Host "Pilihan tidak valid." -ForegroundColor Red }
    }
    
    if ($choice -in '1','2','3','4') {
        Write-Host "`nTekan Enter untuk kembali ke menu..." -ForegroundColor Gray
        Read-Host
    }
} while ($true)
#endregion
