<#
.SINOPSIS
    Alat audit keamanan untuk sistem sendiri (ethical hacking).
.DESCRIPTION
    Script ini menyediakan berbagai fungsi untuk mengaudit keamanan Windows,
    memulihkan akses, dan memeriksa kerentanan. HANYA UNTUK DIGUNAKAN PADA SISTEM ANDA SENDIRI.
.NOTES
    Jalankan sebagai Administrator untuk fungsi maksimal.
    Penulis: Ethical Hacker
#>

# Fungsi untuk menjalankan perintah dengan output berwarna
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Fungsi untuk mendapatkan password WiFi yang tersimpan
function Show-WiFiPasswords {
    Write-ColorOutput Cyan "`n=== MENAMPILKAN PASSWORD WIFI TERSIMPAN ==="
    
    # Ambil daftar profil WiFi
    $profilesRaw = netsh wlan show profiles
    
    # Cari baris yang mengandung profil (format: "Nama Profile : nilai" atau "All User Profile : nilai")
    $profileLines = $profilesRaw | Select-String ":[ ]+"
    
    if ($profileLines.Count -eq 0) {
        Write-ColorOutput Yellow "Tidak ada profil WiFi ditemukan."
        return
    }
    
    foreach ($line in $profileLines) {
        # Ambil nama profil setelah tanda titik dua, lalu bersihkan spasi
        $profileName = ($line -split ":")[1].Trim()
        
        # Tampilkan detail profil dengan password
        $details = netsh wlan show profile name="$profileName" key=clear
        
        # Cari baris yang berisi password (Indonesia: "Konten kunci", Inggris: "Key Content")
        $passwordLine = $details | Select-String "Konten kunci|Key Content"
        
        if ($passwordLine) {
            $password = ($passwordLine -split ":")[1].Trim()
            Write-Output "$profileName : $password"
        } else {
            Write-Output "$profileName : (tanpa password atau tersembunyi)"
        }
    }
}
# Fungsi untuk menampilkan proses mencurigakan (berdasarkan nama umum malware)
function Show-SuspiciousProcesses {
    Write-ColorOutput Cyan "`n=== MEMERIKSA PROSES MENCURIGAKAN ==="
    $suspiciousNames = @(
        'cmd', 'powershell', 'wscript', 'cscript', 'mshta', 'regsvr32',
        'rundll32', 'schtasks', 'taskkill', 'vssadmin', 'bcdedit',
        'wmic', 'net', 'net1', 'sc', 'whoami', 'systeminfo', 'ipconfig',
        'nslookup', 'ping', 'tracert', 'pathping', 'arp', 'route',
        'netsh', 'bitsadmin', 'certutil', 'curl', 'wget'
    )
    $processes = Get-Process | Where-Object { $_.ProcessName -in $suspiciousNames }
    if ($processes) {
        Write-ColorOutput Red "Proses mencurigakan ditemukan:"
        $processes | Format-Table ProcessName, Id, SessionId
    } else {
        Write-ColorOutput Green "Tidak ada proses mencurigakan terdeteksi."
    }
}

# Fungsi untuk memeriksa kebijakan password lokal
function Check-PasswordPolicy {
    Write-ColorOutput Cyan "`n=== KEBIJAKAN PASSWORD LOKAL ==="
    try {
        $policy = net accounts
        $policy | ForEach-Object { Write-Output $_ }
    } catch {
        Write-ColorOutput Red "Gagal membaca kebijakan password: $_"
    }
}

# Fungsi untuk menampilkan file dan folder tersembunyi di direktori tertentu
function Show-HiddenFiles {
    param(
        [string]$Path = "C:\"
    )
    Write-ColorOutput Cyan "`n=== FILE TERSEMBUNYI DI $Path ==="
    try {
        $hidden = Get-ChildItem -Path $Path -Force | Where-Object { $_.Attributes -match "Hidden" }
        if ($hidden) {
            $hidden | Format-Table Name, Attributes, LastWriteTime
        } else {
            Write-Output "Tidak ada file tersembunyi ditemukan."
        }
    } catch {
        Write-ColorOutput Red "Error: $_"
    }
}

# Fungsi untuk mengambil kepemilikan file/folder (membuka kunci)
function Take-Ownership {
    param(
        [string]$Path
    )
    if (-not $Path) {
        $Path = Read-Host "Masukkan path file/folder"
    }
    if (-not (Test-Path $Path)) {
        Write-ColorOutput Red "Path tidak ditemukan."
        return
    }
    try {
        Write-ColorOutput Yellow "Mengambil kepemilikan $Path ..."
        takeown /F $Path /R /D Y | Out-Null
        icacls $Path /grant "${env:USERNAME}:F" /T /Q | Out-Null
        Write-ColorOutput Green "Berhasil mengambil kepemilikan."
    } catch {
        Write-ColorOutput Red "Gagal: $_"
    }
}

# Fungsi untuk menjalankan ulang script dengan hak administrator
function Restart-AsAdmin {
    Write-ColorOutput Yellow "Meminta hak administrator..."
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    Exit
}

# Menu utama
function Show-Menu {
    Clear-Host
    Write-ColorOutput Green "======================================"
    Write-ColorOutput Green "   ETHICAL HACKING TOOLKIT (SENDIRI)  "
    Write-ColorOutput Green "======================================"
    Write-ColorOutput Yellow "Peringatan: Hanya untuk sistem Anda sendiri!"
    Write-Output ""
    Write-Output "1. Tampilkan semua password WiFi tersimpan"
    Write-Output "2. Periksa proses mencurigakan"
    Write-Output "3. Periksa kebijakan password lokal"
    Write-Output "4. Tampilkan file tersembunyi di C:\"
    Write-Output "5. Ambil kepemilikan file/folder (unlock)"
    Write-Output "6. Jalankan ulang sebagai Administrator"
    Write-Output "0. Keluar"
    Write-Output ""
}

# Loop utama
do {
    Show-Menu
    $choice = Read-Host "Pilih menu (0-6)"
    switch ($choice) {
        '1' { Show-WiFiPasswords }
        '2' { Show-SuspiciousProcesses }
        '3' { Check-PasswordPolicy }
        '4' { Show-HiddenFiles -Path "C:\" }
        '5' { Take-Ownership }
        '6' { Restart-AsAdmin }
        '0' { Write-ColorOutput Green "Keluar..." }
        default { Write-ColorOutput Red "Pilihan tidak valid." }
    }
    if ($choice -ne '0') {
        Write-Output ""
        pause
    }
} while ($choice -ne '0')
