# ==================================================================================================
# CLEANUP SCRIPT
# ==================================================================================================

$objectPrefix   = "MaldevAcademy"

$wmiExeDir      = "C:\Windows\System32\wbem"
$wmiExeName     = "SgrmBroker.exe"
$wmiExePath     = "$wmiExeDir\$wmiExeName"

$comDllDir      = "$env:APPDATA\Microsoft\Common"

$spotifyDir     = "$env:APPDATA\Spotify"
$sideloadDll    = "dsound.dll"
$forwardDll     = "dspatial.dll"

$comClsidKey    = "HKCU:\Software\Classes\CLSID\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}"
$configKey      = "HKCU:\Software\$objectPrefix\XXXX"

# ==================================================================================================
# ADMIN PRIV ARE REQUIRED TO CLEANUP WMI AND SYSTEM32\WBEM\SgrmBroker.exe
# ==================================================================================================

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[!] Script must be run as Administrator" -ForegroundColor Red
    Exit
}

# ==================================================================================================
# LAYER 1 - WMI PERSISTENCE
# ==================================================================================================
Write-Host "[*] Cleaning Layer 1 - WMI Persistence..." -ForegroundColor DarkCyan

$wmiFilter = Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "${objectPrefix}_Filter" }
if ($wmiFilter) {
    $wmiFilter | ForEach-Object {
        $_ | Remove-WMIObject
        Write-Host "[+] Removed WMI Event Filter: $($_.Name)" -ForegroundColor Green
    }
} else {
    Write-Host "[i] Already Cleaned Up: WMI Event Filter" -ForegroundColor Yellow
}

$wmiConsumer = Get-WMIObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Where-Object { $_.Name -eq "${objectPrefix}_Consumer" }
if ($wmiConsumer) {
    $wmiConsumer | ForEach-Object {
        $_ | Remove-WMIObject
        Write-Host "[+] Removed WMI Event Consumer: $($_.Name)" -ForegroundColor Green
    }
} else {
    Write-Host "[i] Already Cleaned Up: WMI Event Consumer" -ForegroundColor Yellow
}

$wmiBinding = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*$objectPrefix*" }
if ($wmiBinding) {
    $wmiBinding | ForEach-Object {
        $_ | Remove-WMIObject
        Write-Host "[+] Removed WMI Filter-Consumer Binding" -ForegroundColor Green
    }
} else {
    Write-Host "[i] Already Cleaned Up: WMI Filter-Consumer Binding" -ForegroundColor Yellow
}

# Only remove our specific EXE — do NOT delete the wbem directory
if (Test-Path $wmiExePath) {
    Remove-Item -Path $wmiExePath -Force
    Write-Host "[+] Removed WMI Executable: $wmiExePath" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $wmiExePath" -ForegroundColor Yellow
}

# ==================================================================================================
# LAYER 2 - COM HIJACK
# ==================================================================================================
Write-Host "`n[*] Cleaning Layer 2 - DLL COM Hijack..." -ForegroundColor DarkCyan

if (Test-Path $comClsidKey) {
    Remove-Item -Path $comClsidKey -Recurse -Force
    Write-Host "[+] Removed COM Registry Key: $comClsidKey" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $comClsidKey" -ForegroundColor Yellow
}

if (Test-Path $comDllDir) {
    Get-ChildItem -Path $comDllDir -Recurse | ForEach-Object {
        Write-Host "[+] Removing: $($_.FullName)" -ForegroundColor Green
    }
    Remove-Item -Path $comDllDir -Recurse -Force
    Write-Host "[+] Removed COM DLL Directory: $comDllDir" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $comDllDir" -ForegroundColor Yellow
}

# ==================================================================================================
# LAYER 3 - DLL SIDELOAD
# ==================================================================================================
Write-Host "`n[*] Cleaning Layer 3 - DLL Sideload..." -ForegroundColor DarkCyan

if (Test-Path "$spotifyDir\$sideloadDll") {
    Remove-Item -Path "$spotifyDir\$sideloadDll" -Force
    Write-Host "[+] Removed Sideload DLL: $spotifyDir\$sideloadDll" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $spotifyDir\$sideloadDll" -ForegroundColor Yellow
}

if (Test-Path "$spotifyDir\$forwardDll") {
    Remove-Item -Path "$spotifyDir\$forwardDll" -Force
    Write-Host "[+] Removed Forward DLL: $spotifyDir\$forwardDll" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $spotifyDir\$forwardDll" -ForegroundColor Yellow
}

# ==================================================================================================
# PAYLOAD CONFIGURATION
# ==================================================================================================
Write-Host "`n[*] Cleaning Payload Configuration..." -ForegroundColor DarkCyan

if (Test-Path $configKey) {
    Remove-Item -Path $configKey -Recurse -Force
    Write-Host "[+] Removed Configuration Registry Key: $configKey" -ForegroundColor Green
} else {
    Write-Host "[i] Already Cleaned Up: $configKey" -ForegroundColor Yellow
}

Write-Host "`n[+] Cleanup Complete" -ForegroundColor DarkCyan