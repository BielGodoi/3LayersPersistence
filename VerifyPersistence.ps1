# ==================================================================================================
# VERIFY SCRIPT
# ==================================================================================================

$objectPrefix   = "MaldevAcademy"

$wmiExeDir      = "C:\Windows\System32\wbem"
$wmiExeName     = "SgrmBroker.exe"
$wmiExePath     = "$wmiExeDir\$wmiExeName"

$comDllDir      = "$env:APPDATA\Microsoft\Common"
$comPayloadDll  = "MsComHost.dll"
$comForwardDll  = "Common.StateRepositoryRM.dll"

$spotifyDir     = "$env:APPDATA\Spotify"
$sideloadDll    = "dsound.dll"
$forwardDll     = "dspatial.dll"

$comClsidKey    = "HKCU:\Software\Classes\CLSID\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}"
$configKey      = "HKCU:\Software\$objectPrefix\XXXX"

# ==================================================================================================
# LOCATE DUMPBIN.EXE
# ==================================================================================================

$dumpbin = Get-ChildItem -Path "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter "dumpbin.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if ($dumpbin) {
    Write-Host "[+] Found dumpbin.exe: $dumpbin`n" -ForegroundColor Green
} else {
    Write-Host "[!] dumpbin.exe Not Found - Export Inspection Will Be Skipped" -ForegroundColor Red
}

# ==================================================================================================
# LAYER 1 - WMI PERSISTENCE
# ==================================================================================================
Write-Host "[*] Verifying Layer 1 - WMI Persistence..." -ForegroundColor DarkCyan

$wmiFilter = Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "${objectPrefix}_Filter" }
if ($wmiFilter) {
    Write-Host "[+] WMI Event Filter Found: $($wmiFilter.Name)" -ForegroundColor Green
    Write-Host "    Query: $($wmiFilter.Query)" -ForegroundColor Gray
} else {
    Write-Host "[-] WMI Event Filter Not Found" -ForegroundColor Yellow
}

$wmiConsumer = Get-WMIObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Where-Object { $_.Name -eq "${objectPrefix}_Consumer" }
if ($wmiConsumer) {
    Write-Host "[+] WMI Event Consumer Found: $($wmiConsumer.Name)" -ForegroundColor Green
} else {
    Write-Host "[-] WMI Event Consumer Not Found" -ForegroundColor Yellow
}

$wmiBinding = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*$objectPrefix*" }
if ($wmiBinding) {
    Write-Host "[+] WMI Filter-Consumer Binding Found" -ForegroundColor Green
    Write-Host "    Filter:   $($wmiBinding.Filter)" -ForegroundColor Gray
    Write-Host "    Consumer: $($wmiBinding.Consumer)" -ForegroundColor Gray
} else {
    Write-Host "[-] WMI Filter-Consumer Binding Not Found" -ForegroundColor Yellow
}

if (Test-Path $wmiExePath) {
    $wmiExeFile = Get-Item $wmiExePath
    Write-Host "[+] WMI Executable Found: $wmiExePath [$([math]::Round($wmiExeFile.Length / 1KB, 1)) KB]" -ForegroundColor Green
    Write-Host "    CreationTime:   $($wmiExeFile.CreationTime)" -ForegroundColor Gray
    Write-Host "    LastWriteTime:  $($wmiExeFile.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "[-] WMI Executable Not Found: $wmiExePath" -ForegroundColor Yellow
}

# ==================================================================================================
# LAYER 2 - COM HIJACK
# ==================================================================================================
Write-Host "`n[*] Verifying Layer 2 - DLL COM Hijack..." -ForegroundColor DarkCyan

if (Test-Path $comClsidKey) {
    Write-Host "[+] COM CLSID Key Found: $comClsidKey" -ForegroundColor Green
    $inprocKey = "$comClsidKey\InProcServer32"
    if (Test-Path $inprocKey) {
        $dllPath        = (Get-ItemProperty -Path $inprocKey).'(default)'
        $threadingModel = (Get-ItemProperty -Path $inprocKey).ThreadingModel
        Write-Host "    Default:        $dllPath" -ForegroundColor Gray
        Write-Host "    ThreadingModel: $threadingModel" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] COM CLSID Key Not Found" -ForegroundColor Yellow
}

if (Test-Path $comDllDir) {
    Write-Host "[+] COM DLL Directory Found: $comDllDir" -ForegroundColor Green
    Get-ChildItem -Path $comDllDir -Recurse | ForEach-Object {
        Write-Host "    $($_.FullName) [$([math]::Round($_.Length / 1KB, 1)) KB]" -ForegroundColor Gray
        Write-Host "        CreationTime:  $($_.CreationTime)" -ForegroundColor DarkGray
        Write-Host "        LastWriteTime: $($_.LastWriteTime)" -ForegroundColor DarkGray

        if ($dumpbin -and ($_.Name -eq $comPayloadDll -or $_.Name -eq $comForwardDll)) {
            Write-Host "    Exports:" -ForegroundColor DarkGray
            & $dumpbin /exports $_.FullName 2>$null |
                Where-Object { $_ -match "^\s+\d+\s" } |
                ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
        }
    }
} else {
    Write-Host "[-] COM DLL Directory Not Found: $comDllDir" -ForegroundColor Yellow
}

# ==================================================================================================
# LAYER 3 - DLL SIDELOAD
# ==================================================================================================
Write-Host "`n[*] Verifying Layer 3 - DLL Sideload..." -ForegroundColor DarkCyan

foreach ($dll in @($sideloadDll, $forwardDll)) {
    $fullPath = "$spotifyDir\$dll"
    if (Test-Path $fullPath) {
        $file = Get-Item $fullPath
        Write-Host "[+] Found: $fullPath [$([math]::Round($file.Length / 1KB, 1)) KB]" -ForegroundColor Green
        Write-Host "    CreationTime:  $($file.CreationTime)" -ForegroundColor DarkGray
        Write-Host "    LastWriteTime: $($file.LastWriteTime)" -ForegroundColor DarkGray

        if ($dumpbin) {
            Write-Host "    Exports:" -ForegroundColor DarkGray
            & $dumpbin /exports $fullPath 2>$null |
                Where-Object { $_ -match "^\s+\d+\s" } |
                ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
        }
    } else {
        Write-Host "[-] Not Found: $fullPath" -ForegroundColor Yellow
    }
}

# ==================================================================================================
# PAYLOAD CONFIGURATION
# ==================================================================================================
Write-Host "`n[*] Verifying Payload Configuration..." -ForegroundColor DarkCyan

if (Test-Path $configKey) {
    Write-Host "[+] Configuration Registry Key Found: $configKey" -ForegroundColor Green
    Get-ItemProperty -Path $configKey | Select-Object -Property * -ExcludeProperty PS* | ForEach-Object {
        $_.PSObject.Properties | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Value) [0x$($_.Value.ToString('X8'))]" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "[-] Configuration Registry Key Not Found: $configKey" -ForegroundColor Yellow
}

Write-Host "`n[+] Verification Complete" -ForegroundColor DarkCyan