#include "DebugMacros.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                      FLS 
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD g_dwFlsIdx = FLS_OUT_OF_INDEXES;

static VOID WINAPI DbgFlsDestructor(IN PVOID pBuffer)
{
    if (pBuffer)
    {
        LocalFree((HLOCAL)pBuffer);
    }
}

static LPSTR DbgGetBuffer(VOID)
{
    DWORD   dwCandidateSlot = 0x00,
            dwFlsSlot       = 0x00;
    LPSTR   pThreadBuffer   = NULL;

    if ((DWORD)InterlockedOr((LONG volatile*)&g_dwFlsIdx, 0) == FLS_OUT_OF_INDEXES)
    {
        // Allocate one FLS slot process-wide 
        if ((dwCandidateSlot = FlsAlloc(DbgFlsDestructor)) == FLS_OUT_OF_INDEXES)
            return NULL;

        // Loser of the race discards its slot
        if ((DWORD)InterlockedCompareExchange((LONG volatile*)&g_dwFlsIdx, (LONG)dwCandidateSlot, (LONG)FLS_OUT_OF_INDEXES) != FLS_OUT_OF_INDEXES)
            FlsFree(dwCandidateSlot);
    }

    dwFlsSlot       = (DWORD)InterlockedOr((LONG volatile*)&g_dwFlsIdx, 0);
    pThreadBuffer   = (LPSTR)FlsGetValue(dwFlsSlot);

    // First call on this thread 
    if (pThreadBuffer == NULL)
    {
        // Allocate the thread's private buffer
        if ((pThreadBuffer = (LPSTR)LocalAlloc(LPTR, BUFFER_SIZE_2048)) == NULL)
            return NULL;

        FlsSetValue(dwFlsSlot, pThreadBuffer);
    }

    return pThreadBuffer;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                  FILE SINK 
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#ifdef _DBG_USE_FILE

static CHAR     g_szLogFilename[MAX_PATH] = { 0 };
static SRWLOCK  g_srwFileLock             = SRWLOCK_INIT;
static LONG     g_lFilenameReady          = 0x00;
static LONG     g_lFileCreated            = 0x00;
static HANDLE   g_hLogFile                = NULL;

// Derives "<exename>.log" from the running image path, runs once
static VOID DbgEnsureLogFilename(VOID)
{
    CHAR    szExePath[MAX_PATH]     = { 0 };
    LPSTR   pszExeName              = NULL,
            pszExtension            = NULL;
    
    if (InterlockedCompareExchange(&g_lFilenameReady, 1, 0) == 0)
    {
        GetModuleFileNameA(NULL, szExePath, MAX_PATH);
        
        pszExeName      = PathFindFileNameA(szExePath);
        pszExtension    = PathFindExtensionA(pszExeName);
        
        // Strip the .exe extension before appending .log
        if (pszExtension) *pszExtension = '\0';

        wsprintfA(g_szLogFilename, "%s.log", pszExeName);
    }
}

static VOID DbgSinkFile(LPCSTR pszBuffer)
{
    DWORD   dwAccess        = 0x00,
            dwCreationDisp  = 0x00,
            dwBytesWritten  = 0x00;

    AcquireSRWLockExclusive(&g_srwFileLock);

    // Open the file handle on first write
    if (g_hLogFile == NULL)
    {
        DbgEnsureLogFilename();

        // First open ever: truncates
        if (InterlockedCompareExchange(&g_lFileCreated, 1, 0) == 0)
        {
            dwAccess        = GENERIC_WRITE;
            dwCreationDisp  = CREATE_ALWAYS;
        }
        // Subsequent opens: append
        else
        {
            dwAccess        = FILE_APPEND_DATA;
            dwCreationDisp  = OPEN_ALWAYS;
        }

        if ((g_hLogFile = CreateFileA(g_szLogFilename, dwAccess, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, dwCreationDisp, 0, NULL)) == INVALID_HANDLE_VALUE)
            g_hLogFile = NULL;
    }

    if (g_hLogFile)
        WriteFile(g_hLogFile, pszBuffer, (DWORD)lstrlenA(pszBuffer), &dwBytesWritten, NULL);

    ReleaseSRWLockExclusive(&g_srwFileLock);
}


static VOID DbgCloseFile(VOID)
{
    AcquireSRWLockExclusive(&g_srwFileLock);

    if (g_hLogFile)
    {
        CloseHandle(g_hLogFile);
        g_hLogFile = NULL;
    }

    ReleaseSRWLockExclusive(&g_srwFileLock);
}

#endif // _DBG_USE_FILE

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                 CONSOLE SINK
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef _DBG_USE_CONSOLE

static HANDLE   g_hConsole          = INVALID_HANDLE_VALUE;
static LONG     g_lConReady         = 0x00;
static LONG     g_lConAllocated     = 0x00;

static VOID DbgEnsureConsole(VOID)
{
    HANDLE hConsole = NULL;

    if (InterlockedCompareExchange(&g_lConReady, 1, 0) == 0)
    {
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // No existing console
        if (hConsole == INVALID_HANDLE_VALUE || hConsole == NULL)
        {
            // Allocate one
            if (AllocConsole())
            {
                InterlockedExchange(&g_lConAllocated, 1);
                hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            }
        }

        InterlockedExchangePointer((PVOID volatile*)&g_hConsole, (hConsole && hConsole != INVALID_HANDLE_VALUE) ? hConsole : (PVOID)INVALID_HANDLE_VALUE);
    }
}

static VOID DbgSinkConsole(LPCSTR pszBuffer)
{
    HANDLE  hConsole        = NULL;
    DWORD   dwBytesWritten  = 0x00;

    DbgEnsureConsole();

    // Snapshot the handle in case DbgClose races with us
    hConsole = (HANDLE)InterlockedCompareExchangePointer((PVOID volatile*)&g_hConsole, NULL, NULL);

    if (hConsole != INVALID_HANDLE_VALUE && hConsole != NULL)
        WriteFile(hConsole, pszBuffer, (DWORD)lstrlenA(pszBuffer), &dwBytesWritten, NULL);
}

static VOID DbgCloseConsole(VOID)
{
    // Invalidate the handle before freeing so no thread writes to it after
    InterlockedExchangePointer((PVOID volatile*)&g_hConsole, (PVOID)INVALID_HANDLE_VALUE);

    if (InterlockedExchange(&g_lConAllocated, 0) == 1)
        FreeConsole();

    InterlockedExchange(&g_lConReady, 0);
}

#endif // _DBG_USE_CONSOLE

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                PUBLIC FUNCTIONS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

VOID DbgWrite(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...)
{
    DWORD       dwSavedError    = 0x00;
    INT         cchWritten      = 0x00;
    LPSTR       pszBuffer       = NULL;
    va_list     pszVaArgs       = NULL;

    // Capture the caller's last error before running our logic
    dwSavedError = GetLastError();

    if ((pszBuffer = DbgGetBuffer()) == NULL)
        goto _END_OF_FUNC;

    va_start(pszVaArgs, pszFmt);
    cchWritten = wvsprintfA(pszBuffer, pszFmt, pszVaArgs);
    va_end(pszVaArgs);

    if (cchWritten < 0)
        goto _END_OF_FUNC;

    // Append file and line tag if there's room
    if (cchWritten < BUFFER_SIZE_2048 - 1)
        wsprintfA(pszBuffer + cchWritten, "     [%s:%d]\n", pszFile, nLine);
    else
    {
        // Message was too long. Add '...\n\0'
        pszBuffer[BUFFER_SIZE_2048 - 5] = '.';
        pszBuffer[BUFFER_SIZE_2048 - 4] = '.';
        pszBuffer[BUFFER_SIZE_2048 - 3] = '.';
        pszBuffer[BUFFER_SIZE_2048 - 2] = '\n';
        pszBuffer[BUFFER_SIZE_2048 - 1] = '\0';
    }

#ifdef _DBG_USE_DEBUGSTR
    OutputDebugStringA(pszBuffer);
#endif
#ifdef _DBG_USE_FILE
    DbgSinkFile(pszBuffer);
#endif
#ifdef _DBG_USE_CONSOLE
    DbgSinkConsole(pszBuffer);
#endif

_END_OF_FUNC:
    // Restore caller's last error 
    SetLastError(dwSavedError);
}


VOID DbgClose(VOID)
{
    DWORD dwFlsSlot = FLS_OUT_OF_INDEXES;

    // Swap the slot index to FLS_OUT_OF_INDEXES 
    if ((dwFlsSlot = (DWORD)InterlockedExchange((LONG volatile*)&g_dwFlsIdx, (LONG)FLS_OUT_OF_INDEXES)) != FLS_OUT_OF_INDEXES)
        FlsFree(dwFlsSlot);

#ifdef _DBG_USE_FILE
    DbgCloseFile();
#endif
#ifdef _DBG_USE_CONSOLE
    DbgCloseConsole();
#endif
}