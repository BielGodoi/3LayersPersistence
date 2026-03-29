#include "Headers.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region STRING_MANIPLUATION

LPVOID ConvertString(IN LPVOID pvSrc, IN INT cbSrc, IN STRING_ENCODING Encoding)
{
    INT     cbNeeded    = 0x00;
    LPVOID  pvDst       = NULL;
    UINT    uCodePage   = 0x00;

    if (!pvSrc || cbSrc == 0) return NULL;

    switch (Encoding)
    {
        case ENCODING_ANSI_TO_WIDE:
        case ENCODING_UTF8_TO_WIDE:
        {
            uCodePage = (Encoding == ENCODING_UTF8_TO_WIDE) ? CP_UTF8 : CP_ACP;

            if ((cbNeeded = MultiByteToWideChar(uCodePage, 0, (LPCSTR)pvSrc, cbSrc, NULL, 0)) <= 0)
            {
                DBG_LAST_ERROR("MultiByteToWideChar");
                return NULL;
            }

            HEAP_ALLOC(pvDst, ((cbNeeded + 1) * sizeof(WCHAR)));
            if (!pvDst) return NULL;

            MultiByteToWideChar(uCodePage, 0, (LPCSTR)pvSrc, cbSrc, (LPWSTR)pvDst, cbNeeded);
            break;
        }

        case ENCODING_WIDE_TO_ANSI:
        case ENCODING_WIDE_TO_UTF8:
        {
            uCodePage = (Encoding == ENCODING_WIDE_TO_UTF8) ? CP_UTF8 : CP_ACP;

            if ((cbNeeded = WideCharToMultiByte(uCodePage, 0, (LPCWSTR)pvSrc, cbSrc, NULL, 0, NULL, NULL)) <= 0)
            {
                DBG_LAST_ERROR("WideCharToMultiByte");
                return NULL;
            }

            HEAP_ALLOC(pvDst, (cbNeeded + 1));
            if (!pvDst) return NULL;

            WideCharToMultiByte(uCodePage, 0, (LPCWSTR)pvSrc, cbSrc, (LPSTR)pvDst, cbNeeded, NULL, NULL);
            break;
        }

        case ENCODING_ANSI_TO_UTF8:
        {
            LPWSTR pwszIntermediate = (LPWSTR)ConvertString(pvSrc, cbSrc, ENCODING_ANSI_TO_WIDE);
            if (!pwszIntermediate) return NULL;

            pvDst = ConvertString(pwszIntermediate, (SIZE_T)lstrlenW(pwszIntermediate), ENCODING_WIDE_TO_UTF8);
            HEAP_FREE(pwszIntermediate);
            break;
        }

        case ENCODING_UTF8_TO_ANSI:
        {
            LPWSTR pwszIntermediate = (LPWSTR)ConvertString(pvSrc, cbSrc, ENCODING_UTF8_TO_WIDE);
            if (!pwszIntermediate) return NULL;

            pvDst = ConvertString(pwszIntermediate, (SIZE_T)lstrlenW(pwszIntermediate), ENCODING_WIDE_TO_ANSI);
            HEAP_FREE(pwszIntermediate);
            break;
        }

        default:
            return NULL;
    }

    return pvDst;
}

#pragma endregion 

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region FILE_IO

BOOL ReadFileFromDiskW(IN LPCWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
    HANDLE      hFile                   = INVALID_HANDLE_VALUE;
    DWORD       dwFileSize              = 0x00,
                dwNumberOfBytesRead     = 0x00;
    PBYTE       pBaseAddress            = NULL;
 
    if (!szFileName || !pdwFileSize || !ppFileBuffer)
        return FALSE;
 
    if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBG_LAST_ERROR("CreateFileW");
        goto _END_OF_FUNC;
    }
 
    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
    {
        DBG_LAST_ERROR("GetFileSize");
        goto _END_OF_FUNC;
    }
 
    HEAP_ALLOC(pBaseAddress, dwFileSize);
    if (!pBaseAddress) goto _END_OF_FUNC;
 
    if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead)
    {
        DBG_LAST_ERROR("ReadFile");
        DBG("[i] Read %d Of %d Bytes", dwNumberOfBytesRead, dwFileSize);
        goto _END_OF_FUNC;
    }
 
    *ppFileBuffer = pBaseAddress;
    *pdwFileSize  = dwFileSize;
 
_END_OF_FUNC:
    CLOSE_HANDLE(hFile);
    if (!*ppFileBuffer) { HEAP_FREE(pBaseAddress); }
    return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

BOOL WriteFileToDiskW(IN LPCWSTR pszFileName, IN CONST BYTE* pbDataBuffer, IN DWORD dwDataLength)
{
    HANDLE  hFile                   = INVALID_HANDLE_VALUE;
    DWORD   dwNumerOfBytesWritten   = 0x00;
    BOOL    bResult                 = FALSE;

    if (!pszFileName || !pbDataBuffer || dwDataLength == 0x00)
        return FALSE;

    if ((hFile = CreateFileW(pszFileName, GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBG_LAST_ERROR("CreateFileW");
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hFile, pbDataBuffer, dwDataLength, &dwNumerOfBytesWritten, NULL) || dwNumerOfBytesWritten != dwDataLength)
    {
        DBG_LAST_ERROR("WriteFile");
        DBG("[i] Wrote %d Of %d Bytes", dwNumerOfBytesWritten, dwDataLength);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    CLOSE_HANDLE(hFile);
    return bResult;
}

BOOL CloneFileTimestampsW(IN LPCWSTR pwszSrcPath, IN LPCWSTR pwszDstPath)
{
    HANDLE      hSrcFile    = INVALID_HANDLE_VALUE,
                hDstFile    = INVALID_HANDLE_VALUE;
    FILETIME    ftCreation   = { 0 },
                ftLastAccess = { 0 },
                ftLastWrite  = { 0 };
    BOOL        bResult     = FALSE;

    if (!pwszSrcPath || !pwszDstPath)
        return FALSE;

    if ((hSrcFile = CreateFileW(pwszSrcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBG_LAST_ERROR("CreateFileW");
        return FALSE;
    }

    if (!GetFileTime(hSrcFile, &ftCreation, &ftLastAccess, &ftLastWrite))
    {
        DBG_LAST_ERROR("GetFileTime");
        goto _END_OF_FUNC;
    }

    if ((hDstFile = CreateFileW(pwszDstPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBG_LAST_ERROR("CreateFileW");
        goto _END_OF_FUNC;
    }

    if (!SetFileTime(hDstFile, &ftCreation, &ftLastAccess, &ftLastWrite))
    {
        DBG_LAST_ERROR("SetFileTime");
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    CLOSE_HANDLE(hSrcFile);
    CLOSE_HANDLE(hDstFile);
    return bResult;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region REG_IO

BOOL SetRegistryStringW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN LPCWSTR pwszValue, IN BOOL bOverwrite)
{
    HKEY        hKey            = NULL;
    DWORD       dwDisposition   = 0x00;
    LSTATUS     lStatus         = ERROR_SUCCESS;
    BOOL        bResult         = FALSE;

    if ((lStatus = RegCreateKeyExW(hRoot, pwszPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition)) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegCreateKeyExW", lStatus);
        return FALSE;
    }

    if (dwDisposition == REG_OPENED_EXISTING_KEY && !bOverwrite)
    {
        DBG("[i] Registry Key Already Exists, Skipping");
        bResult = TRUE;
        goto _END_OF_FUNC;
    }

    if ((lStatus = RegSetValueExW(hKey, pwszName, 0, REG_SZ, (LPBYTE)pwszValue, (DWORD)((lstrlenW(pwszValue) + 1) * sizeof(WCHAR)))) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegSetValueExW", lStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    RegCloseKey(hKey);
    return bResult;
}

BOOL SetRegistryDwordW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, IN DWORD dwValue, IN BOOL bOverwrite)
{
    HKEY        hKey            = NULL;
    DWORD       dwDisposition   = 0x00;
    LSTATUS     lStatus         = ERROR_SUCCESS;
    BOOL        bResult         = FALSE;

    if ((lStatus = RegCreateKeyExW(hRoot, pwszPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition)) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegCreateKeyExW", lStatus);
        return FALSE;
    }

    if (dwDisposition == REG_OPENED_EXISTING_KEY && !bOverwrite)
    {
        DBG("[i] Registry Key Already Exists, Skipping");
        bResult = TRUE;
        goto _END_OF_FUNC;
    }

    if ((lStatus = RegSetValueExW(hKey, pwszName, 0, REG_DWORD, (LPBYTE)&dwValue, sizeof(DWORD))) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegSetValueExW", lStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    RegCloseKey(hKey);
    return bResult;
}

BOOL GetRegistryDwordW(IN HKEY hRoot, IN LPCWSTR pwszPath, IN LPCWSTR pwszName, OUT PDWORD pdwOutput)
{
    HKEY        hKey            = NULL;
    DWORD       dwType          = REG_DWORD,
                dwDataLength    = sizeof(DWORD);
    LSTATUS     lStatus         = ERROR_SUCCESS;
    BOOL        bResult         = FALSE;

    if ((lStatus = RegOpenKeyExW(hRoot, pwszPath, 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegOpenKeyExW", lStatus);
        return FALSE;
    }

    if ((lStatus = RegQueryValueExW(hKey, pwszName, NULL, &dwType, (LPBYTE)pdwOutput, &dwDataLength)) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegQueryValueExW", lStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    RegCloseKey(hKey);
    return bResult;
}

BOOL DeleteRegistryKeyW(IN HKEY hRoot, IN LPCWSTR pwszPath)
{
    LSTATUS lStatus = ERROR_SUCCESS;

    if ((lStatus = RegDeleteTreeW(hRoot, pwszPath)) != ERROR_SUCCESS)
    {
        DBG_HEX_ERROR("RegDeleteTreeW", lStatus);
        return FALSE;
    }

    return TRUE;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region FILE_SYSTEM

// Builds the full path to a file in the System32 directory.
BOOL GetSystem32PathW(IN LPCWSTR pwszFileName, OUT LPWSTR pwszOutPath, IN DWORD dwOutSize)
{
    WCHAR   wszSystem32Path[MAX_PATH]   = { 0 };

    if (!pwszFileName || !pwszOutPath || !dwOutSize)
        return FALSE;

    if (!GetSystemDirectoryW(wszSystem32Path, ARRAYSIZE(wszSystem32Path)))
    {
        DBG_LAST_ERROR("GetSystemDirectoryW");
        return FALSE;
    }

    if (wsprintfW(pwszOutPath, L"%s\\%s", wszSystem32Path, pwszFileName) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    return TRUE;
}


// Extracts the directory component from a full file path, or uses the path as-is 
// if it is already a directory (when bIsFilePath is false), and creates the directory if it doesn't exist
BOOL EnsureDirectoryExistsW(IN LPCWSTR pwszPath, IN BOOL bIsFilePath)
{
    WCHAR   wszDirPath[MAX_PATH]    = { 0 };
    HRESULT hResult                 = S_OK;

    if (!pwszPath) return FALSE;

    if (FAILED((hResult = StringCchCopyW(wszDirPath, ARRAYSIZE(wszDirPath), pwszPath))))
    {
        DBG_HEX_ERROR("StringCchCopyW", hResult);
        return FALSE;
    }

    if (bIsFilePath) PathRemoveFileSpecW(wszDirPath);

    if (!CreateDirectoryW(wszDirPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        DBG_LAST_ERROR("CreateDirectoryW");
        return FALSE;
    }

    return TRUE;
}


/*
 * Copies a file to a destination directory, while creating the directory if it doesn't exist. 
 * It calls both EnsureDirectoryExistsW and GetSystem32PathW depending on the parameters:
 *
 *   pwszDestPath      [IN]           - Destination directory path. Supports environment variables, this is created if doesnt exist.
 *   pwszDestName      [IN/OPTIONAL]  - Destination file name. If NULL, the source file name is used.
 *   pwszSrcPath       [IN/OPTIONAL]  - Source directory path. If NULL, System32 is used as the source directory.
 *   pwszSrcName       [IN]           - Source file name.
 *   pwszOutFullPath   [OUT/OPTIONAL] - Output parameter that receives the full destination path of the copied file. If NULL, ignored.
 *   dwOutFullPathSize [IN/OPTIONAL]  - Output parameter that receives the size of the outputted pwszOutFullPath buffer in characters. 
*/

BOOL CopyFileToDirW(IN LPCWSTR pwszDestPath, IN OPTIONAL LPCWSTR pwszDestName, IN OPTIONAL LPCWSTR pwszSrcPath, IN LPCWSTR pwszSrcName, OUT OPTIONAL LPWSTR pwszOutFullPath, IN OPTIONAL DWORD dwOutFullPathSize)
{
    WCHAR       wszExpandedDestPath[MAX_PATH]   = { 0 };
    WCHAR       wszFullSrcPath[MAX_PATH]        = { 0 };
    WCHAR       wszFullDestPath[MAX_PATH]       = { 0 };
    HRESULT     hResult                         = S_OK;
    LPCWSTR     pwszFinalDestName               = NULL;

    if (!pwszDestPath || !pwszSrcName) return FALSE;
    if (pwszOutFullPath && !dwOutFullPathSize) return FALSE;

    // Expand environment variables in the destination path if any
    if (!ExpandEnvironmentStringsW(pwszDestPath, wszExpandedDestPath, ARRAYSIZE(wszExpandedDestPath)))
    {
        DBG_LAST_ERROR("ExpandEnvironmentStringsW");
        return FALSE;
    }

    // Create the destination directory if it doesn't exist
    if (!EnsureDirectoryExistsW(wszExpandedDestPath, FALSE))
        return FALSE;

    // If no source path provided, copy from System32
    if (pwszSrcPath == NULL)
    {
        if (!GetSystem32PathW(pwszSrcName, wszFullSrcPath, ARRAYSIZE(wszFullSrcPath)))
            return FALSE;
    }
    else
    {
        if (wsprintfW(wszFullSrcPath, L"%s\\%s", pwszSrcPath, pwszSrcName) < 0)
        {
            DBG_LAST_ERROR("wsprintfW");
            return FALSE;
        }
    }

    // If no destination name provided, use the source name
    pwszFinalDestName = (pwszDestName != NULL) ? pwszDestName : pwszSrcName;

    // Build the full destination path
    if (wsprintfW(wszFullDestPath, L"%s\\%s", wszExpandedDestPath, pwszFinalDestName) < 0)
    {
        DBG_LAST_ERROR("wsprintfW");
        return FALSE;
    }

    // Copy the file, fail if destination already exists
    if (!CopyFileW(wszFullSrcPath, wszFullDestPath, TRUE))
    {
        DBG_LAST_ERROR("CopyFileW");
        return FALSE;
    }

    // If the caller provided an output buffer, fill it with the full destination path
    if (pwszOutFullPath != NULL)
    {
        if (FAILED((hResult = StringCchCopyW(pwszOutFullPath, dwOutFullPathSize, wszFullDestPath))))
        {
            DBG_HEX_ERROR("StringCchCopyW", hResult);
            return FALSE;
        }
    }

    return TRUE;
}


#pragma endregion
