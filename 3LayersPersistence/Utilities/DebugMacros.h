// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Define Any Combination At The *Project Level* (compiler flags / project settings) Before Building:
//
//   _DBG_USE_DEBUGSTR          -> DbgView
//   _DBG_USE_FILE              -> File
//   _DBG_USE_CONSOLE           -> Console (Default)
//
// *In Release Mode*, None Of These Will Work Unless This Is Also Defined At The Project Level:
//
//   _DBG_FORCE
//
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#pragma once
#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H

#include <Windows.h>
#include <Strsafe.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                  HELPERS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifndef BUFFER_SIZE_2048
#define BUFFER_SIZE_2048        2048
#endif

#ifndef GET_FILENAMEA
#define GET_FILENAMEA(PATHA)   PathFindFileNameA(PATHA)
#endif

#ifndef GET_FILENAMEW
#define GET_FILENAMEW(PATHW)   PathFindFileNameW(PATHW)
#endif

#if !defined(_DBG_USE_DEBUGSTR) && !defined(_DBG_USE_FILE) && !defined(_DBG_USE_CONSOLE)
#define _DBG_USE_CONSOLE
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                          INTERNAL FUNCTION DECLARATIONS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    VOID DbgWrite(LPCSTR pszFile, INT nLine, LPCSTR pszFmt, ...);
    VOID DbgClose(VOID);

#ifdef __cplusplus
}
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                                DBG & DBG_CLOSE
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define DBG_CLOSE()         DbgClose()

#if defined(_DEBUG) || defined(_DBG_FORCE)
#define DBG(fmt, ...)       DbgWrite(GET_FILENAMEA(__FILE__), __LINE__, fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)       ((void)0)
#endif

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//                                          DBG_LAST_ERROR & DBG_HEX_ERROR
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#if defined(_DEBUG) || defined(_DBG_FORCE)

#define DBG_LAST_ERROR(APINAME)                                         \
        do {                                                            \
            DWORD _dwLastErr = GetLastError();                          \
            DBG("[!] %s Failed With Error: %lu", APINAME, _dwLastErr);  \
            SetLastError(_dwLastErr);                                   \
        } while (0)
#define DBG_HEX_ERROR(APINAME, HEXCODE)    DBG("[!] %s Failed With Error: 0x%0.8X", APINAME, HEXCODE)

#else

#define DBG_LAST_ERROR(APINAME)          ((void)0)
#define DBG_HEX_ERROR(APINAME, ERROR)    ((void)0)

#endif

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


#endif // !DEBUG_MACROS_H