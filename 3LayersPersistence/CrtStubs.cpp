// If compiled in "Stripped" mode
#if !defined(_DEBUG) && !defined(NDEBUG)

#include <Windows.h>

#pragma function(memset)
void* memset(void* dst, int val, size_t size)
{
    unsigned char* p = (unsigned char*)dst;
    while (size--)
        *p++ = (unsigned char)val;
    return dst;
}

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t size)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (size--)
        *d++ = *s++;
    return dst;
}


#endif
