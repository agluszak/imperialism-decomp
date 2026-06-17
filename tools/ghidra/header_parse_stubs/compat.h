#ifndef COMPAT_H
#define COMPAT_H

/* Minimal compat.h for header parsing (pcpp cannot handle MSVC #pragma warning). */

#if __cplusplus < 201103L
#define override
#define nullptr 0
#endif

#endif
