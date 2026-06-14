#pragma once

#define NOGDI
#define NOUSER
#include <windows.h>
#undef NOGDI
#undef NOUSER

#ifdef CopyMemory
#undef CopyMemory
#endif
#ifdef MoveMemory
#undef MoveMemory
#endif

extern "C" int __stdcall CopyRect(RECT* destination, const RECT* source);
extern "C" int __stdcall OffsetRect(RECT* rect, int dx, int dy);
