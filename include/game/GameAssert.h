#pragma once

#include <windows.h>

#if defined(__MINGW32__) || defined(__clang__)
struct HWND__;
typedef struct HWND__* GameAssertHWND;
#else
typedef void* GameAssertHWND;
#endif

extern "C" __declspec(dllimport) int __stdcall
MessageBoxA(GameAssertHWND hWnd, const char* lpText, const char* lpCaption, unsigned int uType);

#define GAME_FAIL_NIL_POINTER() MessageBoxA(NULL, "Nil Pointer", "Failure", 0x30)
