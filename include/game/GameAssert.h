#pragma once

extern "C" __declspec(dllimport) int __stdcall MessageBoxA(void* hWnd, const char* lpText, const char* lpCaption, unsigned int uType);

#define GAME_FAIL_NIL_POINTER() MessageBoxA(0, "Nil Pointer", "Failure", 0x30)
