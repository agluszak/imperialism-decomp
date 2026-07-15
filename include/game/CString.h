#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

extern "C" int __cdecl _mbscmp(const unsigned char* lhs, const unsigned char* rhs);

CString __stdcall operator+(const CString& string1, const CString& string2);
CString __stdcall operator+(const CString& string1, const char* lpsz);
CString __stdcall operator+(const char* lpsz, const CString& string2);
