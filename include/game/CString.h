#pragma once

#include <mbstring.h>

#include "decomp_types.h"
#include "game/mfc.h"

CString __stdcall operator+(const CString& string1, const CString& string2);
CString __stdcall operator+(const CString& string1, const char* lpsz);
CString __stdcall operator+(const char* lpsz, const CString& string2);

void __stdcall FormatFloatToLocalizedSharedString(float value, CString* outResult);
