#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

// Game-owned CString helpers not exported from nafxcw.lib.
undefined** GetSharedEmptyStringRef(void);
void __stdcall DecrementSharedStringRefCountAndFree(long* ref_count_ptr);
CString* __stdcall AssignSharedStringConcatRefAndRef(CString* dst, const CString* lhs,
                                                     const CString* rhs);
CString* __stdcall AssignSharedStringConcatRefAndCStr(CString* dst, const CString* lhs,
                                                      const char* rhs_text);
CString* __stdcall AssignSharedStringConcatCStrAndRef(CString* dst, const char* lhs_text,
                                                      const CString* rhs);
CString* AssignStringSharedRefAndReturnThis(CString* dest, const CString* src);

int CompareAnsiStringsWithMbcsAwareness(unsigned char* lhs, unsigned char* rhs);

CString __stdcall operator+(const CString& string1, const CString& string2);
CString __stdcall operator+(const CString& string1, const char* lpsz);
CString __stdcall operator+(const char* lpsz, const CString& string2);
