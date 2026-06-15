#include "game/CString.h"

#include <string.h>

extern "C" unsigned char g_MbcsCharTypeTable_006A8018[512] = {0};
extern "C" int g_fMbcsEnabledForStringCompare_006A811C = 0;

undefined4 EnterIndexedCriticalSectionWithLazyInit(void);
undefined4 LeaveIndexedCriticalSection(void);

// FUNCTION: IMPERIALISM 0x005e7980
int CompareAnsiStringsWithMbcsAwareness(unsigned char* lhs, unsigned char* rhs) {
  if (g_fMbcsEnabledForStringCompare_006A811C != 0) {
    reinterpret_cast<void(__cdecl*)(int)>(EnterIndexedCriticalSectionWithLazyInit)(0x19);
    while (1) {
      unsigned short lhsUnit = (unsigned short)*lhs;
      unsigned char* lhsNext = lhs + 1;
      if ((g_MbcsCharTypeTable_006A8018[lhsUnit + 1] & 4) != 0) {
        unsigned char trailByte = *lhsNext;
        if (trailByte == 0) {
          lhsUnit = 0;
        } else {
          lhsNext = lhs + 2;
          lhsUnit = (unsigned short)(((unsigned short)*lhs << 8) | (unsigned short)trailByte);
        }
      }
      unsigned short rhsUnit = (unsigned short)*rhs;
      unsigned char* rhsNext = rhs + 1;
      if ((g_MbcsCharTypeTable_006A8018[rhsUnit + 1] & 4) != 0) {
        unsigned char trailByte = *rhsNext;
        if (trailByte == 0) {
          rhsUnit = 0;
        } else {
          rhsNext = rhs + 2;
          rhsUnit = (unsigned short)(((unsigned short)*rhs << 8) | (unsigned short)trailByte);
        }
      }
      if (lhsUnit != rhsUnit) {
        reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(0x19);
        return (int)((-(unsigned int)(rhsUnit < lhsUnit) & 2) - 1);
      }
      rhs = rhsNext;
      lhs = lhsNext;
      if (lhsUnit == 0) {
        reinterpret_cast<void(__cdecl*)(int)>(LeaveIndexedCriticalSection)(0x19);
        return 0;
      }
    }
  }

  while (1) {
    unsigned char lhsByte = *lhs;
    int lhsLess = (int)(lhsByte < *rhs);
    if (lhsByte != *rhs) {
      return (1 - (unsigned int)lhsLess) - (unsigned int)(lhsLess != 0);
    }
    if (lhsByte == 0) {
      return 0;
    }
    lhsByte = lhs[1];
    lhsLess = (int)(lhsByte < rhs[1]);
    if (lhsByte != rhs[1]) {
      return (1 - (unsigned int)lhsLess) - (unsigned int)(lhsLess != 0);
    }
    lhs = lhs + 2;
    rhs = rhs + 2;
    if (lhsByte == 0) {
      return 0;
    }
  }
}

// LIBRARY: IMPERIALISM 0x0049eb00
// AssignStringSharedRefAndReturnThis

// LIBRARY: IMPERIALISM 0x00605791
// GetSharedEmptyStringRef

// LIBRARY: IMPERIALISM 0x00605797
// CString::CString

// LIBRARY: IMPERIALISM 0x006057a7
// CString::StringSharedRef_AssignFromPtr

// LIBRARY: IMPERIALISM 0x006057de
// CString::AllocBuffer

// LIBRARY: IMPERIALISM 0x0060584a
// DecrementSharedStringRefCountAndFree

// LIBRARY: IMPERIALISM 0x0060586d
// CString::Empty

// LIBRARY: IMPERIALISM 0x0060588b
// CString::CopyBeforeWrite

// LIBRARY: IMPERIALISM 0x006058b9
// CString::AllocBeforeWrite

// LIBRARY: IMPERIALISM 0x006058e2
// CString::~CString

// LIBRARY: IMPERIALISM 0x00605950
// CString::CString

// LIBRARY: IMPERIALISM 0x006059fc
// CString::AssignCopy

// LIBRARY: IMPERIALISM 0x00605a29
// CString::operator=

// LIBRARY: IMPERIALISM 0x00605a78
// CString::operator=

// LIBRARY: IMPERIALISM 0x00605ae0
// CString::ConcatCopy

// LIBRARY: IMPERIALISM 0x00605b21
// AssignSharedStringConcatRefAndRef

// LIBRARY: IMPERIALISM 0x00605b87
// AssignSharedStringConcatRefAndCStr

// LIBRARY: IMPERIALISM 0x00605bfb
// AssignSharedStringConcatCStrAndRef

// LIBRARY: IMPERIALISM 0x00605c6f
// CString::ConcatInPlace

// LIBRARY: IMPERIALISM 0x00605cce
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605cf5
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605d0a
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605d22
// CString::GetBuffer

// LIBRARY: IMPERIALISM 0x00605d71
// CString::ReleaseBuffer

// LIBRARY: IMPERIALISM 0x00605d99
// CString::GetBufferSetLength

// LIBRARY: IMPERIALISM 0x00605dec
// CString::LockBuffer
