#pragma once

#include "decomp_types.h"

#include <windows.h>

// MFC CStringData header immediately before the character buffer (layout at +0x0c).
struct CStringData {
  long nRefs;
  int nDataLength;
  int nAllocLength;
};

// Legacy alias used by TFileStream and other layout-sensitive callers.
typedef CStringData SharedStringHeader;

class CString;

// Global helpers (stdcall where noted in the original).
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

class CString {
public:
  int data_ptr; // m_pchData

  CString();
  CString(const CString& stringSrc);
  CString(const char* lpsz);
  ~CString();

  BOOL LoadString(UINT nIDResource);

  void AllocBuffer(int nLen);
  void AllocBeforeWrite(int nLen);
  void AssignCopy(int nSrcLen, const char* lpszSrcData);
  void ConcatCopy(int nSrcLen1, const char* lpszSrcData1, int nSrcLen2, const char* lpszSrcData2);
  void ConcatInPlace(int nSrcLen, const char* lpszSrcData);
  void CopyBeforeWrite();
  void Empty();
  char* GetBuffer(int nMinBufLength);
  char* GetBufferSetLength(int nNewLength);
  char* LockBuffer();
  void ReleaseBuffer(int nNewLength = -1);

  const CString& operator=(const CString& stringSrc);
  const CString& operator=(const char* lpsz);
  const CString& operator+=(const CString& string);
  const CString& operator+=(const char* lpsz);
  const CString& operator+=(char ch);

  // Internal helper used by operator+ / EH return-slot assignment paths.
  const CString& StringSharedRef_AssignFromPtr(const CString& src_ref);

  operator const char*() const { return reinterpret_cast<const char*>(data_ptr); }
  const char* Text() const { return *this; }
  int Length() const { return GetData()->nDataLength; }
  int Capacity() const { return GetData()->nAllocLength; }

  CStringData* GetData() { return reinterpret_cast<CStringData*>(data_ptr - sizeof(CStringData)); }
  const CStringData* GetData() const {
    return reinterpret_cast<const CStringData*>(data_ptr - sizeof(CStringData));
  }
};

// MFC stdcall operator+ overloads (hidden return slot is the destination CString).
CString __stdcall operator+(const CString& string1, const CString& string2);
CString __stdcall operator+(const CString& string1, const char* lpsz);
CString __stdcall operator+(const char* lpsz, const CString& string2);
