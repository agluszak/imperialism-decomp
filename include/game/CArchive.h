#pragma once

#include "decomp_types.h"

#include "game/CObject.h"

struct CRuntimeClass;
struct CMapPtrToPtr;

// MFC CArchive serialization buffer.
class CArchive {
public:
  char pad_00[0x08];
  int m_bDirect;
  char pad_0c[0x04];
  void* m_pExceptionContext;
  int m_nMode;
  char pad_18[0x04];
  int m_nBufSize;
  void* m_pFile;
  unsigned char* m_lpBufCur;
  unsigned char* m_lpBufMax;
  unsigned char* m_lpBufStart;
  unsigned int m_nMapCount;
  CMapPtrToPtr* m_pStoreMap;

  CArchive& operator<<(unsigned char value);
  CArchive& operator<<(unsigned short value);
  CArchive& operator<<(unsigned long value);
  CArchive& operator>>(unsigned short& value);
  CArchive& operator>>(unsigned long& value);

  unsigned int Read(void* lpBuf, unsigned int nMax);
  void Write(const void* lpBuf, unsigned int nMax);
  void FillBuffer(unsigned int nBytesRequired);

  void WriteCount(unsigned long count);
  void CheckCount();
  void WriteObject(const CObject* object);
  CObject* ReadObject(const CRuntimeClass* pClassRef);
  void MapObject(const CObject* objectRef);
  void WriteClass(const CRuntimeClass* pClassRef);
  void Close();
};
