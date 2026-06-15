#pragma once

#include "decomp_types.h"

// MFC CMapPtrToPtr (archive store map, CDC handle map, …).
struct CMapPtrToPtr {
  struct CAssoc {
    CAssoc* pNext;
    void* key;
    void* value;
  };

  void* m_unknown00;
  CAssoc** m_pHashTable;
  unsigned int m_nHashTableSize;
  int m_nCount;
  CAssoc* m_pFreeList;
  void* m_pBlocks;
  int m_nBlockSize;

  void InitHashTable(unsigned int nHashSize, int bAllocNow);
  CAssoc* GetAssocAt(void* key, unsigned int* pHashOut) const;
  CAssoc* NewAssoc();
  void FreeAssoc(CAssoc* p);
  void*& operator[](void* key);
  int RemoveKey(void* key);
  void RemoveAll();
};
