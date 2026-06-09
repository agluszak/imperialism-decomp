#pragma once

#include "decomp_types.h"

// MFC CMapPtrToPtr: an open-hash map from a void* key to a void* value. Used as
// the CArchive object store/load map (CObject* -> serialized handle index).
// Association nodes are bump-allocated in blocks via AllocateAndLinkBlockHead
// (CPlex::Create) and recycled through a free list. The Ghidra autogen modeled
// these methods under the provisional "TNetMgr" class; they are the standard
// MFC collection primitives and belong here.
struct CMapPtrToPtr {
  struct CAssoc {
    CAssoc* pNext;
    void* key;
    void* value;
  };

  void* m_unknown00;             // +0x00 (not referenced by these methods)
  CAssoc** m_pHashTable;         // +0x04
  unsigned int m_nHashTableSize; // +0x08
  int m_nCount;                  // +0x0c
  CAssoc* m_pFreeList;           // +0x10
  void* m_pBlocks;               // +0x14 (CPlex chain head)
  int m_nBlockSize;              // +0x18

  // (0x006033dd) Free any existing bucket array and optionally allocate a fresh
  // zeroed one of nHashSize buckets.
  void InitHashTable(unsigned int nHashSize, int bAllocNow);

  // (0x006034e4) Find the association for key; writes the bucket index to
  // *pHashOut. Returns null if absent.
  CAssoc* GetAssocAt(void* key, unsigned int* pHashOut);

  // (0x00603481) Pop a zeroed association from the free list, growing it by one
  // block when empty.
  CAssoc* NewAssoc();

  // (0x0060356b) Return a pointer to the value slot for key, inserting a new
  // (zeroed) association when the key is not yet present.
  void** GetOrCreateValueSlot(void* key);

  // (0x006035bb) Remove hash-bucket entry by key and return the node to the free list.
  int RemoveKey(void* key);

  // (0x006034cb) Return an association node to the free list.
  void FreeAssoc(CAssoc* p);

  // (0x00603423) Release all associations and hash buckets when the map empties.
  void RemoveAll();
};
