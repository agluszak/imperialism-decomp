#include <string.h>
#include "game/CMapPtrToPtr.h"

// MFC collection code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
int AllocateWithFallbackHandler(undefined4 size_bytes);
void* __stdcall AllocateAndLinkBlockHead(void** blockChainPtr, int blockCount, int elementSize);
void __fastcall FreeLinkedBlockChain(void* blockChainHead);

// LIBRARY: IMPERIALISM 0x006033dd
// CMapPtrToPtr::InitHashTable

// LIBRARY: IMPERIALISM 0x00603423
// CMapPtrToPtr::RemoveAll

// FUNCTION: IMPERIALISM 0x00603481
CMapPtrToPtr::CAssoc* CMapPtrToPtr::NewAssoc() {
  if (m_pFreeList == 0) {
    void* block = AllocateAndLinkBlockHead(&m_pBlocks, m_nBlockSize, sizeof(CAssoc));
    CAssoc* p = reinterpret_cast<CAssoc*>(reinterpret_cast<char*>(block) + 4) + (m_nBlockSize - 1);
    for (int i = m_nBlockSize - 1; i >= 0; --i) {
      p->pNext = m_pFreeList;
      m_pFreeList = p;
      --p;
    }
  }
  CAssoc* result = m_pFreeList;
  CAssoc* next = result->pNext;
  ++m_nCount;
  m_pFreeList = next;
  result->key = 0;
  result->value = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x006034cb
void CMapPtrToPtr::FreeAssoc(CAssoc* p) {
  p->pNext = m_pFreeList;
  m_pFreeList = p;
  --m_nCount;
  if (m_nCount == 0) {
    RemoveAll();
  }
}

// FUNCTION: IMPERIALISM 0x006034e4
CMapPtrToPtr::CAssoc* CMapPtrToPtr::GetAssocAt(void* key, unsigned int* pHashOut) {
  unsigned int hash = (reinterpret_cast<unsigned int>(key) >> 4) % m_nHashTableSize;
  *pHashOut = hash;
  if (m_pHashTable != 0) {
    for (CAssoc* p = m_pHashTable[hash]; p != 0; p = p->pNext) {
      if (p->key == key) {
        return p;
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0060356b
void** CMapPtrToPtr::GetOrCreateValueSlot(void* key) {
  unsigned int hash;
  CAssoc* p = GetAssocAt(key, &hash);
  if (p == 0) {
    if (m_pHashTable == 0) {
      InitHashTable(m_nHashTableSize, 1);
    }
    p = NewAssoc();
    p->key = key;
    p->pNext = m_pHashTable[hash];
    m_pHashTable[hash] = p;
  }
  return &p->value;
}

// LIBRARY: IMPERIALISM 0x006035bb
// CMapPtrToPtr::RemoveKey
