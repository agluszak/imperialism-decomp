#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CObject.h"

// MFC CPtrList CNode (m_pNext, m_pPrev, data) — 12 bytes.
struct CPtrListNode {
  CPtrListNode* next;
  CPtrListNode* prev;
  void* data;
};

// Standalone block-chain helpers (MFC CPlex::Create / FreeDataChain).
void* __stdcall AllocateAndLinkBlockHead(void** blockChainPtr, int blockCount, int elementSize);
void __fastcall FreeLinkedBlockChain(void* blockChainHead);

// VTABLE: IMPERIALISM 0x00672eec
class CPtrList : public CObject {
public:
  CPtrListNode* headNode;
  CPtrListNode* tailNode;
  int nodeCount;
  CPtrListNode* freeNodeList;
  void* blockChain;
  int blockSize;

  CPtrList(int blockSize = 10);
  virtual ~CPtrList();

  void RemoveAll();
  CPtrListNode* NewNode(CPtrListNode* prev, CPtrListNode* next);
  void FreeNode(CPtrListNode* node);
  CPtrListNode* AddHead(void* value);
  CPtrListNode* AddTail(void* value);
  void* RemoveHead();
  void* RemoveTail();
  CPtrListNode* InsertBefore(CPtrListNode* position, void* value);
  CPtrListNode* InsertAfter(CPtrListNode* position, void* value);
  void RemoveAt(CPtrListNode* position);
  CPtrListNode* Find(void* value, CPtrListNode* startAfter = 0);
  CPtrListNode* GetNodeAtZeroBasedIndex(int zeroBasedIndex);
  void* GetDataAtOneBasedIndex(int oneBasedIndex);
};

ASSERT_SIZE(CPtrList, 0x1c);
