#pragma once

#include "decomp_types.h"
#include "game/RefCountedObjectBase.h"
#include "game/cobject.h"

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
class CPtrListSentinelView : public CObject {
 public:
  CPtrListNode* headNode;
  CPtrListNode* tailNode;
  int nodeCount;
  CPtrListNode* freeNodeList;
  void* blockChain;
  int blockSize;

  CPtrListSentinelView* CPtrList(int ownerContext);
  void* DestructCPtrListAndMaybeFree(byte freeSelfFlag);
  virtual ~CPtrListSentinelView();

  void RemoveAll();
  CPtrListNode* NewNode(CPtrListNode* pPrev, CPtrListNode* pNext);
  void FreeNode(CPtrListNode* pNode);
  CPtrListNode* AddHead(void* value);
  CPtrListNode* AddTail(void* value);
  void* RemoveHead();
  void* RemoveTailNodeAndReturnPayload();
  CPtrListNode* InsertNodeBeforeAndSetPayload(CPtrListNode* position, void* value);
  CPtrListNode* InsertNodeAfterAndSetPayload(CPtrListNode* position, void* value);
  void RemoveAt_60217d(CPtrListNode* pos);
  CPtrListNode* Find(void* searchValue, CPtrListNode* startAfter);
};

typedef char CPtrListSentinelViewSizeMustMatch[(sizeof(CPtrListSentinelView) == 0x1C) ? 1 : -1];

struct TPtrList : public RefCountedObjectBase {
  CPtrListSentinelView listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
  void* DestructTPtrListAndMaybeFree(byte freeSelfFlag, int unused1, int unused2);
};

typedef char TPtrListSizeMustMatch[(sizeof(TPtrList) == 0x20) ? 1 : -1];
