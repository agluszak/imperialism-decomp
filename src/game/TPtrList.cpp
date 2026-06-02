#include "game/TPtrList.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

extern "C" {
char g_pClassDescTPtrList = 0;
}

undefined4 DestructCPtrListBaseState(void);
void FreeHeapBufferIfNotNull(undefined4 ptrValue);
int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" {
char g_vtblCPtrList = 0;
}

// FUNCTION: IMPERIALISM 0x00601B74
void* __stdcall AllocateAndLinkBlockHead(void** blockChainPtr, int blockCount, int elementSize) {
  void* block = reinterpret_cast<void*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(blockCount * elementSize + 4)));
  *reinterpret_cast<void**>(block) = *blockChainPtr;
  *blockChainPtr = block;
  return block;
}

// FUNCTION: IMPERIALISM 0x00601B94
void __fastcall FreeLinkedBlockChain(void* blockChainHead) {
  while (blockChainHead != 0) {
    void* next = *reinterpret_cast<void**>(blockChainHead);
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(blockChainHead)));
    blockChainHead = next;
  }
}

// FUNCTION: IMPERIALISM 0x00601F1D
CPtrListSentinelView* CPtrListSentinelView::CPtrList(int ownerContext) {
  this->nodeCount = 0;
  this->freeNodeList = 0;
  this->tailNode = 0;
  this->headNode = 0;
  this->blockChain = 0;
  this->vftable = reinterpret_cast<void*>(&g_vtblCPtrList);
  this->blockSize = ownerContext;
  return this;
}

// FUNCTION: IMPERIALISM 0x00601F40
void* CPtrListSentinelView::DestructCPtrListAndMaybeFree(byte freeSelfFlag) {
  reinterpret_cast<void(__fastcall*)(void*)>(::DestructCPtrListBaseState)(this);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// The outer TPtrList wrappers match best under the build's default favor-speed
// optimization; the embedded CPtrList list engine below matches under favor-size.
#if defined(_MSC_VER)
#pragma optimize("yt", on)
#endif

// FUNCTION: IMPERIALISM 0x00488510
void* TPtrList::GetTPtrListClassNamePointer() {
  return &g_pClassDescTPtrList;
}

// FUNCTION: IMPERIALISM 0x004885D0
void TPtrList::ConstructTPtrListBaseState(int ownerContext) {
  this->listState.CPtrList(ownerContext);
}

// FUNCTION: IMPERIALISM 0x004885F0
void* TPtrList::DestructTPtrListAndMaybeFree(byte freeSelfFlag, int, int) {
  return this->listState.DestructCPtrListAndMaybeFree(freeSelfFlag);
}

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// FUNCTION: IMPERIALISM 0x00601F5C
void CPtrListSentinelView::RemoveAll() {
  void* chain = this->blockChain;
  this->nodeCount = 0;
  this->freeNodeList = 0;
  this->tailNode = 0;
  this->headNode = 0;
  FreeLinkedBlockChain(chain);
  this->blockChain = 0;
}

// FUNCTION: IMPERIALISM 0x00601FAF
CPtrListNode* CPtrListSentinelView::NewNode(CPtrListNode* pPrev, CPtrListNode* pNext) {
  if (this->freeNodeList == 0) {
    void* plex = AllocateAndLinkBlockHead(&this->blockChain, this->blockSize, sizeof(CPtrListNode));
    CPtrListNode* blockNode =
        reinterpret_cast<CPtrListNode*>(reinterpret_cast<char*>(plex) + 4) + (this->blockSize - 1);
    for (int i = this->blockSize - 1; i >= 0; i--, blockNode--) {
      blockNode->next = this->freeNodeList;
      this->freeNodeList = blockNode;
    }
  }
  CPtrListNode* node = this->freeNodeList;
  this->freeNodeList = node->next;
  node->prev = pPrev;
  node->next = pNext;
  this->nodeCount++;
  node->data = 0;
  return node;
}

// FUNCTION: IMPERIALISM 0x00602004
void CPtrListSentinelView::FreeNode(CPtrListNode* pNode) {
  pNode->next = this->freeNodeList;
  this->nodeCount--;
  this->freeNodeList = pNode;
  if (this->nodeCount == 0) {
    this->RemoveAll();
  }
}

// FUNCTION: IMPERIALISM 0x0060201D
CPtrListNode* CPtrListSentinelView::AddHead(void* value) {
  CPtrListNode* node = this->NewNode(0, this->headNode);
  node->data = value;
  if (this->headNode != 0) {
    this->headNode->prev = node;
  } else {
    this->tailNode = node;
  }
  this->headNode = node;
  return node;
}

// FUNCTION: IMPERIALISM 0x00602047
CPtrListNode* CPtrListSentinelView::AddTail(void* value) {
  CPtrListNode* node = this->NewNode(this->tailNode, 0);
  node->data = value;
  if (this->tailNode != 0) {
    this->tailNode->next = node;
  } else {
    this->headNode = node;
  }
  this->tailNode = node;
  return node;
}

// FUNCTION: IMPERIALISM 0x006020B9
void* CPtrListSentinelView::RemoveHead() {
  CPtrListNode* oldHead = this->headNode;
  CPtrListNode* newHead = oldHead->next;
  void* payload = oldHead->data;
  this->headNode = newHead;
  if (newHead != 0) {
    newHead->prev = 0;
  } else {
    this->tailNode = 0;
  }
  this->FreeNode(oldHead);
  return payload;
}

// FUNCTION: IMPERIALISM 0x006020DD
void* CPtrListSentinelView::RemoveTailNodeAndReturnPayload() {
  CPtrListNode* oldTail = this->tailNode;
  CPtrListNode* newTail = oldTail->prev;
  void* payload = oldTail->data;
  this->tailNode = newTail;
  if (newTail != 0) {
    newTail->next = 0;
  } else {
    this->headNode = 0;
  }
  this->FreeNode(oldTail);
  return payload;
}

// FUNCTION: IMPERIALISM 0x00602101
CPtrListNode* CPtrListSentinelView::InsertNodeBeforeAndSetPayload(CPtrListNode* position,
                                                                  void* value) {
  if (position == 0) {
    return this->AddHead(value);
  }
  CPtrListNode* node = this->NewNode(position->prev, position);
  node->data = value;
  if (position->prev != 0) {
    position->prev->next = node;
  } else {
    this->headNode = node;
  }
  position->prev = node;
  return node;
}

// FUNCTION: IMPERIALISM 0x00602140
CPtrListNode* CPtrListSentinelView::InsertNodeAfterAndSetPayload(CPtrListNode* position,
                                                                 void* value) {
  if (position == 0) {
    return this->AddTail(value);
  }
  CPtrListNode* node = this->NewNode(position, position->next);
  node->data = value;
  if (position->next != 0) {
    position->next->prev = node;
  } else {
    this->tailNode = node;
  }
  position->next = node;
  return node;
}

// FUNCTION: IMPERIALISM 0x0060217D
void CPtrListSentinelView::RemoveAt_60217d(CPtrListNode* pos) {
  if (pos == this->headNode) {
    this->headNode = pos->next;
  } else {
    pos->prev->next = pos->next;
  }
  if (pos == this->tailNode) {
    this->tailNode = pos->prev;
  } else {
    pos->next->prev = pos->prev;
  }
  this->FreeNode(pos);
}

// FUNCTION: IMPERIALISM 0x006021D6
CPtrListNode* CPtrListSentinelView::Find(void* searchValue, CPtrListNode* startAfter) {
  CPtrListNode* node;
  if (startAfter == 0) {
    node = this->headNode;
  } else {
    node = startAfter->next;
  }
  while (node != 0) {
    if (node->data == searchValue) {
      return node;
    }
    node = node->next;
  }
  return 0;
}
