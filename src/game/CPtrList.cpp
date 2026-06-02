#include "game/CPtrList.h"

#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
int AllocateWithFallbackHandler(undefined4 size_bytes);

extern "C" {
char g_vtblCPtrList = 0;
}

// FUNCTION: IMPERIALISM 0x00601b74
void* __stdcall AllocateAndLinkBlockHead(void** blockChainPtr, int blockCount, int elementSize) {
  void* block = reinterpret_cast<void*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(blockCount * elementSize + 4)));
  *reinterpret_cast<void**>(block) = *blockChainPtr;
  *blockChainPtr = block;
  return block;
}

// FUNCTION: IMPERIALISM 0x00601b94
void __fastcall FreeLinkedBlockChain(void* blockChainHead) {
  while (blockChainHead != 0) {
    void* next = *reinterpret_cast<void**>(blockChainHead);
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(blockChainHead)));
    blockChainHead = next;
  }
}

// FUNCTION: IMPERIALISM 0x00601f1d
CPtrList::CPtrList(int blockSize) {
  this->nodeCount = 0;
  this->freeNodeList = 0;
  this->tailNode = 0;
  this->headNode = 0;
  this->blockChain = 0;
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(&g_vtblCPtrList);
  this->blockSize = blockSize;
}

// FUNCTION: IMPERIALISM 0x00601f7c
CPtrList::~CPtrList() {
  RemoveAll();
}

// FUNCTION: IMPERIALISM 0x00601f40
void* CPtrList::DestructCPtrListAndMaybeFree(byte freeSelfFlag) {
  this->CPtrList::~CPtrList();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// FUNCTION: IMPERIALISM 0x00601f5c
void CPtrList::RemoveAll() {
  void* chain = this->blockChain;
  this->nodeCount = 0;
  this->freeNodeList = 0;
  this->tailNode = 0;
  this->headNode = 0;
  FreeLinkedBlockChain(chain);
  this->blockChain = 0;
}

// FUNCTION: IMPERIALISM 0x00601faf
CPtrListNode* CPtrList::NewNode(CPtrListNode* pPrev, CPtrListNode* pNext) {
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
void CPtrList::FreeNode(CPtrListNode* pNode) {
  pNode->next = this->freeNodeList;
  this->nodeCount--;
  this->freeNodeList = pNode;
  if (this->nodeCount == 0) {
    this->RemoveAll();
  }
}

// FUNCTION: IMPERIALISM 0x0060201d
CPtrListNode* CPtrList::AddHead(void* value) {
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
CPtrListNode* CPtrList::AddTail(void* value) {
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

// FUNCTION: IMPERIALISM 0x006020b9
void* CPtrList::RemoveHead() {
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

// FUNCTION: IMPERIALISM 0x006020dd
void* CPtrList::RemoveTail() {
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
CPtrListNode* CPtrList::InsertBefore(CPtrListNode* position, void* value) {
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
CPtrListNode* CPtrList::InsertAfter(CPtrListNode* position, void* value) {
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

// FUNCTION: IMPERIALISM 0x0060217d
void CPtrList::RemoveAt(CPtrListNode* pos) {
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

// FUNCTION: IMPERIALISM 0x006021d6
CPtrListNode* CPtrList::Find(void* searchValue, CPtrListNode* startAfter) {
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
