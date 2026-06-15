#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CObject.h"

struct CRuntimeClass;

struct __POSITION {
  int unused;
};
typedef __POSITION* POSITION;

// MFC CPtrList::CNode — 12 bytes (pNext, pPrev, data).
struct CPtrListNode {
  CPtrListNode* next;
  CPtrListNode* prev;
  void* data;
};

inline CPtrListNode* NodeFromPosition(POSITION pos) {
  return reinterpret_cast<CPtrListNode*>(pos);
}

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
  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual ~CPtrList() override;

  void RemoveAll();
  POSITION AddHead(void* newElement);
  POSITION AddTail(void* newElement);
  void* RemoveHead();
  void* RemoveTail();
  POSITION InsertBefore(POSITION position, void* newElement);
  POSITION InsertAfter(POSITION position, void* newElement);
  void RemoveAt(POSITION position);
  POSITION Find(void* searchValue, POSITION startAfter = 0) const;
  POSITION FindIndex(int zeroBasedIndex) const;

  void* GetDataAtOneBasedIndex(int oneBasedIndex) const {
    POSITION pos = FindIndex(oneBasedIndex - 1);
    return pos != 0 ? NodeFromPosition(pos)->data : 0;
  }
};

ASSERT_SIZE(CPtrList, 0x1c);
