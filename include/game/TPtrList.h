#pragma once

#include "decomp_types.h"
#include "game/RefCountedObjectBase.h"

struct CPtrListSentinelView {
  void* vftable;
  void* headNode;
  void* tailNode;
  int nodeCount;
  void* freeNodeList;
  void* blockChain;
  int blockSize;

  CPtrListSentinelView* CPtrList(int ownerContext);
  void* DestructCPtrListAndMaybeFree(byte freeSelfFlag);
};

typedef char CPtrListSentinelViewSizeMustMatch[(sizeof(CPtrListSentinelView) == 0x1C) ? 1 : -1];

struct TPtrList : public RefCountedObjectBase {
  CPtrListSentinelView listState;

  static void* GetTPtrListClassNamePointer();
  void ConstructTPtrListBaseState(int ownerContext);
  void* DestructTPtrListAndMaybeFree(byte freeSelfFlag, int unused1, int unused2);
};

typedef char TPtrListSizeMustMatch[(sizeof(TPtrList) == 0x20) ? 1 : -1];
