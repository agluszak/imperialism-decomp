#pragma once

#include "decomp_types.h"
#include "game/CObject.h"

class CPtrArray : public CObject {
 public:
  void** entries;
  int count;
  int capacity;
  int growBy;

  CPtrArray();
  virtual ~CPtrArray();

  void* DestructCObArrayAndMaybeFree(byte freeSelfFlag);

  void SetSize(int nNewSize, int nGrowBy = -1);
  void SetAtGrow(int nIndex, void* newElement);
  void InsertAt(int nIndex, void* newElement, int nCount = 1);
  void RemoveAt(int nIndex, int nCount = 1);
};

typedef char CPtrArraySizeMustMatch[(sizeof(CPtrArray) == 0x14) ? 1 : -1];
