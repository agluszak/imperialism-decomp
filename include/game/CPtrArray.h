#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CObject.h"

class CPtrArray : public CObject {
public:
  void** entries;
  int count;
  int capacity;
  int growBy;

  CPtrArray();
  virtual ~CPtrArray() override;

  void SetSize(int nNewSize, int nGrowBy = -1);
  void SetAtGrow(int nIndex, void* newElement);
  void InsertAt(int nIndex, void* newElement, int nCount = 1);
  void RemoveAt(int nIndex, int nCount = 1);
};

ASSERT_SIZE(CPtrArray, 0x14);
