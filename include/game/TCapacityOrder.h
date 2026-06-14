#pragma once

#include "game/TCityOrderItem.h"

struct CRuntimeClass;

// Mac oracle: TCapacityOrder (capacity / industry production order).
class TCapacityOrder : public TCityOrderItem {
public:
  virtual CRuntimeClass* GetRuntimeClass();
  // Ghidra: CreateTCapacityOrderInstance — Mac: FillOrderSheet(OrderSheet*, short).
  void FillOrderSheet(void* orderSheet);

  short quantityField04;
  unsigned char pad06[0x48 - 0x06];
  short resourceTypeIndex48;
};
