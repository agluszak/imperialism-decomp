#pragma once

#include "game/TCityOrderItem.h"

struct CRuntimeClass;

class TCity;

// Mac oracle: TCapacityOrder (capacity / industry production order).
// VTABLE: IMPERIALISM 0x0064f678
class TCapacityOrder : public TCityOrderItem {
public:
  explicit TCapacityOrder(TCity* city);
  CRuntimeClass* GetRuntimeClass() const override;
  short MaxOrder() override;
  bool SetQuantity(short quantity) override;
  void CommitIfPending() override;
  void FillOrderSheet(void* orderSheet, short quantity) override;
  bool CanMakeFromCityStock() override;
  bool CanFillOrderSheet(void* orderSheet) override;
  // Mac: ICapacityOrder(TCity*, short, short, short, short).
  void ICapacityOrder(TCity* city, short resourceType, short trackingIndex4e, short trackingIndex50,
                      short field52);
  void ApplyCityProductionSlotDelta() override;
  static TCapacityOrder* NewForCity(TCity* city);

  short quantityField04;
  TCity* cityField08;
  class TCitySummaryObject* summaryField0c;
  short trackingSlots10[0x17];
  short field3e;
  short field40;
  int field44;
  short resourceTypeIndex48;
  short field4c;
  short trackingIndex4e;
  short trackingIndex50;
  short field52;
};
