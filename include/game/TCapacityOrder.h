#pragma once

#include "game/TItemOrder.h"

struct CRuntimeClass;

class TCity;

// Mac oracle: TCapacityOrder (capacity / industry production order).
// VTABLE: IMPERIALISM 0x0064f678
class TCapacityOrder : public TItemOrder {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  ~TCapacityOrder();

  undefined CommitIfPending() override; // slot 0x0d 0x4b8dd0
  virtual undefined InitializeCityProductionState_Impl_At004b8d50(
      TCity* city, short resourceType, short trackingIndex4e, short trackingIndex50,
      short field52); // slot 0x12 0x4b8d50

  explicit TCapacityOrder(TCity* city);
  short ComputeCapacityOrderMaxQuantity();
  bool SetCapacityOrderQuantity(short quantity);
  void CommitCapacityOrderIfPending();
  void FillOrderSheet(void* orderSheet, short quantity);
  bool CanMakeFromCityStock();
  bool CanFillOrderSheet(void* orderSheet);
  static TCapacityOrder* NewForCity(TCity* city);

  short quantityField04;
  TCity* cityField08;
  class TPopulationMgr* summaryField0c;
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

