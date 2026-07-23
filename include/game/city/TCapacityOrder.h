#pragma once

#include "game/city/TItemOrder.h"

struct CRuntimeClass;

class TCity;

// Mac oracle: TCapacityOrder (capacity / industry production order).
// VTABLE: IMPERIALISM 0x0064f678
class TCapacityOrder : public TItemOrder {
public:
  DECLARE_DYNCREATE(TCapacityOrder)
  TCapacityOrder(); // trivial; inlined into CreateObject in the binary
  ~TCapacityOrder() override;

  void Produce() override; // slot 0x0d 0x4b8dd0
  virtual void ICapacityOrder(TCity* city, short resourceType, short primaryInputResource,
                              short secondaryInputResource,
                              short productionSlot); // slot 0x12 0x4b8d50

  explicit TCapacityOrder(TCity* city);
  short ComputeCapacityOrderMaxQuantity();
  bool SetCapacityOrderQuantity(short quantity);
  void CommitCapacityOrderIfPending();
  // No FillOrderSheet override here: TCapacityOrder's vtable slot 0x10 is byte-identical
  // to TItemOrder's (confirmed via direct vtable read), so it inherits TItemOrder's
  // FillOrderSheet unchanged. The real logic once misfiled here as this class's own
  // FillOrderSheet was actually TShipOrder::FillOrderSheet (0x004b8b80) -- moved there.
  bool CanMakeFromCityStock();
  bool CanFillOrderSheet(OrderSheet* orderSheet);
  static TCapacityOrder* NewForCity(TCity* city);

  // No own fields: RTTI proves TCapacityOrder is exactly TItemOrder's size (0x54).
  // quantityField04/cityField08/summaryField0c/trackingSlots10/field3e/field40 are
  // TProductionOrder's own fields (accumulatedValue is field44/resourceTypeIndex48 is
  // shared too); requestedQuantity4c/primaryInputResourceId/secondaryInputResourceId/
  // productionSlot are TItemOrder's own fields -- use the inherited names directly.
};
