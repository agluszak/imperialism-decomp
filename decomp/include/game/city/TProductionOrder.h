#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/order_sheet.h"
#include "game/resource_domain_types.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;
class TPopulationMgr;

enum ProductionOrderLimitKind {
  kProductionOrderLimitResources = 0,
  kProductionOrderLimitWorkforce = 1,
  kProductionOrderLimitCapacity = 2,
  kProductionOrderLimitTreasury = 3
};

// TProductionOrder is the common base for the city order-slot family
// (TShipOrder, TTrainingOrder, TItemOrder/TOrItemOrder, TUnitOrder,
// TPowerPlantOrder, TFoodProcessingOrder, TPopGrowthOrder, TCapacityOrder,
// TExpansionOrder). Base edge (TObject) recovered from RTTI CRuntimeClass
// chain: TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064fa18
class TProductionOrder : public TObject {
public:
  DECLARE_DYNCREATE(TProductionOrder)
  // FUNCTION: IMPERIALISM 0x004b4f50
  virtual ~TProductionOrder() override {}          // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b4fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b5060
  virtual void IProductionOrder(TCity* city, short resourceType);      // slot 0x0a 0x4b4f70
  virtual bool SetQuantity(short newQuantity);                         // slot 0x0b 0x4b5100
  virtual short MaxOrder();                                            // slot 0x0c 0x4b50e0
  virtual void Produce();                                              // slot 0x0d 0x4b5160
  virtual void Restock();                                              // slot 0x0e 0x4b5140
  virtual void ResetOrderSheet(OrderSheet* orderSheet);                // slot 0x0f 0x4b5180
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity); // slot 0x10 0x4b51b0
  // LAYOUT: the order-slot family shares this complete 0x4c-byte prefix; several
  // direct children add no storage, while TUnitOrder appends its own fields.
  short quantity;                          // 0x04 — pending order quantity
  TCity* ownerCity;                        // 0x08 — owning city
  TPopulationMgr* productionSummary;       // 0x0c — city population/production summary
  short trackingSlots[kResourceKindCount]; // 0x10..0x3e — per-resource tracking slots
  short reservedWorkforce;                 // 0x3e — labor committed to this order
  short limitingConstraint;                // 0x40 — ProductionOrderLimitKind
  int accumulatedValue; // 0x44 — summed by TGreatPower::SumCommodityRecordAccumulatedValues (0x004e06d0)
  short resourceTypeIndex; // 0x48 — resource/entry type index
  short unknown4a;         // 0x4a — unresolved storage; no recovered access outside layout

  // In-class inline. 0x004b4f00 is the out-of-line copy MSVC still emits, but derived
  // CreateObject bodies absorb it instead of calling it: TItemOrder::CreateObject
  // (0x004b51d0) has no call and no EH frame, just new + the derived vptr store.
  // FUNCTION: IMPERIALISM 0x004b4f00
  TProductionOrder() : TObject() {}
};

ASSERT_SIZE(TProductionOrder, 0x4c);

// FUNCTION: IMPERIALISM 0x004b5100
inline bool TProductionOrder::SetQuantity(short newQuantity) {
  if (newQuantity > MaxOrder() || newQuantity < 0) {
    return false;
  }
  quantity = newQuantity;
  return true;
}
