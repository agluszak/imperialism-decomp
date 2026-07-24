#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/order_sheet.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;
class TPopulationMgr;

// TProductionOrder is the common base for the city order-slot family
// (TShipOrder, TTrainingOrder, TItemOrder/TOrItemOrder, TUnitOrder,
// TPowerPlantOrder, TFoodProcessingOrder, TPopGrowthOrder, TCapacityOrder,
// TExpansionOrder). Base edge (TObject) recovered from RTTI CRuntimeClass
// chain: TProductionOrder -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064fa18
class TProductionOrder : public TObject {
public:
  DECLARE_DYNCREATE(TProductionOrder)
  virtual ~TProductionOrder() override;            // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b4fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b5060
  virtual void IProductionOrder(TCity* city, short resourceType);      // slot 0x0a 0x4b4f70
  virtual bool SetQuantity(short quantity);                            // slot 0x0b 0x4b5100
  virtual short MaxOrder();                                            // slot 0x0c 0x4b50e0
  virtual void Produce();                                              // slot 0x0d 0x4b5160
  virtual void Restock();                                              // slot 0x0e 0x4b5140
  virtual void ResetOrderSheet(OrderSheet* orderSheet);                // slot 0x0f 0x4b5180
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity); // slot 0x10 0x4b51b0
  // Field layout recovered from the RTTI object-size match: TProductionOrder
  // and several direct children (TShipOrder, TTrainingOrder,
  // TFoodProcessingOrder, TPopGrowthOrder) are ALL exactly 0x4c bytes per
  // `config/rtti_class_oracle.csv`, so those children add zero fields of
  // their own — every field previously modeled on TShipOrder at these same
  // offsets is really this base's own layout. Cross-checked against
  // TUnitOrder::Produce (0x004b73b0, a sibling with its own extra
  // 0x10 bytes) reading the identical offsets +0x04/+0x08/+0x48 for the same
  // roles (pending quantity, owning city, resource/entry id).
  short quantityField04;          // 0x04 — pending order quantity
  TCity* cityField08;             // 0x08 — owning city
  TPopulationMgr* summaryField0c; // 0x0c — city population/production summary
  short trackingSlots10[0x17];    // 0x10..0x3e — per-resource tracking slots
  short field3e;                  // 0x3e
  short field40;                  // 0x40
  int accumulatedValue; // 0x44 — summed by TGreatPower::SumCommodityRecordAccumulatedValues (0x004e06d0)
  short resourceTypeIndex48; // 0x48 — resource/entry type index
  short field4a;             // 0x4a

  // In-class inline. 0x004b4f00 is the out-of-line copy MSVC still emits, but derived
  // CreateObject bodies absorb it instead of calling it: TItemOrder::CreateObject
  // (0x004b51d0) has no call and no EH frame, just new + the derived vptr store.
  // FUNCTION: IMPERIALISM 0x004b4f00
  TProductionOrder() : TObject() {}
};

ASSERT_SIZE(TProductionOrder, 0x4c);
