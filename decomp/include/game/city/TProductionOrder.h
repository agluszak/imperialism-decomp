#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/order_sheet.h"
#include "game/resource_domain_types.h"

class TStream;
class TCity;
class TPopulationMgr;

enum ProductionOrderLimitKind {
  kProductionOrderLimitResources = 0,
  kProductionOrderLimitWorkforce = 1,
  kProductionOrderLimitCapacity = 2,
  kProductionOrderLimitTreasury = 3
};

// VTABLE: IMPERIALISM 0x0064fa18
class TProductionOrder : public TObject {
public:
  DECLARE_DYNCREATE(TProductionOrder)
  // FUNCTION: IMPERIALISM 0x004b4f50
  virtual ~TProductionOrder() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void IProductionOrder(TCity* city, short resourceType);
  virtual bool SetQuantity(short newQuantity);
  virtual short MaxOrder();
  virtual void Produce();
  virtual void Restock();
  virtual void ResetOrderSheet(OrderSheet* orderSheet);
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity);
  // The order-slot family shares this 0x4c-byte prefix; TUnitOrder appends fields.
  short quantity;                          // pending order quantity
  TCity* ownerCity;                        // owning city
  TPopulationMgr* productionSummary;       // city population/production summary
  short trackingSlots[kResourceKindCount]; // per-resource tracking slots
  short reservedWorkforce;                 // labor committed to this order
  short limitingConstraint;                // ProductionOrderLimitKind
  int accumulatedValue;    // summed by TGreatPower::SumCommodityRecordAccumulatedValues
  short resourceTypeIndex; // resource/entry type index
  short unused4a;          // field-xrefs show zero accesses; layout padding/reserved

  // The base order has no initialized fields until IProductionOrder is called.
  // FUNCTION: IMPERIALISM 0x004b4f00
  TProductionOrder() {}
};

ASSERT_SIZE(TProductionOrder, 0x4c);
