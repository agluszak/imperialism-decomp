#include "game/TForeignMinisterPersonalities.h"

#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TTechMgr.h"
#include "game/TTradeMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

namespace {

struct ResourcePriorityEntry {
  short resourceCode;
  short priority;
};

static bool HasAdvancedTradeResource(const TForeignMinister* minister) {
  return g_pCityOrderCapabilityState->orderCapRows277[minister->ownerContextAt04->nationSlot]
             .techStatusByTechId[0x13] == 2;
}

} // namespace

// ===================== TTedForeignMinister (0x659d70) =====================

// SYNTHETIC: IMPERIALISM 0x00531130
// TTedForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005311b0
// TTedForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTedForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005311d0
TTedForeignMinister::TTedForeignMinister() : TForeignMinister() {
  field1a = 4;
  this->skillIndexC = 5;
}

// SYNTHETIC: IMPERIALISM 0x00531240
// TTedForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531290
void TTedForeignMinister::SetBuyPriorities() {
  if (!HasAdvancedTradeResource(this)) {
    if (ownerContextAt04->GetDiplomacyExternalStateByTarget(4) <
        ownerContextAt04->GetDiplomacyExternalStateByTarget(3)) {
      preferredResourceSlots40[0] = 4;
      preferredResourceSlots40[2] = 3;
    } else {
      preferredResourceSlots40[0] = 3;
      preferredResourceSlots40[2] = 4;
    }
    preferredResourceSlots40[1] = 2;
    preferredResourceSlots40[3] = rand() < 0x3ffe ? 0 : 1;
    TForeignMinister::SetBuyPriorities();
    return;
  }

  short resources[4] = {2, 3, 4, 6};
  for (int i = 0; i < 3; ++i) {
    for (int j = i + 1; j < 4; ++j) {
      if (ownerContextAt04->GetDiplomacyExternalStateByTarget(resources[j]) <
          ownerContextAt04->GetDiplomacyExternalStateByTarget(resources[i])) {
        short swap = resources[i];
        resources[i] = resources[j];
        resources[j] = swap;
      }
    }
  }
  for (int resourceIndex = 0; resourceIndex < 3; ++resourceIndex) {
    preferredResourceSlots40[resourceIndex] = resources[resourceIndex];
  }
  preferredResourceSlots40[3] = rand() < 0x3ffe ? 0 : 1;
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531550
void TTedForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90TedVariant).
}

// FUNCTION: IMPERIALISM 0x00531770
void TTedForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                            short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (DispatchNationInteractionAmountByModePolicyA).
}

// FUNCTION: IMPERIALISM 0x00531a10
void TTedForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueTedFourRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00531af0
void TTedForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x00531b10
void TTedForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] = 3;
}

// ===================== TBillForeignMinister (0x659e30) =====================

// SYNTHETIC: IMPERIALISM 0x00531b30
// TBillForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00531bc0
// TBillForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TBillForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00531be0
TBillForeignMinister::TBillForeignMinister() : TForeignMinister() {
  orderFlag80 = 0;
  field48 = 1;
  field1c = 1;
  field1a = 4;
  skillIndexC = 4;
}

// SYNTHETIC: IMPERIALISM 0x00531c50
// TBillForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00531ca0
void TBillForeignMinister::ReadFrom(TStream* stream) {
  TForeignMinister::ReadFrom(stream);
  stream->ReadBytes(&orderFlag80, 1);
}

// FUNCTION: IMPERIALISM 0x00531ce0
void TBillForeignMinister::WriteTo(TStream* stream) {
  TForeignMinister::WriteTo(stream);
  stream->WriteBytesSlot78(&orderFlag80, 1);
}

// FUNCTION: IMPERIALISM 0x00531d20
void TBillForeignMinister::SetBuyPriorities() {
  bool hasAdvancedResource = HasAdvancedTradeResource(this);
  if (ownerContextAt04->GetDiplomacyExternalStateByTarget(4) <
      ownerContextAt04->GetDiplomacyExternalStateByTarget(3)) {
    preferredResourceSlots40[0] = 4;
    preferredResourceSlots40[hasAdvancedResource ? 3 : 2] = 3;
  } else {
    preferredResourceSlots40[0] = 3;
    preferredResourceSlots40[hasAdvancedResource ? 3 : 2] = 4;
  }
  preferredResourceSlots40[1] = 2;
  if (hasAdvancedResource) {
    preferredResourceSlots40[2] = 6;
  } else {
    preferredResourceSlots40[3] = static_cast<short>(0xfff6);
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00531e50
void TBillForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90BillVariant).
}

// FUNCTION: IMPERIALISM 0x00532190
void TBillForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (DispatchNationInteractionAmountByModePolicyB).
}

// FUNCTION: IMPERIALISM 0x00532520
void TBillForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueDiplomatTwoRandomAvailableTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x005325e0
void TBillForeignMinister::DoSecondTurnDiplomacy() {
  // Partial port (QueueDiplomatTwoCompatibleMatrixActionsCode5A).
}

// FUNCTION: IMPERIALISM 0x00532650
void TBillForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] = 3;
  short nextLevel = static_cast<short>(city->GetBuildingType(2) + 2);
  city->productionAccum1fc[2] = static_cast<short>(city->productionAccum1fc[2] + nextLevel -
                                                   city->productionOrderTable1dc[2]);
  city->productionOrderTable1dc[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(4) + 2);
  city->productionAccum1fc[4] = static_cast<short>(city->productionAccum1fc[4] + nextLevel -
                                                   city->productionOrderTable1dc[4]);
  city->productionOrderTable1dc[4] = nextLevel;
  city->SetOwnerNeedCapA6(static_cast<short>(city->GetOwnerNeedCapA6() + 2));
}

// ===================== TDiplomatForeignMinister (0x659f48) =====================

// SYNTHETIC: IMPERIALISM 0x005326e0
// TDiplomatForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00532760
// TDiplomatForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TDiplomatForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00532780
TDiplomatForeignMinister::TDiplomatForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x005327f0
// TDiplomatForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00532840
void TDiplomatForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueDiplomatWeightedTerrainActionRunCode133).
}

// FUNCTION: IMPERIALISM 0x005328d0
void TDiplomatForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x005328f0
void TDiplomatForeignMinister::SetBuyPriorities() {
  preferredResourceSlots40[0] = 2;
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots40[3] = rand() % 2 == 0 ? 1 : 0;
    if (ownerContextAt04->GetDiplomacyExternalStateByTarget(4) <
        ownerContextAt04->GetDiplomacyExternalStateByTarget(3)) {
      preferredResourceSlots40[1] = 4;
      preferredResourceSlots40[2] = ownerContextAt04->GetDiplomacyExternalStateByTarget(6) <
                                            ownerContextAt04->GetDiplomacyExternalStateByTarget(3)
                                        ? 6
                                        : 3;
    } else {
      preferredResourceSlots40[1] = 3;
      preferredResourceSlots40[2] = ownerContextAt04->GetDiplomacyExternalStateByTarget(6) <
                                            ownerContextAt04->GetDiplomacyExternalStateByTarget(4)
                                        ? 6
                                        : 4;
    }
    TForeignMinister::SetBuyPriorities();
    return;
  }

  bool hasTradeCandidate = false;
  for (short nationSlot = 7; nationSlot <= 0x16 && !hasTradeCandidate; ++nationSlot) {
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 &&
        (g_pNationInteractionStateManager->categoryRows[3].cells18[nationSlot + 0x2e] != 0 ||
         g_pNationInteractionStateManager->categoryRows[4].cells18[nationSlot + 0x2e] != 0)) {
      hasTradeCandidate = true;
    }
  }
  if (!hasTradeCandidate) {
    preferredResourceSlots40[1] = 0;
    preferredResourceSlots40[2] = 1;
    preferredResourceSlots40[3] = rand() < 0x3ffe ? 3 : 4;
  } else if (((g_pSimMgr->economicTurn / 4) & 1) != 0) {
    if (ownerContextAt04->GetDiplomacyExternalStateByTarget(4) <
        ownerContextAt04->GetDiplomacyExternalStateByTarget(3)) {
      preferredResourceSlots40[1] = 4;
      preferredResourceSlots40[2] = 3;
    } else {
      preferredResourceSlots40[1] = 3;
      preferredResourceSlots40[2] = 4;
    }
    preferredResourceSlots40[3] =
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0) >
                g_pNationInteractionStateManager->QueryProposalWeightSlot4C(1)
            ? 0
            : 1;
  } else {
    if (ownerContextAt04->GetDiplomacyExternalStateByTarget(0) <
        ownerContextAt04->GetDiplomacyExternalStateByTarget(1)) {
      preferredResourceSlots40[1] = 0;
      preferredResourceSlots40[2] = 1;
    } else {
      preferredResourceSlots40[1] = 1;
      preferredResourceSlots40[2] = 0;
    }
    preferredResourceSlots40[3] = ownerContextAt04->GetDiplomacyExternalStateByTarget(4) <
                                          ownerContextAt04->GetDiplomacyExternalStateByTarget(3)
                                      ? 4
                                      : 3;
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00532c60
void TDiplomatForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantA).
}

// FUNCTION: IMPERIALISM 0x00532f70
void TDiplomatForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                 short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (RunForeignMinisterPolicySlot30VariantA).
}

// FUNCTION: IMPERIALISM 0x00533050
void TDiplomatForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}

// ===================== TTextileForeignMinister (0x65a008) =====================

// SYNTHETIC: IMPERIALISM 0x00533070
// TTextileForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x005330f0
// TTextileForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTextileForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00533110
TTextileForeignMinister::TTextileForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533180
// TTextileForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005331d0
void TTextileForeignMinister::SetBuyPriorities() {
  preferredResourceSlots40[0] = 0;
  preferredResourceSlots40[1] = 1;
  TMinisterBaseOrderArray* priorities = new TMinisterBaseOrderArray();
  priorities->recordSize14 = sizeof(ResourcePriorityEntry);
  const short resources[4] = {3, 4, 2, 6};
  int resourceCount = HasAdvancedTradeResource(this) ? 4 : 3;
  for (int i = 0; i < resourceCount; ++i) {
    ResourcePriorityEntry entry;
    entry.resourceCode = resources[i];
    entry.priority = ownerContextAt04->GetDiplomacyExternalStateByTarget(resources[i]);
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  for (int selectedIndex = 0; selectedIndex < 2; ++selectedIndex) {
    ResourcePriorityEntry* entry = static_cast<ResourcePriorityEntry*>(
        priorities->GetPtrListEntryByOneBasedIndex(selectedIndex + 1));
    preferredResourceSlots40[selectedIndex + 2] = entry->resourceCode;
  }
  priorities->ReleasePtrList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533380
void TTextileForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantB).
}

// FUNCTION: IMPERIALISM 0x00533670
void TTextileForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                                short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (DispatchNationInteractionAmountWithAvailableCap).
}

// FUNCTION: IMPERIALISM 0x00533780
void TTextileForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] += 2;
  city->orderCountByType5c[1] += 1;
  short nextLevel = static_cast<short>(city->GetBuildingType(2) + 2);
  city->productionAccum1fc[2] = static_cast<short>(city->productionAccum1fc[2] + nextLevel -
                                                   city->productionOrderTable1dc[2]);
  city->productionOrderTable1dc[2] = nextLevel;
  nextLevel = static_cast<short>(city->GetBuildingType(1) + 1);
  city->productionAccum1fc[1] = static_cast<short>(city->productionAccum1fc[1] + nextLevel -
                                                   city->productionOrderTable1dc[1]);
  city->productionOrderTable1dc[1] = nextLevel;
}

// ===================== TTraderForeignMinister (0x65a0c8) =====================

// SYNTHETIC: IMPERIALISM 0x00533800
// TTraderForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533880
// TTraderForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TTraderForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x005338a0
TTraderForeignMinister::TTraderForeignMinister() : TForeignMinister() {}

// SYNTHETIC: IMPERIALISM 0x00533910
// TTraderForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00533960
void TTraderForeignMinister::SetBuyPriorities() {
  TMinisterBaseOrderArray* priorities = new TMinisterBaseOrderArray();
  priorities->recordSize14 = sizeof(ResourcePriorityEntry);
  for (short resourceCode = 0; resourceCode <= 4; ++resourceCode) {
    ResourcePriorityEntry entry;
    entry.resourceCode = resourceCode;
    entry.priority = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceCode);
    if (resourceCode == 3 || resourceCode == 4) {
      entry.priority = static_cast<short>(entry.priority - 15);
    }
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  if (HasAdvancedTradeResource(this)) {
    ResourcePriorityEntry entry;
    entry.resourceCode = 6;
    entry.priority =
        static_cast<short>(g_pNationInteractionStateManager->QueryProposalWeightSlot4C(6) - 15);
    priorities->InsertCopiedRecordSortedByComparator(&entry);
  }
  for (int i = 0; i < 4; ++i) {
    ResourcePriorityEntry* entry =
        static_cast<ResourcePriorityEntry*>(priorities->GetPtrListEntryByOneBasedIndex(i + 1));
    preferredResourceSlots40[i] = entry->resourceCode;
  }
  priorities->ReleasePtrList();
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00533b10
void TTraderForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterPolicySlot28VariantC).
}

// FUNCTION: IMPERIALISM 0x00533db0
void TTraderForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                               short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (DispatchNationInteractionAmountWithFallbackVariant).
}

// FUNCTION: IMPERIALISM 0x00533e90
void TTraderForeignMinister::DoFirstTurnDiplomacy() {
  // Partial port (QueueTraderFourRandomTerrainActionsCode133).
}

// FUNCTION: IMPERIALISM 0x00533f50
void TTraderForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[2] += 3;
}

// ===================== TArmsForeignMinister (0x65a188) =====================

// SYNTHETIC: IMPERIALISM 0x00533f70
// TArmsForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x00533ff0
// TArmsForeignMinister::GetRuntimeClass

// Binary descriptor base is TMinister (0x659a80), not TForeignMinister — original macro arg.
IMPLEMENT_DYNCREATE(TArmsForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x00534010
TArmsForeignMinister::TArmsForeignMinister() : TForeignMinister() {
  field48 = 1;
  field1a = 4;
  field1c = 1;
  skillIndexC = 0;
}

// SYNTHETIC: IMPERIALISM 0x00534080
// TArmsForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005340d0
void TArmsForeignMinister::SetBuyPriorities() {
  if (HasAdvancedTradeResource(this)) {
    preferredResourceSlots40[0] = 6;
    preferredResourceSlots40[1] = 2;
    preferredResourceSlots40[2] = 3;
    preferredResourceSlots40[3] = 4;
  } else {
    preferredResourceSlots40[0] = 2;
    preferredResourceSlots40[1] = 3;
    preferredResourceSlots40[2] = 4;
    preferredResourceSlots40[3] = rand() % 2;
  }
  TForeignMinister::SetBuyPriorities();
}

// FUNCTION: IMPERIALISM 0x00534190
void TArmsForeignMinister::SetTradeBids() {
  // Partial port (RunForeignMinisterVtableSlot90ArmsVariant).
}

// FUNCTION: IMPERIALISM 0x00534450
void TArmsForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3,
                                             short resourceCode) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)resourceCode;
  // Partial port (DispatchNationInteractionAmountWithSharedSplitCache).
}

// FUNCTION: IMPERIALISM 0x00534660
void TArmsForeignMinister::MakeNewCity(TCity* city) {
  city->orderCountByType5c[1] += 5;
}
