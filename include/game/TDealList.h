#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/mfc.h"
#include "game/TIndexAndRankList.h"

class CArchive;

#define TDEALLIST_VTABLE_SLOT(n)                                                                   \
  virtual void VTableIndex##n##_Provisional(void) {}

// Mac oracle: TDealList (nation interaction / proposal weight manager).
// VTABLE: IMPERIALISM 0x0066da38
class TDealList : public CObject {
public:
  struct NationMetricCategoryRow {
    unsigned char pad00[0x0a];
    short proposalWeightScale0a;
    unsigned char pad0c[0x0c];
    short capabilityActiveFlag18;
    unsigned char pad1a[0xa0 - 0x1a];
  };

  TDealList();
  void InitializeNationInteractionStateManagerDefaults();

  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual void Serialize(CArchive& ar) override;
  virtual void AssertValid() const override;
  virtual void Dump(CDumpContext& unused) const override;
  TDEALLIST_VTABLE_SLOT(05);
  TDEALLIST_VTABLE_SLOT(06);
  TDEALLIST_VTABLE_SLOT(07);
  TDEALLIST_VTABLE_SLOT(08);
  TDEALLIST_VTABLE_SLOT(09);
  TDEALLIST_VTABLE_SLOT(10);
  TDEALLIST_VTABLE_SLOT(11);
  TDEALLIST_VTABLE_SLOT(12);
  TDEALLIST_VTABLE_SLOT(13);
  TDEALLIST_VTABLE_SLOT(14);
  // slot 0x3c — nonzero when the capability category row (+0x18) is active.
  virtual short IsCapabilityCategoryActiveSlot3C(int category);
  TDEALLIST_VTABLE_SLOT(16);
  TDEALLIST_VTABLE_SLOT(17);
  TDEALLIST_VTABLE_SLOT(18);
  // slot 0x4c — proposal-weight threshold for random%100+200 tests.
  virtual short QueryProposalWeightSlot4C(int metricSlot);
  TDEALLIST_VTABLE_SLOT(20);
  TDEALLIST_VTABLE_SLOT(21);
  TDEALLIST_VTABLE_SLOT(22);
  TDEALLIST_VTABLE_SLOT(23);
  // slot 0x60 — diplomacy transfer dispatch used by foreign-minister proposals.
  virtual void DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
                                            int maxAmount, int targetNation, char emitEventFlag,
                                            char skipLocalizationBranch);
  TDEALLIST_VTABLE_SLOT(25);
  TDEALLIST_VTABLE_SLOT(26);
  TDEALLIST_VTABLE_SLOT(27);
  TDEALLIST_VTABLE_SLOT(28);
  TDEALLIST_VTABLE_SLOT(29);
  TDEALLIST_VTABLE_SLOT(30);
  TDEALLIST_VTABLE_SLOT(31);
  TDEALLIST_VTABLE_SLOT(32);
  // slot 0x84 — maps a proposal code into a capability category's effective code.
  virtual short ResolveProposalCodeForCategorySlot84(int proposalCode, int category);

  NationMetricCategoryRow categoryRows[0x11];
  unsigned char padBetweenRowsAndLists[0x3f8];
  TIndexAndRankList* categoryRankLists[0x11];
};

typedef TDealList TNationInteractionStateManager;

extern TDealList* g_pNationInteractionStateManager;
