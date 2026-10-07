#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/ui_widgets/TMinorTradeBidsDialog.h"
#include "game/ui_tags_widgets.h"

#include "game/nation/TMinor.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x005b2a60
TMinorTradeBidsDialog::~TMinorTradeBidsDialog() {}

IMPLEMENT_DYNCREATE(TMinorTradeBidsDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b2aa0
void TMinorTradeBidsDialog::StuffValues() {
  TView* costPanel = FindSubView(kControlTagCost); // 'Cost'
  if (costPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x179);
  }

  short nationSlot;
  for (nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    TNumberText* amountControl = static_cast<TNumberText*>(
        costPanel->FindSubView(g_tradeBidNationMetricControlTags[nationSlot]));
    if (amountControl != 0) {
      amountControl->SetControlValue(g_pTradeMgr->GetPrice(nationSlot), 0);
    }
  }

  TMinor** auxiliaryNationSlot = g_apNationAuxRuntimeStateSlots;
  int minorTableByteOffset = 0;
  for (int remainingMinorCount = 0; remainingMinorCount < kMinorNationCount;
       ++remainingMinorCount) {
    int minorIndex = minorTableByteOffset / sizeof(TMinor*);
    if (g_apTerrainTypeDescriptorTable[7 + minorIndex] != 0) {
      TView* minorPanel = FindSubView(g_minorTreatyPanelTags[minorIndex]);
      if (minorPanel == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs, 0x189);
      }

      for (short metricSlot = 0; metricSlot < kResourceKindCount; ++metricSlot) {
        TNumberText* amountControl = static_cast<TNumberText*>(
            minorPanel->FindSubView(g_tradeBidNationMetricControlTags[metricSlot]));
        if (amountControl != 0) {
          amountControl->SetEnable(0);
          amountControl->minimumValue = -1;
          amountControl->SetControlValue((*auxiliaryNationSlot)->GetTradeOffersFor(metricSlot), 0);
        }
      }
    }
    minorTableByteOffset += sizeof(TMinor*);
    ++auxiliaryNationSlot;
  }
}
