#include "game/ui_widgets/TMinorTradeBidsDialog.h"
#include "game/ui_tags_widgets.h"

#include "game/nation/TMinor.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b2a30
// TMinorTradeBidsDialog::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b2a60
TMinorTradeBidsDialog::~TMinorTradeBidsDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b29a0
// TMinorTradeBidsDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2a80
// TMinorTradeBidsDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinorTradeBidsDialog, TDialogView)

// FUNCTION: IMPERIALISM 0x005b2aa0
void TMinorTradeBidsDialog::StuffValues() {
  TView* costPanel = ResolveControlByTag(kControlTagCost); // 'Cost'
  if (costPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x179);
  }

  short nationSlot;
  for (nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    TNumberText* amountControl = static_cast<TNumberText*>(
        costPanel->ResolveControlByTag(g_tradeBidNationMetricControlTags[nationSlot]));
    if (amountControl != 0) {
      amountControl->SetControlValue(g_pNationInteractionStateManager->GetPrice(nationSlot), 0);
    }
  }

  TMinor** auxiliaryNationSlot = g_apNationAuxRuntimeStateSlots;
  int minorTableByteOffset = 0;
  int remainingMinorCount = 16;
  do {
    int minorIndex = minorTableByteOffset / sizeof(TMinor*);
    if (g_apMinorNationCapabilityObjects[minorIndex] != 0) {
      TView* minorPanel = ResolveControlByTag(g_minorTreatyPanelTags[minorIndex]);
      if (minorPanel == 0) {
        FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x189);
      }

      for (short metricSlot = 0; metricSlot < 0x17; ++metricSlot) {
        TNumberText* amountControl = static_cast<TNumberText*>(
            minorPanel->ResolveControlByTag(g_tradeBidNationMetricControlTags[metricSlot]));
        if (amountControl != 0) {
          amountControl->SetEnable(0);
          amountControl->minimumValue = -1;
          amountControl->SetControlValue((*auxiliaryNationSlot)->GetTradeOffersFor(metricSlot), 0);
        }
      }
    }
    minorTableByteOffset += sizeof(TMinor*);
    ++auxiliaryNationSlot;
    --remainingMinorCount;
  } while (remainingMinorCount != 0);
}
