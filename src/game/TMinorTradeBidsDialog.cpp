#include "game/TMinorTradeBidsDialog.h"

#include "game/TMinor.h"
#include "game/TNumberText.h"
#include "game/TTradeMgr.h"
#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x005b2a30
// TMinorTradeBidsDialog::`scalar deleting destructor'
TMinorTradeBidsDialog::~TMinorTradeBidsDialog() {}
// SYNTHETIC: IMPERIALISM 0x005b29a0
// TMinorTradeBidsDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b2a80
// TMinorTradeBidsDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinorTradeBidsDialog, TDialogView)

TMinorTradeBidsDialog::TMinorTradeBidsDialog() {}

// FUNCTION: IMPERIALISM 0x005b2aa0
void TMinorTradeBidsDialog::StuffValues() {
  TView* costPanel = ResolveControlByTag(0x436f7374); // 'Cost'
  if (costPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUTestDialogs_0069A7F8, 0x179);
  }

  short nationSlot;
  for (nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    TNumberText* amountControl = static_cast<TNumberText*>(
        costPanel->ResolveControlByTag(g_tradeBidNationMetricControlTags[nationSlot]));
    if (amountControl != 0) {
      amountControl->SetControlValue(
          g_pNationInteractionStateManager->QueryProposalWeightSlot4C(nationSlot), 0);
    }
  }

  for (int minorIndex = 0; minorIndex < 16; ++minorIndex) {
    if (g_apMinorNationCapabilityObjects[minorIndex] == 0) {
      continue;
    }

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
        amountControl->SetControlValue(
            g_apNationAuxRuntimeStateSlots[minorIndex]->QueryNationMetricBySlot7C(metricSlot), 0);
      }
    }
  }
}
