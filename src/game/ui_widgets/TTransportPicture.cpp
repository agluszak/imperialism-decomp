#include "game/ui_widgets/TTransportPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/mfc.h"
#include "game/ui_core/TControl.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x00591d90
// TTransportPicture::CreateObject
// SYNTHETIC: IMPERIALISM 0x00591e50
// TTransportPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTransportPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00591e70
TTransportPicture::TTransportPicture()
    : TPicture(), gaugeMetricId90(0x3a), splitValue94(0), splitValue96(0),
      splitLimit98((short)0xffff) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00591ec0
// TTransportPicture::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00591ef0
TTransportPicture::~TTransportPicture() {}

// FUNCTION: IMPERIALISM 0x00591f10
void TTransportPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 100 && commandId <= 0x65) {
    short nationId = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationId];
    int metricSlot = static_cast<int>(resourceMetricSlot92);
    short targetAmount;
    short currentAmount;
    if (metricSlot == 0) {
      targetAmount = nation->needTargetByType[1] + nation->needTargetByType[0];
      currentAmount = nation->needCurrentByType[1] + nation->needCurrentByType[0];
    } else if (metricSlot == 0x13) {
      targetAmount = nation->needTargetByType[0x14] + nation->needTargetByType[0x13];
      currentAmount = nation->needCurrentByType[0x14] + nation->needCurrentByType[0x13];
    } else {
      targetAmount = nation->needTargetByType[metricSlot];
      currentAmount = nation->needCurrentByType[metricSlot];
    }
    bool changed = false;
    if (commandId == 100) {
      if (targetAmount < currentAmount && nation->needCapA6 != nation->needsOverCapFlag) {
        splitValue94 = static_cast<short>(targetAmount + 1);
        changed = true;
      }
    } else if (targetAmount > 0) {
      splitValue94 = static_cast<short>(targetAmount - 1);
      changed = true;
    }
    if (changed) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);

      short selectedMetricSlot = resourceMetricSlot92;
      if (selectedMetricSlot == 0) {
        short firstWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(0);
        short secondWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(1);
        int primaryNeedIndex;
        int secondaryNeedIndex;
        if (firstWeight > secondWeight) {
          primaryNeedIndex = 0;
          secondaryNeedIndex = 1;
        } else {
          primaryNeedIndex = 1;
          secondaryNeedIndex = 0;
        }

        short primaryCurrentAmount = nation->needCurrentByType[primaryNeedIndex];
        if (primaryCurrentAmount < splitValue94) {
          nation->UpdateNeedTargetAndAccumulateOverCap(primaryNeedIndex, primaryCurrentAmount);
          nation->UpdateNeedTargetAndAccumulateOverCap(
              secondaryNeedIndex, static_cast<short>(splitValue94 - primaryCurrentAmount));
        } else {
          nation->UpdateNeedTargetAndAccumulateOverCap(primaryNeedIndex, splitValue94);
          nation->UpdateNeedTargetAndAccumulateOverCap(secondaryNeedIndex, 0);
        }
      } else if (selectedMetricSlot == 0x13) {
        short primaryCurrentAmount = nation->needCurrentByType[0x13];
        if (primaryCurrentAmount < splitValue94) {
          nation->UpdateNeedTargetAndAccumulateOverCap(0x13, primaryCurrentAmount);
          nation->UpdateNeedTargetAndAccumulateOverCap(
              0x14, static_cast<short>(splitValue94 - primaryCurrentAmount));
        } else {
          nation->UpdateNeedTargetAndAccumulateOverCap(0x13, splitValue94);
          nation->UpdateNeedTargetAndAccumulateOverCap(0x14, 0);
        }
      } else {
        nation->UpdateNeedTargetAndAccumulateOverCap(selectedMetricSlot, splitValue94);
      }

      RefreshControl();
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005921c0
void TTransportPicture::Refresh() {
  short total = splitValue96;
  if (total < 1) {
    total = 1;
  }

  // The gauge is 113 pixels wide. The original gives the first remainder pixels one
  // extra pixel so all integer divisions still fill the complete bar.
  float pixelsPerUnit = 113.0f / static_cast<float>(total);
  float remainder = 113.0f - pixelsPerUnit * static_cast<float>(total);
  float markerPosition;
  if (remainder < static_cast<float>(splitValue94)) {
    markerPosition = remainder * (pixelsPerUnit + 1.0f) +
                     (static_cast<float>(splitValue94) - remainder) * pixelsPerUnit;
  } else {
    markerPosition = static_cast<float>(splitValue94) * (pixelsPerUnit + 1.0f);
  }

  CString currentText;
  CString totalText;
  CString gaugeText;
  currentText.Format(g_szDecimalFormat, static_cast<int>(splitValue94));
  totalText.Format(g_szDecimalFormat, static_cast<int>(splitValue96));
  gaugeText = currentText + CString(s_szSpaceSeparator_00695794) + totalText;

  TStaticText* text = static_cast<TStaticText*>(ResolveControlByTag(kControlTagText));
  text->AssertValid();
  text->SetTextAndMaybeRefresh(&gaugeText, 1);

  if (resourceMetricSlot92 == 0x16 || resourceMetricSlot92 == 0x15) {
    int multiplier = resourceMetricSlot92 == 0x16 ? 200 : 500;
    CString valueText;
    valueText.Format(g_szDecimalFormat, static_cast<int>(splitValue94) * multiplier);
    TStaticText* value = static_cast<TStaticText*>(ResolveControlByTag(kControlTagValu));
    value->AssertValid();
    value->SetTextAndMaybeRefresh(&valueText, 1);
  }

  if (splitLimit98 >= 0) {
    SetState(splitValue94 < splitLimit98 ? 0 : 1, 0);
  }

  if (controlTag != static_cast<int>(kControlTagTota)) {
    short activeNation = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[activeNation];
    TTransportPicture* totalPicture =
        static_cast<TTransportPicture*>(ownerContext->ResolveControlByTag(kControlTagTota));
    totalPicture->AssertValid();
    totalPicture->splitValue94 = nation != 0 ? nation->needsOverCapFlag : 0;
    totalPicture->RefreshControl();
  }

  (void)markerPosition;
  TView::RefreshControl();
}

// FUNCTION: IMPERIALISM 0x00592830
void TTransportPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  ForceRedraw();
}
