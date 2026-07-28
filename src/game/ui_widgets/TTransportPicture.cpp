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
#include "game/gfx/CTemporaryRegion.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"

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
      if (targetAmount < currentAmount &&
          nation->transportCapacity != nation->reservedTransportCapacity) {
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

// Paints the ledger gauge, then updates its caption. The bar is drawn as two abutting
// fills -- track start to marker in the row's own colour, marker to track end in the
// empty-track colour 0x3b -- with an optional 2px limit marker underneath. Every fill is
// bracketed by ClipRect/SetClip against a scoped GetClip so it cannot bleed outside the
// gauge; the CTemporaryRegion holding that saved clip is the function's outermost object
// and its destructor is what closes the EH frame.
// FUNCTION: IMPERIALISM 0x005921c0
void TTransportPicture::Refresh() {
  CTemporaryRegion savedClip;
  CString currentText;
  CString totalText;
  CString gaugeText;

  // Rows in the right-hand ledger column start further right than the left column's.
  // Written as an if/else, not a ternary: VC5 turns a ternary between two constants into a
  // branchless setle/dec/and/add chain, where the original branches (0x00592220).
  short trackLeft = 0x61;
  if (ownerLocalX > 0xc8) {
    trackLeft = 0x5d;
  }

  // The gauge is 113 pixels wide. The original gives the first remainder pixels one
  // extra pixel so all integer divisions still fill the complete bar. The +1.0f is
  // emitted as a subtraction of the -1.0 double at 0x006631a0. There is deliberately no
  // guard on splitValue96 here -- the original divides by it unclamped (0x00592258).
  float pixelsPerUnit = 113.0f / static_cast<float>(splitValue96);
  float remainder = 113.0f - pixelsPerUnit * static_cast<float>(splitValue96);
  float markerOffset;
  if (remainder < static_cast<float>(splitValue94)) {
    markerOffset = remainder * (pixelsPerUnit + 1.0f) +
                   (static_cast<float>(splitValue94) - remainder) * pixelsPerUnit;
  } else {
    markerOffset = static_cast<float>(splitValue94) * (pixelsPerUnit + 1.0f);
  }

  GetClip(savedClip.tempRgn);
  int marker = static_cast<int>(static_cast<float>(trackLeft) + markerOffset);

  RECT emptyRect;
  emptyRect.left = marker;
  emptyRect.top = 0xd;
  emptyRect.right = trackLeft + 0x71;
  emptyRect.bottom = 0x11;
  ClipRect(&emptyRect);
  g_pUiRuntimeContext->SetForeColor(0x3b);
  FillRectWithQuickDrawBrushAndContextOffset(&emptyRect);

  RECT fillRect;
  fillRect.left = trackLeft;
  fillRect.top = 0xd;
  fillRect.right = marker;
  fillRect.bottom = 0x11;
  if (controlTag == static_cast<int>(kControlTagTota)) {
    // The capacity total goes red once allocation reaches the cap.
    g_pUiRuntimeContext->SetForeColor(splitValue96 == splitValue94 ? 0x34 : 0x33);
  } else {
    g_pUiRuntimeContext->SetForeColor(gaugeMetricId90);
  }
  ClipRect(&fillRect);
  FillRectWithQuickDrawBrushAndContextOffset(&fillRect);
  SetClip(savedClip.tempRgn);
  SetQuickDrawFillColor(0);

  if (splitLimit98 >= 0) {
    RECT limitRect;
    limitRect.left = trackLeft - 1;
    limitRect.top = 0x12;
    limitRect.right = trackLeft + 0x72;
    limitRect.bottom = 0x14;
    g_pUiRuntimeContext->SetForeColor(splitValue94 < splitLimit98 ? 0x33 : 0x34);
    ClipRect(&limitRect);
    FillRectWithQuickDrawBrushAndContextOffset(&limitRect);
    SetClip(savedClip.tempRgn);
    SetQuickDrawFillColor(0);
  }

  TStaticText* text = static_cast<TStaticText*>(ResolveControlByTag(kControlTagText));
  if (text == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x1a59);
  }
  currentText.Format(g_szDecimalFormat, static_cast<int>(splitValue94));
  totalText.Format(g_szDecimalFormat, static_cast<int>(splitValue96));
  gaugeText = currentText + s_szGaugeCountSeparator_0069936C + totalText;
  text->SetTextAndMaybeRefresh(&gaugeText, 1);

  // The two money rows caption their allocation in currency rather than units.
  if (resourceMetricSlot92 == 0x16) {
    TStaticText* value = static_cast<TStaticText*>(ResolveControlByTag(kControlTagValu));
    if (value == 0) {
      FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x1a63);
    }
    g_pSimMgr->NumToCurrency(static_cast<int>(splitValue94) * 200, &gaugeText);
    value->SetTextAndMaybeRefresh(&gaugeText, 1);
  } else if (resourceMetricSlot92 == 0x15) {
    TStaticText* value = static_cast<TStaticText*>(ResolveControlByTag(kControlTagValu));
    if (value == 0) {
      FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x1a6a);
    }
    g_pSimMgr->NumToCurrency(static_cast<int>(splitValue94) * 500, &gaugeText);
    value->SetTextAndMaybeRefresh(&gaugeText, 1);
  }

  if (controlTag != static_cast<int>(kControlTagTota)) {
    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TTransportPicture* totalPicture =
        static_cast<TTransportPicture*>(ownerContext->ResolveControlByTag(kControlTagTota));
    if (totalPicture == 0) {
      FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x1a77);
    }
    totalPicture->splitValue94 =
        static_cast<short>(nation->reservedTransportCapacity - nation->transportCapacity +
                           (nation != 0 ? nation->transportCapacity : 0));
    totalPicture->RefreshControl();
    PrepareForDrawing();
  }
}

// FUNCTION: IMPERIALISM 0x00592830
void TTransportPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  Refresh();
}
