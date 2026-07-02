#include "game/TCouncilTickerAnimation.h"

#include "game/TCivAnimation2.h"
#include "game/TControl.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TPicture.h"
#include "game/TStaticText.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/TDiplomacyMgr.h"
#include "game/TSimMgr.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

void __cdecl BuildUiTextStyleDescriptor(void* styleDescriptor, int unused, int arg2,
                                        int stylePrimary);

namespace {
const short kCouncilCoatOfArmsPictureBase = 0x1105;
const short kCouncilTickerIntervalMapMode = 0x2710;
const unsigned int kEndControlTagReselect = 0x52655374u;    // mode 0x17
const unsigned int kEndControlTagReselectAlt = 0x53636f72u; // mode 0x16

TView* CouncilHostPanel(TCouncilTickerAnimation* panelToken) {
  return static_cast<TView*>(static_cast<void*>(panelToken));
}

char* CouncilHostPanelBytes(TCouncilTickerAnimation* panelToken) {
  return reinterpret_cast<char*>(CouncilHostPanel(panelToken));
}

void ApplyCouncilCandidateTextStyle(TStaticText* textControl,
                                    const TControlPictureRectState* style) {
  textControl->SetCityProductionDialogPictureRectAndMaybeRefresh(
      const_cast<TControlPictureRectState*>(style), 0);
}

void RefreshCouncilCandidateNameText(TView* hostPanel, unsigned int controlTag, short nationSlot) {
  TControl* control = hostPanel->ResolveControlByTag(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();

  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == nullptr) {
    return;
  }

  CString labelText;
  nation->LoadNationDisplayNameSharedRefFromField8(&labelText);
  TStaticText* textControl = static_cast<TStaticText*>(control);
  textControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&labelText, 1);
}

void RefreshCouncilCoatOfArmsPicture(TView* hostPanel, unsigned int controlTag, short nationSlot) {
  TControl* control = hostPanel->ResolveControlByTag(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  const short pictureId = static_cast<short>(nationSlot + kCouncilCoatOfArmsPictureBase);
  static_cast<TPicture*>(control)->SetPictureResourceIdAndRefresh(pictureId, 1);
}
} // namespace

// SYNTHETIC: IMPERIALISM 0x0049ff20
// TCouncilTickerAnimation::`scalar deleting destructor'
TCouncilTickerAnimation::~TCouncilTickerAnimation() {}
// SYNTHETIC: IMPERIALISM 0x0049fef0
// TCouncilTickerAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049ff70
// TCouncilTickerAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCouncilTickerAnimation, TAnimation)

TCouncilTickerAnimation::TCouncilTickerAnimation() {}

// FUNCTION: IMPERIALISM 0x0049ff90
void TCouncilTickerAnimation::ConstructTCouncilTickerAnimationBaseState(void* hostPanel,
                                                                        int tickMode) {
  char* objectBytes = reinterpret_cast<char*>(this);
  *reinterpret_cast<void**>(objectBytes + 0x4) = hostPanel;
  *reinterpret_cast<unsigned short*>(objectBytes + 0x8) = 0;
  *reinterpret_cast<unsigned short*>(objectBytes + 0xa) = 0;
  *reinterpret_cast<unsigned short*>(objectBytes + 0xc) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x10) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x14) = static_cast<unsigned int>(tickMode);
  *reinterpret_cast<unsigned int*>(objectBytes + 0x18) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x1c) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x20) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x24) = 0;
  *reinterpret_cast<unsigned int*>(objectBytes + 0x28) = 0;
}

// FUNCTION: IMPERIALISM 0x0049ffe0
undefined TCouncilTickerAnimation::WrapperFor_InvalidateCityDialogRectRegion_At0049f140() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fc2e0
void TCouncilTickerAnimation::InitializeDiplomacyCouncilViewControlsAndTicker() {
  TView* hostPanel = CouncilHostPanel(this);
  char* panelState = CouncilHostPanelBytes(this);

  TControlPictureRectState councilTextStyle;
  councilTextStyle.mode = 0;
  councilTextStyle.flag2 = 0;
  councilTextStyle.pointSize = 0;
  councilTextStyle.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&councilTextStyle, 0, 0xe, 0x2b6a);

  *reinterpret_cast<short*>(panelState + 0x24c8) = 0;

  RefreshCouncilCandidateNameText(hostPanel, kControlTagCan0,
                                  g_pDiplomacyTurnStateManager->selectedSourceNationSlot784);
  TControl* can0Control = hostPanel->ResolveControlByTag(kControlTagCan0);
  if (can0Control != nullptr) {
    ApplyCouncilCandidateTextStyle(static_cast<TStaticText*>(can0Control), &councilTextStyle);
  }

  RefreshCouncilCandidateNameText(hostPanel, kControlTagCan1,
                                  g_pDiplomacyTurnStateManager->selectedTargetNationSlot786);
  TControl* can1Control = hostPanel->ResolveControlByTag(kControlTagCan1);
  if (can1Control != nullptr) {
    ApplyCouncilCandidateTextStyle(static_cast<TStaticText*>(can1Control), &councilTextStyle);
  }

  RefreshCouncilCoatOfArmsPicture(hostPanel, kControlTagCoa0,
                                  g_pDiplomacyTurnStateManager->selectedSourceNationSlot784);
  RefreshCouncilCoatOfArmsPicture(hostPanel, kControlTagCoa1,
                                  g_pDiplomacyTurnStateManager->selectedTargetNationSlot786);

  const short localizationMode = static_cast<short>(g_pLocalizationTable->mode);
  if (localizationMode == 0x16 || localizationMode == 0x17) {
    const char* tileRecordBytes = reinterpret_cast<const char*>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10));
    int flagIndex = 0;
    for (int tileOffset = 0; tileOffset < 0xfc00; tileOffset += 0xa8) {
      if (tileRecordBytes[tileOffset] != -1) {
        panelState[0x52c + flagIndex] = 1;
      }
      ++flagIndex;
    }
    *reinterpret_cast<short*>(panelState + 0x528) = kCouncilTickerIntervalMapMode;

    TControl* endControl = hostPanel->ResolveControlByTag(kControlTagEnd);
    if (endControl != nullptr) {
      endControl->AssertValid();
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(endControl) + 0x1c) =
          (localizationMode == 0x17) ? kEndControlTagReselect : kEndControlTagReselectAlt;
    }
    return;
  }

  short maxPendingTier = *reinterpret_cast<short*>(panelState + 0x24c8);
  short* tierScan =
      reinterpret_cast<short*>(reinterpret_cast<char*>(g_pDiplomacyTurnStateManager) + 0x484);
  const int tierCount = (0x784 - 0x484) / static_cast<int>(sizeof(short));
  for (int tierIndex = 0; tierIndex < tierCount; ++tierIndex) {
    const short tierValue = tierScan[tierIndex];
    if (tierValue != -1 && maxPendingTier < tierValue) {
      maxPendingTier = tierValue;
    }
  }
  *reinterpret_cast<short*>(panelState + 0x24c8) = maxPendingTier;
  *reinterpret_cast<short*>(panelState + 0x528) = 0;

  TCouncilTickerAnimation* tickerAnimation = new TCouncilTickerAnimation();
  if (tickerAnimation != nullptr) {
    tickerAnimation->ConstructTCouncilTickerAnimationBaseState(hostPanel, 2);
    if (g_pUiAnimator != nullptr) {
      TCivAnimation2* civAnimator = static_cast<TCivAnimation2*>(static_cast<void*>(g_pUiAnimator));
      civAnimator->AddObjectToUiTransientRegistry(tickerAnimation);
    }
  }

  SetCursor(static_cast<HCURSOR>(g_pUiRuntimeContext->cursorTable[26]));

  TControl* endControl = hostPanel->ResolveControlByTag(kControlTagEnd);
  if (endControl != nullptr) {
    endControl->AssertValid();
    endControl->SetState(0, 0);
  }
}
