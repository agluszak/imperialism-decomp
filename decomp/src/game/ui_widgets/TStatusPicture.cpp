#include "game/ui_widgets/TStatusPicture.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TViewMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0043d840
TStatusPicture::TStatusPicture() {
  comparisonMode = -1;
}

// FUNCTION: IMPERIALISM 0x0043d8a0
TStatusPicture::~TStatusPicture() {}

IMPLEMENT_DYNCREATE(TStatusPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00593f20
void TStatusPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  unsigned int pictureTag = kControlTagArmyPlacardFirst; // 'pic0'
  int rowY = 0x50;
  for (unsigned int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(nationSlot))) {
      TPicture* picture = new TPicture();
      int offsetLayout[2] = {0x71, rowY};
      int sizeLayout[2] = {0x23, 0x34};
      picture->IPicture(this, offsetLayout, sizeLayout, 5, 5,
                        static_cast<short>(nationSlot + 0x10d7));
      picture->controlTag = pictureTag;
      rowY += 0x37;
      ++pictureTag;
    }
  }

  for (unsigned int tabIndex = 0; tabIndex < 10; ++tabIndex) {
    TView* tabControl = ResolveControlByTag(kControlTagTab0 + tabIndex); // 'tab0'-'tab9'
    LoadUiStringByGroupAndIndexToControlObject(0x2757, static_cast<short>(tabIndex + 9),
                                               tabControl);
  }
  ApplySharedStringToGlobalControlTag(g_pStatusPictureMainSharedText, kControlTagMain);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xd, ResolveControlByTag(kControlTagEnd));
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, ResolveControlByTag(kControlTagQuer));

  comparisonMode = 0;
  RefreshControl();
  CalcStandardGraph();

  TInfoBarText* cursControl = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel = cursControl;
  cursControl->AssertValid();
  cursControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// FUNCTION: IMPERIALISM 0x005941e0
void TStatusPicture::SwitchStatusMode(int comparisonMode) {
  this->comparisonMode = comparisonMode;
  RefreshControl();
  if (comparisonMode == 0) {
    CalcStandardGraph();
    return;
  }
  RecomputeNationComparisonValuesAndNormalizeScale();
}

// FUNCTION: IMPERIALISM 0x005942f0
void TStatusPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagTab0 && tag <= kControlTagTab9) {
      int newIndex = static_cast<int>(tag - kControlTagTab0);
      if (newIndex != comparisonMode) {
        TView* newTab = ResolveControlByTag(kControlTagTab0 + newIndex);
        newTab->AssertValid();
        newTab->Show(0, 1);
        static_cast<TView*>(sourceHandler)->AssertValid();
        static_cast<TView*>(sourceHandler)->Show(1, 1);
        g_pSfxPlaybackSystem->PlaySoundEffect(0x13f0, 0, 1);
        comparisonMode = newIndex;
        if (newIndex == 0) {
          CalcStandardGraph();
        } else {
          RecomputeNationComparisonValuesAndNormalizeScale();
        }
      } else if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0) {
        // Already-selected tab, shift-held: a debug shortcut into the help-index records.
        unsigned int tag = sourceHandler->controlTag;
        int idx;
        if (tag == kControlTagTab1) { // 'tab1'
          idx = 2;
        } else if (tag == kControlTagTab2) { // 'tab2'
          idx = 0;
        } else if (tag == kControlTagTab3) { // 'tab3'
          idx = 1;
        } else {
          idx = -1;
        }
        if (idx != -1) {
          g_pHelpMgr->SelectAndActivatePendingEventTypeOffsetFrom1A0B(idx);
        }
      }
    }
  }
  TPicture::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00594540
void TStatusPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);

  CString title;
  g_pSimMgr->GetString(0x2757, static_cast<short>(comparisonMode) + 8, &title);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xe, 0x2b6a);
  short titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&title);
  SetQuickDrawTextOriginWithContextOffset(0x140 - titleWidth / 2, 0x3c);
  DrawTextWithCachedQuickDrawStyleState(&title);

  int rowY = 100;
  for (int i = 0; i < 7; ++i, rowY += 0x37) {
    if (pictureIds[i] == -1) {
      continue;
    }
    CString label;
    g_apNationStates[pictureIds[i]]->FormatOverlayTerrainLabelText(&label);
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b6a);
    SetQuickDrawTextOriginWithContextOffset(0x9a, rowY - 8);
    DrawTextWithCachedQuickDrawStyleState(&label);

    RECT swatch = {0x98, rowY + 1, static_cast<short>(values[i]) + 0x98, rowY + 13};
    SetQuickDrawFillColor(0);
    FillRectWithQuickDrawBrushAndContextOffset(&swatch);
    OffsetRect(&swatch, -1, -1);
    g_pViewMgr->SetForeColor(static_cast<short>(pictureIds[i]));
    FillRectWithQuickDrawBrushAndContextOffset(&swatch);
  }
}

// FUNCTION: IMPERIALISM 0x00594790
void TStatusPicture::DrawBar(short rowY, short width, short nationSlot) {
  RECT swatch = {0x98, rowY + 1, width + 0x98, rowY + 13};
  SetQuickDrawFillColor(0);
  FillRectWithQuickDrawBrushAndContextOffset(&swatch);
  OffsetRect(&swatch, -1, -1);
  g_pViewMgr->SetForeColor(nationSlot);
  FillRectWithQuickDrawBrushAndContextOffset(&swatch);
}

// FUNCTION: IMPERIALISM 0x00594900
void TStatusPicture::RecomputeNationComparisonValuesAndNormalizeScale() {
  for (int i = 0; i < 7; ++i) {
    if (g_pSimMgr->ReallyInTheGame(static_cast<short>(i))) {
      TGreatPower* nation = g_apNationStates[i];
      switch (comparisonMode) {
      case 1:
        values[i] = g_pDiplomacyTurnStateManager->comparativePowerRows[i][3] * 3;
        break;
      case 2:
        values[i] = g_pDiplomacyTurnStateManager->comparativePowerRows[i][1] * 3;
        break;
      case 3:
        values[i] = g_pDiplomacyTurnStateManager->comparativePowerRows[i][0] * 3;
        break;
      case 4:
        values[i] = static_cast<int>(nation->merchantCapacity) << 2;
        break;
      case 5:
        values[i] = nation->specialResourceTradeBalance << 2;
        break;
      case 6: {
        TCity* city = (nation == nullptr) ? nullptr : nation->city;
        values[i] = city->rollingItemProductionScore;
        break;
      }
      case 7: {
        TCity* city = (nation == nullptr) ? nullptr : nation->city;
        TPopulationMgr* stats = city->productionSummary;
        TLaborPool* units = stats->productionSlots;
        values[i] = static_cast<short>((units->highSkillCount * 2 + units->mediumSkillCount) * 2 +
                                       stats->extraAt1e + units->lowSkillCount)
                    << 2;
        break;
      }
      case 8:
        values[i] = nation->aidAllocationTotal / 10;
        break;
      case 9:
        values[i] = (nation == nullptr) ? 0 : static_cast<int>(nation->transportCapacity) << 1;
        break;
      default:
        break;
      }
      pictureIds[i] = static_cast<short>(i);
    } else {
      pictureIds[i] = -1;
    }
  }

  SortSevenEntriesAndUpdatePictureWidgets();

  NormalizeAsNeeded();
}

// FUNCTION: IMPERIALISM 0x00594c00
void TStatusPicture::SortSevenEntriesAndUpdatePictureWidgets() {
  int* valOuter = values;
  short* idOuter = pictureIds;
  int outer = 1;
  do {
    if (outer < 7) {
      int* valInner = valOuter + 1;
      short* idInner = idOuter + 1;
      int remaining = 7 - outer;
      do {
        if (*idInner != -1) {
          short outerId = *idOuter;
          if (outerId == -1 || *valInner > *valOuter) {
            *idOuter = *idInner;
            *idInner = outerId;
            int outerVal = *valOuter;
            *valOuter = *valInner;
            *valInner = outerVal;
          }
        }
        ++idInner;
        ++valInner;
        --remaining;
      } while (remaining != 0);
    }
    ++idOuter;
    ++valOuter;
    ++outer;
  } while (outer < 7);

  // Push each sorted entry's picture id into its child picture widget.
  short* idPtr = pictureIds;
  int index = 0;
  do {
    if (*idPtr != -1) {
      TPicture* widget =
          static_cast<TPicture*>(ResolveControlByTag(index + kControlTagArmyPlacardFirst));
      widget->AssertValid();
      widget->SetPictureRsrcID(static_cast<short>(*idPtr + 0x10d7), true);
    }
    ++index;
    ++idPtr;
  } while (index < 7);
}
