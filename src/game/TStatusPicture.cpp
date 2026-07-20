#include "game/TStatusPicture.h"

#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TInfoBarText.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TViewMgr.h"
#include "game/UiRuntimeContext.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043d870
// TStatusPicture::`scalar deleting destructor'
TStatusPicture::~TStatusPicture() {}
// SYNTHETIC: IMPERIALISM 0x00593e80
// TStatusPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00593f00
// TStatusPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TStatusPicture, TPicture)

TStatusPicture::TStatusPicture() {}

// FUNCTION: IMPERIALISM 0x00593f20
void TStatusPicture::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  // One TPicture child per eligible nation slot ('pic0'-'pic6'); the picture tag only
  // advances on rows that actually get a child (ineligible rows are skipped without
  // consuming a tag), matching the original's separate row/tag counters.
  unsigned int pictureTag = 0x70696330u; // 'pic0'
  int rowY = 0x50;
  for (unsigned int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(nationSlot)) != 0) {
      TPicture* picture = new TPicture();
      int offsetLayout[2] = {0x71, rowY};
      int sizeLayout[2] = {0x23, 0x34};
      picture->InitializePictureEntryBaseAndRefresh(
          this, offsetLayout, sizeLayout, 5, 5, static_cast<short>(nationSlot + 0x10d7));
      picture->controlTag = pictureTag;
      rowY += 0x37;
      ++pictureTag;
    }
  }

  for (unsigned int tabIndex = 0; tabIndex < 10; ++tabIndex) {
    TView* tabControl = ResolveControlByTag(0x74616230u + tabIndex); // 'tab0'-'tab9'
    LoadUiStringByGroupAndIndexToControlObject(0x2757, static_cast<short>(tabIndex + 9),
                                               tabControl);
  }
  ApplySharedStringToGlobalControlTag(g_pStatusPictureMainSharedText_00668b88, kControlTagMain);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0xd, ResolveControlByTag(kControlTagEnd));
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, ResolveControlByTag(kControlTagQuer));

  comparisonMode90 = 0;
  RefreshControl();
  g_pDiplomacyTurnStateManager->RecomputeNationComparativePowerMetrics();

  // Same per-nation average as HandleEvent's commandId==10/newIndex==0 branch (identical
  // instruction sequence): sums 4 dip[0x1824+i*0x10] dwords; the *400/40 magic-number scale
  // cancels to a plain 16-bit truncation, verified by simulation.
  {
    char* dip = reinterpret_cast<char*>(g_pDiplomacyTurnStateManager);
    int dipOffset = 0;
    for (int i = 0; i < 7; ++i, dipOffset += 0x10) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(i)) != 0) {
        int sum = *reinterpret_cast<int*>(dip + 0x1824 + dipOffset) +
                  *reinterpret_cast<int*>(dip + 0x1828 + dipOffset) +
                  *reinterpret_cast<int*>(dip + 0x182c + dipOffset) +
                  *reinterpret_cast<int*>(dip + 0x1830 + dipOffset);
        values94[i] = static_cast<short>(sum);
        pictureIds_b0[i] = static_cast<short>(i);
      } else {
        pictureIds_b0[i] = -1;
      }
    }
  }
  SortSevenEntriesAndUpdatePictureWidgets();

  // 'curs' is also installed as the shared cursor-hint panel, same as 'labl' in
  // TLoungeDialog::NoOpUiLifecycleHook.
  TInfoBarText* cursControl = static_cast<TInfoBarText*>(ResolveControlByTag(0x63757273u));
  g_pCursorControlPanel = cursControl;
  cursControl->AssertValid();
  cursControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
}

// FUNCTION: IMPERIALISM 0x005942f0
void TStatusPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= 0x74616230u /* 'tab0' */ && tag <= 0x74616239u /* 'tab9' */) {
      int newIndex = static_cast<int>(tag - 0x74616230u);
      if (newIndex != comparisonMode90) {
        TView* newTab = ResolveControlByTag(0x74616230u + newIndex);
        newTab->AssertValid();
        newTab->SetEnabled(0, 1);
        static_cast<TView*>(sourceHandler)->AssertValid();
        static_cast<TView*>(sourceHandler)->SetEnabled(1, 1);
        g_pSfxPlaybackSystem->PlaySoundEffect(0x13f0, 0, 1);
        comparisonMode90 = newIndex;
        if (newIndex == 0) {
          g_pDiplomacyTurnStateManager->RecomputeNationComparativePowerMetrics();
          char* dip = reinterpret_cast<char*>(g_pDiplomacyTurnStateManager);
          int dipOffset = 0;
          for (int i = 0; i < 7; ++i, dipOffset += 0x10) {
            if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(i)) != 0) {
              int sum = *reinterpret_cast<int*>(dip + 0x1824 + dipOffset) +
                        *reinterpret_cast<int*>(dip + 0x1828 + dipOffset) +
                        *reinterpret_cast<int*>(dip + 0x182c + dipOffset) +
                        *reinterpret_cast<int*>(dip + 0x1830 + dipOffset);
              // The original scales this sum by 400 then divides by 40 via a magic-number
              // sequence; verified by simulation that the two cancel exactly for every
              // 16-bit-range input, so the net effect is a plain (sign-extending) truncation
              // to 16 bits.
              values94[i] = static_cast<short>(sum);
              pictureIds_b0[i] = static_cast<short>(i);
            } else {
              pictureIds_b0[i] = -1;
            }
          }
          SortSevenEntriesAndUpdatePictureWidgets();
        } else {
          RecomputeNationComparisonValuesAndNormalizeScale();
        }
      } else if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0) {
        // Already-selected tab, shift-held: a debug shortcut into the help-index records.
        unsigned int tag = sourceHandler->controlTag;
        int idx;
        if (tag == 0x74616231u) { // 'tab1'
          idx = 2;
        } else if (tag == 0x74616232u) { // 'tab2'
          idx = 0;
        } else if (tag == 0x74616233u) { // 'tab3'
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
  TPicture::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00594540
void TStatusPicture::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);

  CString title;
  g_pSimMgr->GetString(0x2757, static_cast<short>(comparisonMode90) + 8, &title);
  ApplyUiTextStyleAndSyncColor(0, 0xe, 0x2b6a);
  short titleWidth = MeasureTextExtentWithCachedQuickDrawStyle(&title);
  SetQuickDrawTextOriginWithContextOffset(0x140 - titleWidth / 2, 0x3c);
  DrawTextWithCachedStyle(&title);

  int rowY = 100;
  for (int i = 0; i < 7; ++i, rowY += 0x37) {
    if (pictureIds_b0[i] == -1) {
      continue;
    }
    CString label;
    g_apNationStates[pictureIds_b0[i]]->FormatOverlayTerrainLabelText(&label);
    ApplyUiTextStyleAndSyncColor(0, 0xc, 0x2b6a);
    SetQuickDrawTextOriginWithContextOffset(0x9a, rowY - 8);
    DrawTextWithCachedStyle(&label);

    // Horizontal score bar for this row: filled once in fill color 0, then re-filled one
    // pixel up/left in the nation's turn-event palette color for a 1px drop-shadow effect.
    RECT swatch = {0x98, rowY + 1, static_cast<short>(values94[i]) + 0x98, rowY + 13};
    SetQuickDrawFillColor(0);
    FillRectWithQuickDrawBrushAndContextOffset(&swatch);
    OffsetRect(&swatch, -1, -1);
    g_pUiRuntimeContext->ApplyTurnEventPaletteColorByEventCode(pictureIds_b0[i]);
    FillRectWithQuickDrawBrushAndContextOffset(&swatch);
  }
}

// Fills values94[nation] with the per-nation metric selected by comparisonMode90 (and
// pictureIds_b0[nation] with the nation slot, or -1 when the slot is ineligible), sorts the
// seven entries, then rescales them so the largest is at most 400.
// FUNCTION: IMPERIALISM 0x00594900
void TStatusPicture::RecomputeNationComparisonValuesAndNormalizeScale() {
  int dipOffset = 0;
  for (int i = 0; i < 7; ++i, dipOffset += 0x10) {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(i)) != '\0') {
      TGreatPower* nation = g_apNationStates[i];
      char* dip = reinterpret_cast<char*>(g_pDiplomacyTurnStateManager);
      char* raw = reinterpret_cast<char*>(nation);
      switch (comparisonMode90) {
      case 1:
        values94[i] = *reinterpret_cast<int*>(dip + 0x1830 + dipOffset) * 3;
        break;
      case 2:
        values94[i] = *reinterpret_cast<int*>(dip + 0x1828 + dipOffset) * 3;
        break;
      case 3:
        values94[i] = *reinterpret_cast<int*>(dip + 0x1824 + dipOffset) * 3;
        break;
      case 4:
        values94[i] = static_cast<int>(*reinterpret_cast<short*>(raw + 0xa4)) << 2;
        break;
      case 5:
        values94[i] = *reinterpret_cast<int*>(raw + 0x910) << 2;
        break;
      case 6: {
        TCity* city = (nation == nullptr) ? nullptr : nation->city;
        values94[i] = *reinterpret_cast<int*>(reinterpret_cast<char*>(city) + 0x78);
        break;
      }
      case 7: {
        TCity* city = (nation == nullptr) ? nullptr : nation->city;
        int stats = *reinterpret_cast<int*>(reinterpret_cast<char*>(city) + 0x1d8);
        int units = *reinterpret_cast<int*>(stats + 0x14);
        values94[i] =
            static_cast<int>(static_cast<short>(
                (*reinterpret_cast<short*>(units + 8) * 2 + *reinterpret_cast<short*>(units + 6)) *
                    2 +
                *reinterpret_cast<short*>(stats + 0x1e) + *reinterpret_cast<short*>(units + 4)))
            << 2;
        break;
      }
      case 8:
        values94[i] = *reinterpret_cast<int*>(raw + 0x914) / 10;
        break;
      case 9:
        values94[i] = (nation == nullptr) ? 0 : static_cast<int>(nation->needCapA6) << 1;
        break;
      default:
        break;
      }
      pictureIds_b0[i] = static_cast<short>(i);
    } else {
      pictureIds_b0[i] = -1;
    }
  }

  SortSevenEntriesAndUpdatePictureWidgets();

  int maxVal = values94[0];
  if (maxVal > 400) {
    values94[0] = 400;
    for (int k = 1; k < 7; ++k) {
      if (pictureIds_b0[k] != -1) {
        values94[k] = (values94[k] * 400) / maxVal;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00594c00
void TStatusPicture::SortSevenEntriesAndUpdatePictureWidgets() {
  // Selection sort: move the highest-value entry with a live id to the front on each pass;
  // empty (-1) ids sink toward the end.
  int* valOuter = values94;
  short* idOuter = pictureIds_b0;
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
        idInner = idInner + 1;
        valInner = valInner + 1;
        remaining = remaining - 1;
      } while (remaining != 0);
    }
    idOuter = idOuter + 1;
    valOuter = valOuter + 1;
    outer = outer + 1;
  } while (outer < 7);

  // Push each sorted entry's picture id into its child picture widget.
  short* idPtr = pictureIds_b0;
  int index = 0;
  do {
    if (*idPtr != -1) {
      TPicture* widget = static_cast<TPicture*>(ResolveControlByTag(index + 0x70696330));
      widget->AssertValid();
      widget->SetPictureResourceIdAndRefresh(static_cast<short>(*idPtr + 0x10d7), true);
    }
    index = index + 1;
    idPtr = idPtr + 1;
  } while (index < 7);
}
