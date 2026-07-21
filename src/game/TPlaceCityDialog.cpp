#include "game/TPlaceCityDialog.h"

#include "game/TNumberedItem.h"
#include "game/TPicture.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTown.h"
#include "game/TUpDownPictureButton.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004d1760
// TPlaceCityDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d17e0
// TPlaceCityDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPlaceCityDialog, TPicture)

// FUNCTION: IMPERIALISM 0x004d1800
TPlaceCityDialog::TPlaceCityDialog() {}

// SYNTHETIC: IMPERIALISM 0x004d1830
// TPlaceCityDialog::`scalar deleting destructor'
TPlaceCityDialog::~TPlaceCityDialog() {}

// FUNCTION: IMPERIALISM 0x004d1880
void TPlaceCityDialog::StuffValues(TTown* town) {
  town90 = town;
  town->CalculateCityResources();

  short visibleResourceCount = 0;
  for (int resource = 0; resource < 0x17; ++resource) {
    if (town->resourceYieldByType[resource] != 0) {
      ++visibleResourceCount;
    }
  }

  int extraHeight =
      static_cast<short>(((visibleResourceCount * 0x2c) / (frameWidth34 - 0x20) + 1) * 0x20);

  TView* owner = OwnerPanel();
  if (owner == 0) {
    FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, 0xdd6);
  } else {
    CRect ownerBounds;
    owner->QueryBounds(&ownerBounds);
    ownerBounds.bottom += extraHeight;
    owner->ApplyBounds(&ownerBounds, 1);
  }

  CRect dialogBounds;
  QueryBounds(&dialogBounds);
  dialogBounds.bottom += extraHeight;
  ApplyBounds(&dialogBounds, 1);

  const unsigned int buttonTags[2] = {0x636e636cu, 0x6f6b6179u}; // 'cncl', 'okay'
  const int buttonAssertLines[2] = {0xde2, 0xde8};
  for (int buttonIndex = 0; buttonIndex < 2; ++buttonIndex) {
    // Startup.rsrc:953 declares both 'cncl' and 'okay' as TUpDownPictureButton.
    TUpDownPictureButton* button =
        static_cast<TUpDownPictureButton*>(ResolveControlByTag(buttonTags[buttonIndex]));
    if (button == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, buttonAssertLines[buttonIndex]);
      continue;
    }
    CRect buttonBounds;
    button->QueryBounds(&buttonBounds);
    OffsetRect(&buttonBounds, 0, extraHeight);
    button->ApplyBounds(&buttonBounds, 1);
  }

  short x = static_cast<short>(frameWidth34);
  short y = 0x50;
  for (short resourceIndex = 0; resourceIndex < 0x17; ++resourceIndex) {
    short count = town->resourceYieldByType[resourceIndex];
    if (count == 0) {
      continue;
    }

    x = static_cast<short>(x + 0x2c);
    if (x > frameWidth34 - 0x10) {
      x = 0x10;
      y = static_cast<short>(y + 0x20);
    }

    TNumberedItem* item = new TNumberedItem();
    int position[2] = {x, y};
    int size[2] = {0x2c, 0x20};
    item->InitializeNumberedResourceItem(this, position, size, resourceIndex, count);
  }

  short primaryFood = town->resourceYieldByType[0x11];
  short secondaryFood = town->resourceYieldByType[0x12];
  short alternateFood =
      static_cast<short>(town->resourceYieldByType[0x13] + town->resourceYieldByType[0x14]);
  short totalFood = static_cast<short>(primaryFood + secondaryFood + alternateFood);
  short sustainablePopulation = 0;
  for (int unit = 0; unit < totalFood; ++unit) {
    short* foodPool = &primaryFood;
    if (unit % 4 == 1) {
      foodPool = &secondaryFood;
    } else if (unit % 4 == 3) {
      foodPool = &alternateFood;
    }
    if (*foodPool != 0) {
      --*foodPool;
      ++sustainablePopulation;
    }
  }

  CString sustainableText;
  CString totalText;
  CString templateText;
  CString summaryText;
  sustainableText.Format(g_szDecimalFormat, static_cast<int>(sustainablePopulation));
  totalText.Format(g_szDecimalFormat, static_cast<int>(totalFood));
  g_pSimMgr->GetString(0x273f, 5, &templateText);
  scanBracketExpressions(g_pSimMgr, &summaryText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(sustainableText), static_cast<LPCSTR>(totalText));

  TStaticText* sustainability =
      static_cast<TStaticText*>(ResolveControlByTag(0x73757374u)); // 'sust'
  sustainability->SetTextAndMaybeRefresh(&summaryText, 1);
  TUiTextStyleDescriptor style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);
  sustainability->SetTextStyleAndMaybeRefresh(&style, 0);

  TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(0x7469746cu)); // 'titl'
  title->AssertValid();
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b6a);
  title->SetTextStyleAndMaybeRefresh(&style, 0);
  g_pSimMgr->GetString(0x273f, 7, &templateText);
  title->SetTextAndMaybeRefresh(&templateText, 1);
}

// FUNCTION: IMPERIALISM 0x004d1e40
void TPlaceCityDialog::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x004d1e60
void TPlaceCityDialog::Close() {
  TView::Close();
}
