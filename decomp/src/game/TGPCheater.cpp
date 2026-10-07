#include "game/TGPCheater.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TNumberText.h"
#include "game/globals/shared_globals.h"
#include "game/globals/global_types.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x004b1710
void TGPCheater::ConstructNumericEntryDialogCoreAndValueLabel(int* offsetLayout, int fieldIndex,
                                                              short value, int fieldTag) {
  int valueFieldSize[2] = {0x20, 0x16};
  TNumberText* valueField = new TNumberText();
  valueField->INumberText(this, offsetLayout, valueFieldSize, value, 0xffff8ad0, 3000);

  int captionSize[2] = {0x80, 0x18};
  int captionOffset[2] = {offsetLayout[0] + 0xac, offsetLayout[1]};
  TStaticText* caption = new TStaticText();
  caption->IStaticText(this, captionOffset, captionSize, 5, 5,
                       static_cast<short>(captionStringResourceGroup), 0x18);
}

// FUNCTION: IMPERIALISM 0x004b1a50
TGPCheater::~TGPCheater() {}

IMPLEMENT_DYNCREATE(TGPCheater, TCheater)

// FUNCTION: IMPERIALISM 0x004b1a90
void TGPCheater::IGPCheater(TView* panel) {
  ICheater(panel, 0x2728);

  int nameOffset[2] = {0, 0};
  int nameSize[2] = {4, 0x20};
  TStaticText* nameCaption = new TStaticText();
  nameCaption->IStaticText(this, nameOffset, nameSize, 5, 5, -1, 0);

  int rowLayout[2];
  rowLayout[0] = 0;
  rowLayout[1] = 0x40;
  ConstructNumericEntryDialogCoreAndValueLabel(rowLayout, 0, 0,
                                               IMPERIALISM_FOURCC('t', 'r', 'e', 'a'));
  rowLayout[1] = 0x58;
  ConstructNumericEntryDialogCoreAndValueLabel(rowLayout, 3, 0,
                                               IMPERIALISM_FOURCC('m', 'e', 'r', 'c'));
  rowLayout[1] = 0x70;
  ConstructNumericEntryDialogCoreAndValueLabel(rowLayout, 4, 0,
                                               IMPERIALISM_FOURCC('t', 'c', 'a', 'p'));
  rowLayout[1] = 0x88;
  ConstructNumericEntryDialogCoreAndValueLabel(rowLayout, 5, 0,
                                               IMPERIALISM_FOURCC('s', 'a', 'l', 'e'));
  rowLayout[1] = 0x9e;
  ConstructNumericEntryDialogCoreAndValueLabel(rowLayout, 6, 0,
                                               IMPERIALISM_FOURCC('p', 'u', 'r', 'c'));
}

// FUNCTION: IMPERIALISM 0x004b1cb0
void TGPCheater::DisplayGP(int nationSlot) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  CString nameText;

  TStaticText* name =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  if (name == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xec);
  }
  nation->FormatOverlayTerrainLabelText(&nameText);
  name->SetTextAndMaybeRefresh(&nameText, true);

  TNumberText* treasury =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'r', 'e', 'a')));
  if (treasury == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xf2);
  }
  treasury->SetControlValue(nation->treasuryValue, 1);

  TNumberText* mercenaries =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('m', 'e', 'r', 'c')));
  if (mercenaries == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xf5);
  }
  mercenaries->SetControlValue(nation->merchantCapacity, 1);

  TNumberText* tradeCap =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'c', 'a', 'p')));
  if (tradeCap == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xf8);
  }
  tradeCap->SetControlValue(nation != NULL ? nation->transportCapacity : 0, 1);

  TNumberText* sale =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('s', 'a', 'l', 'e')));
  if (sale == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xfb);
  }
  sale->SetControlValue(nation->budgetPoolBase, 1);

  TNumberText* purchase =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'u', 'r', 'c')));
  if (purchase == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCheaters.cpp", 0xfe);
  }
  purchase->SetControlValue(nation->budgetPoolDelta, 1);
}
