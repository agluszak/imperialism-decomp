#include "game/TGPCheater.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TNumberText.h"
#include "game/globals/shared_globals.h"
#include "game/globals/prelude.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x004b1710
void TGPCheater::ConstructNumericEntryDialogCoreAndValueLabel(int* offsetLayout, int param2,
                                                              short value, int param4) {
  int valueFieldSize[2] = {0x20, 0x16};
  TNumberText* valueField = new TNumberText();
  valueField->InitializeNumberText(this, offsetLayout, valueFieldSize, value, 0xffff8ad0, 3000);

  int captionSize[2] = {0x80, 0x18};
  int captionOffset[2] = {offsetLayout[0] + 0xac, offsetLayout[1]};
  TStaticText* caption = new TStaticText();
  caption->InitializeTextEntryBaseAndOptionalStringResource(this, captionOffset, captionSize, 5, 5,
                                                            static_cast<short>(field60), 0x18);
}
// SYNTHETIC: IMPERIALISM 0x004b19b0
// TGPCheater::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b1a20
// TGPCheater::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b1a50
TGPCheater::~TGPCheater() {}

// SYNTHETIC: IMPERIALISM 0x004b1a70
// TGPCheater::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGPCheater, TCheater)

// NOOP: verified empty in original 0x004b19e3 (no standalone TGPCheater::TGPCheater body exists: CreateObject 0x004b19b0 inlines this default ctor, calling the TView base ctor directly at that site)
TGPCheater::TGPCheater() {}

// FUNCTION: IMPERIALISM 0x004b1a90
void TGPCheater::ConstructTGPCheaterBaseState(TView* panel) {
  ConstructTCheaterBaseState(panel, 0x2728);

  int nameOffset[2] = {0, 0};
  int nameSize[2] = {4, 0x20};
  TStaticText* nameCaption = new TStaticText();
  nameCaption->InitializeTextEntryBaseAndOptionalStringResource(this, nameOffset, nameSize, 5, 5,
                                                                -1, 0);

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
void TGPCheater::RefreshGPCheaterNationValues(int nationSlot) {
  TGreatPower* nation = g_apNationStates[nationSlot];
  CString nameText;

  TStaticText* name =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'a', 'm', 'e')));
  if (name == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  nation->FormatOverlayTerrainLabelText(&nameText);
  name->SetTextAndMaybeRefresh(&nameText, 1);

  TNumberText* treasury =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'r', 'e', 'a')));
  if (treasury == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  treasury->SetControlValue(nation->treasuryValue10, 1);

  TNumberText* mercenaries =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('m', 'e', 'r', 'c')));
  if (mercenaries == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  mercenaries->SetControlValue(nation->tradeCapacity, 1);

  TNumberText* tradeCap =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('t', 'c', 'a', 'p')));
  if (tradeCap == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  tradeCap->SetControlValue(nation != nullptr ? nation->needCapA6 : 0, 1);

  TNumberText* sale =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('s', 'a', 'l', 'e')));
  if (sale == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  sale->SetControlValue(nation->budgetPoolBase, 1);

  TNumberText* purchase =
      static_cast<TNumberText*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'u', 'r', 'c')));
  if (purchase == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  purchase->SetControlValue(nation->budgetPoolDelta, 1);
}
