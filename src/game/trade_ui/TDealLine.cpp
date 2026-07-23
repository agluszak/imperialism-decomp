#include "game/trade_ui/TDealLine.h"

#include "game/ui_screens/CString.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TMyStaticText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x005c0cf0
// TDealLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c0d60
// TDealLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealLine, TLineData)

// FUNCTION: IMPERIALISM 0x005c0d80
TDealLine::TDealLine() : TLineData() {}

// SYNTHETIC: IMPERIALISM 0x005c0db0
// TDealLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005c0de0
TDealLine::~TDealLine() {}

// FUNCTION: IMPERIALISM 0x005c0e50
void TDealLine::InstallViews(TView* panel, int* offsetLayout) {
  CString counterpartyName;
  CString commodityName;
  CString templateText;
  CString displayText;
  CString amountText;
  CString priceText;

  TMyStaticText* text = new TMyStaticText();
  int textSize[2] = {field08 - 0x28, field0c};
  int textOffset[2] = {offsetLayout[0] + 0x28, offsetLayout[1]};
  text->InitializeTextEntryBaseAndOptionalStringResource(panel, textOffset, textSize, 5, 5, -1, 0);

  TextStyle textStyle;
  BuildUiTextStyleDescriptor(&textStyle, 0, 0xa, 0x2b6a);
  text->InstallTextStyle(textStyle, 0);

  short dealKind = 0;
  short amount = 0;
  short counterpartyNationSlot = 0;
  int unitPriceOrStatus = 0;
  g_apNationStates[ownerNationSlot12]->ReadTrackedSlotEntryFields(
      commoditySlot10, entryOrdinal14, &dealKind, &amount, &counterpartyNationSlot,
      &unitPriceOrStatus);

  counterpartyName = g_pSimMgr->LoadNormalizedCredentialName(counterpartyNationSlot);
  g_pSimMgr->GetStringPrelude(commoditySlot10, &commodityName);

  if (amount != 0) {
    amountText.Format(g_szDecimalFormat, static_cast<int>(amount));
    short currentMarketPrice =
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(commoditySlot10);
    if (unitPriceOrStatus != currentMarketPrice) {
      g_pSimMgr->NumToCurrency(unitPriceOrStatus, &priceText);
      g_pSimMgr->GetString(0x2740, dealKind == kTrackedSlotOfferEntry ? 0x12 : 0x13, &templateText);
      scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(amountText), static_cast<LPCSTR>(commodityName),
                             static_cast<LPCSTR>(counterpartyName), static_cast<LPCSTR>(priceText));
    } else {
      g_pSimMgr->GetString(0x2740, dealKind == kTrackedSlotOfferEntry ? 0x14 : 0x15, &templateText);
      scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(amountText), static_cast<LPCSTR>(commodityName),
                             static_cast<LPCSTR>(counterpartyName));
    }
  } else if (unitPriceOrStatus != -123456 && unitPriceOrStatus != -123457 &&
             unitPriceOrStatus != -123458 && unitPriceOrStatus != -123459) {
    g_pSimMgr->GetString(0x2740, 0x16, &templateText);
    scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(counterpartyName),
                           static_cast<LPCSTR>(commodityName));
  } else {
    g_pSimMgr->GetString(0x2740, 0x1f, &templateText);
    scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(counterpartyName));

    short statusStringIndex = 0;
    if (unitPriceOrStatus == -123456) {
      statusStringIndex = 0x21;
    } else if (unitPriceOrStatus == -123457) {
      statusStringIndex = 0x20;
    } else if (unitPriceOrStatus == -123458 || unitPriceOrStatus == -123459) {
      statusStringIndex = 0x23;
    }
    if (statusStringIndex != 0) {
      CString statusText;
      g_pSimMgr->GetString(0x2740, statusStringIndex, &statusText);
      displayText += s_szSpaceSeparator_00695794 + statusText;
    }
  }

  text->SetTextAndMaybeRefresh(&displayText, 1);
  SetQuickDrawFillColorFromPaletteIndex(0);
}
