#include "game/TCommodityLine.h"

#include "game/CString.h"
#include "game/TColorKeyPicture.h"
#include "game/TMyStaticText.h"
#include "game/TSimMgr.h"
#include "game/TTradeMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x005c1430
// TCommodityLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005c14a0
// TCommodityLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCommodityLine, TLineData)

// FUNCTION: IMPERIALISM 0x005c14c0
TCommodityLine::TCommodityLine() : TLineData() {}

// SYNTHETIC: IMPERIALISM 0x005c14f0
// TCommodityLine::`scalar deleting destructor'
TCommodityLine::~TCommodityLine() {}

// FUNCTION: IMPERIALISM 0x005c1580
void TCommodityLine::InstallViews(TView* panel, int* offsetLayout) {
  CString commodityName;
  CString priceText;
  CString displayText;
  TextStyle textStyle;

  BuildUiTextStyleDescriptor(&textStyle, 0, 0xe, 0x2b67);
  g_pSimMgr->GetStringPrelude(commoditySlot10, &commodityName);
  short price = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(commoditySlot10);
  g_pSimMgr->NumToCurrency(price, &priceText);
  displayText = commodityName + s_szSpaceSeparator_00695794 + priceText;

  int textSize[2] = {field08 - 0x28, field0c};
  int textOffset[2] = {offsetLayout[0] + 0x28, offsetLayout[1]};
  TMyStaticText* text = new TMyStaticText();
  text->InitializeTextEntryBaseAndOptionalStringResource(panel, textOffset, textSize, 5, 5, -1, 1);
  text->InstallTextStyle(textStyle, 0);
  text->SetTextAndMaybeRefresh(&displayText, 1);

  int iconSize[2] = {0x20, 0x18};
  TColorKeyPicture* icon = new TColorKeyPicture();
  icon->InitializePictureEntryBaseAndRefresh(panel, offsetLayout, iconSize, 5, 5,
                                             static_cast<short>(commoditySlot10 + 0x2bc));
}
