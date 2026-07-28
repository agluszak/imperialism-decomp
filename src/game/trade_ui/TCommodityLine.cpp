#include "game/trade_ui/TCommodityLine.h"

#include "game/ui_screens/CString.h"
#include "game/ui_screens/TColorKeyPicture.h"
#include "game/ui_widgets/TMyStaticText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
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
// FUNCTION: IMPERIALISM 0x005c1520
TCommodityLine::~TCommodityLine() {}

// FUNCTION: IMPERIALISM 0x005c1540
void TCommodityLine::ICommodityLine(short rowArg, short colArg, int* bounds, short value) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  commoditySlot = value;
}

// FUNCTION: IMPERIALISM 0x005c1580
void TCommodityLine::InstallViews(TView* panel, int* offsetLayout) {
  CString commodityName;
  CString priceText;
  CString displayText;
  TextStyle textStyle;

  BuildUiTextStyleDescriptor(&textStyle, 0, 0xe, 0x2b67);
  g_pSimMgr->GetStringPrelude(commoditySlot, &commodityName);
  short price = g_pTradeMgr->GetPrice(commoditySlot);
  g_pSimMgr->NumToCurrency(price, &priceText);
  displayText = commodityName + s_szSpaceSeparator_00695794 + priceText;

  int textSize[2] = {layoutWidth - 0x28, layoutHeight};
  int textOffset[2] = {offsetLayout[0] + 0x28, offsetLayout[1]};
  TMyStaticText* text = new TMyStaticText();
  text->IStaticText(panel, textOffset, textSize, 5, 5, -1, 1);
  text->InstallTextStyle(textStyle, 0);
  text->SetTextAndMaybeRefresh(&displayText, 1);

  int iconSize[2] = {0x20, 0x18};
  TColorKeyPicture* icon = new TColorKeyPicture();
  icon->IPicture(panel, offsetLayout, iconSize, 5, 5, static_cast<short>(commoditySlot + 0x2bc));
}
