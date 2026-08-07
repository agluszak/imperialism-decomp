#include "TransportScreen.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TTransportPicture.h"

#include <string.h>

namespace {

// The map toolbar's transport button while the ledger is up.
const short kTransportToolbarSelectedPicture = 0x24f0;

// The ledger's two column headings come from this string group.
const short kLedgerHeadingStringGroup = 0x2735;
const short kLeftHeadingStringIndex = 5;
const short kRightHeadingStringIndex = 6;

// The separator the capacity readout puts between the current amount and the capacity.
const char* const kCapacitySeparator = "  /  ";

// A commodity's hover help names both amounts. A '[' left in the text is an unsubstituted
// placeholder -- the string was loaded but never filled in.
const char* const kWarehouseLabel = "Warehouse:";
const char* const kNeededLabel = "Needed:";

// Where the ledger lays out the capacity readout inside its gauge.
const int kCapacityLabelX = 0xa2;
const int kCapacityLabelY = 0x14;
const int kCapacityLabelWidth = 0x3c;
const int kCapacityLabelHeight = 0xb;

} // namespace

TransportScreen::TransportScreen()
    : MainViewScreen(RUNTIME_CLASS(TPicture), kTurnEventTransport, "the transport ledger") {}

bool TransportScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TPicture), kTurnEventTransport) &&
         TransportScreen().Find(kControlTagTitL) != 0;
}

TStaticText* TransportScreen::Heading(int tag) const {
  TView* heading = Find(tag);
  return heading != 0 && heading->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0
             ? static_cast<TStaticText*>(heading)
             : 0;
}

bool TransportScreen::HasLedgerHeadings() const {
  TStaticText* left = Heading(kControlTagTitL);
  TStaticText* right = Heading(kControlTagTitR);
  if (left == 0 || right == 0 || left->text == 0 || right->text == 0 || g_pSimMgr == 0) {
    return false;
  }
  CString expectedLeft;
  CString expectedRight;
  g_pSimMgr->GetString(kLedgerHeadingStringGroup, kLeftHeadingStringIndex, &expectedLeft);
  g_pSimMgr->GetString(kLedgerHeadingStringGroup, kRightHeadingStringIndex, &expectedRight);
  return *left->text == expectedLeft && *right->text == expectedRight;
}

bool TransportScreen::ToolbarIconIsSelected() const {
  TView* toolbarDialog = g_pDisplayMgr != 0 ? g_pDisplayMgr->activeDialog : 0;
  TView* button = toolbarDialog != 0 ? toolbarDialog->ResolveControlByTag(kControlTagTran) : 0;
  if (button == 0 || button->IsKindOf(RUNTIME_CLASS(TPicture)) == 0) {
    return false;
  }
  TPicture* icon = static_cast<TPicture*>(button);
  return icon->glyphBase84 == kTransportToolbarSelectedPicture && icon->controlState64 == 0;
}

bool TransportScreen::CommodityHelpIsSubstituted(short commodityIndex) const {
  TView* commodity = Find(g_pTradeSummarySelectionMap[commodityIndex]);
  if (commodity == 0) {
    return false;
  }
  LPCSTR help = static_cast<LPCSTR>(commodity->hoverHelpText58);
  return help != 0 && strstr(help, kWarehouseLabel) != 0 && strstr(help, kNeededLabel) != 0 &&
         strchr(help, '[') == 0;
}

TTransportPicture* TransportScreen::CapacityGauge() const {
  TView* gauge = Find(kControlTagTota);
  return gauge != 0 && gauge->IsKindOf(RUNTIME_CLASS(TTransportPicture)) != 0
             ? static_cast<TTransportPicture*>(gauge)
             : 0;
}

TStaticText* TransportScreen::CapacityLabel() const {
  TTransportPicture* gauge = CapacityGauge();
  TView* label = gauge != 0 ? gauge->ResolveControlByTag(kControlTagText) : 0;
  return label != 0 && label->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0
             ? static_cast<TStaticText*>(label)
             : 0;
}

bool TransportScreen::CapacityLabelMatchesSplit() const {
  TTransportPicture* gauge = CapacityGauge();
  TStaticText* label = CapacityLabel();
  if (gauge == 0 || label == 0 || label->text == 0) {
    return false;
  }
  CString current;
  CString capacity;
  current.Format("%d", static_cast<int>(gauge->splitValue94));
  capacity.Format("%d", static_cast<int>(gauge->splitValue96));
  return *label->text == current + kCapacitySeparator + capacity;
}

bool TransportScreen::CapacityLabelHasRetailGeometry() const {
  TStaticText* label = CapacityLabel();
  return label != 0 && label->ownerLocalX == kCapacityLabelX &&
         label->ownerLocalY == kCapacityLabelY && label->frameWidth34 == kCapacityLabelWidth &&
         label->frameHeight38 == kCapacityLabelHeight;
}

RuntimeActionResult TransportScreen::Close() {
  return Activate(kControlTagEnd, "leave the transport ledger");
}
