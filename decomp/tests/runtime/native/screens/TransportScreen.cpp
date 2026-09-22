#include "TransportScreen.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/core/TMouseCaptureState.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TRightLeftView.h"
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

TTransportPicture* TransportScreen::CommodityRow(short slot) const {
  if (slot < 0 || slot >= 0x17) {
    return 0;
  }
  TView* row = Find(g_pTradeSummarySelectionMap[slot]);
  return row != 0 && row->IsKindOf(RUNTIME_CLASS(TTransportPicture)) != 0
             ? static_cast<TTransportPicture*>(row)
             : 0;
}

short TransportScreen::FirstLowerableCommoditySlot() const {
  for (short slot = 0; slot < 0x17; ++slot) {
    // Slots 0 and 0x13 sum a pair of need entries, and the four slots the refresh skips
    // never get a live row.
    if (slot == 0 || slot == 0x13 || slot == 1 || slot == 7 || slot == 10 || slot == 0x10 ||
        slot == 0x14) {
      continue;
    }
    TTransportPicture* row = CommodityRow(slot);
    if (row != 0 && row->splitValue94 > 0) {
      return slot;
    }
  }
  return -1;
}

RuntimeActionResult TransportScreen::ClickCommodityArrow(short slot, int arrowTag) {
  TTransportPicture* row = CommodityRow(slot);
  if (row == 0) {
    return RuntimeActionResult::Failure("no commodity row to click");
  }
  // The ledger refresh replaces each row's generated TSidewaysArrow children with live
  // TRightLeftView widgets; both raise 100/101 on rght/left track, so the click path is the
  // same either way.
  TView* arrowView = row->ResolveControlByTag(arrowTag);
  if (arrowView == 0 || arrowView->IsKindOf(RUNTIME_CLASS(TRightLeftView)) == 0) {
    return RuntimeActionResult::Failure("commodity row has no sideways arrow");
  }
  TControl* arrow = static_cast<TControl*>(arrowView);

  CRect bounds;
  arrow->QueryContentBounds(&bounds);
  CPoint zone(bounds.left + bounds.Width() / 2, bounds.top + bounds.Height() / 2);
  CPoint windowPoint(zone); // RUNTIME_COORDINATE_EXPLAINED
  arrow->TranslatePointToParentChain4D(&windowPoint);

  TWindow* window = arrow->GetWindow();
  if (window == 0) {
    return RuntimeActionResult::Failure("sideways arrow has no owning window");
  }
  TToolboxEvent event;
  event.mouseX = windowPoint.x;
  event.mouseY = windowPoint.y;
  event.commandCode = 0;
  event.keyFlags = 0;
  event.mouseButton24 = 0;
  CPoint windowOrigin(0, 0); // RUNTIME_COORDINATE_EXPLAINED: origin of the owning window
  if (window->HandleMouseDown(windowPoint, &event, windowOrigin) == 0 ||
      g_McAppMouseCaptureState.capturedControl != arrow) {
    return RuntimeActionResult::Failure("sideways arrow did not receive the view-tree mouse down");
  }
  g_McAppMouseCaptureState.EndMouseCaptureAndStopRepeatTimer(0, windowPoint.x, windowPoint.y);
  return RuntimeActionResult::Success();
}

short TransportScreen::CommodityNeedTarget(short slot) const {
  TGreatPower* nation = g_pSimMgr != 0 ? g_apNationStates[g_pSimMgr->GetActiveNationId()] : 0;
  return nation != 0 && slot >= 0 && slot < 0x17 ? nation->needTargetByType[slot] : -1;
}

short TransportScreen::ReservedTransportCapacity() const {
  TGreatPower* nation = g_pSimMgr != 0 ? g_apNationStates[g_pSimMgr->GetActiveNationId()] : 0;
  return nation != 0 ? nation->reservedTransportCapacity : -1;
}

RuntimeActionResult TransportScreen::Close() {
  return Activate(kControlTagEnd, "leave the transport ledger");
}
