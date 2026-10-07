#include "game/ui_widgets/TCloseButton.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

IMPLEMENT_DYNCREATE(TCloseButton, TPictureButton)

// FUNCTION: IMPERIALISM 0x00584af0
TCloseButton::TCloseButton() {}

// FUNCTION: IMPERIALISM 0x00584b50
TCloseButton::~TCloseButton() {}

// FUNCTION: IMPERIALISM 0x00584b70
bool TCloseButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  TView::HandleMouseDown(point, event, origin);
  g_pViewMgr->DispatchTurnEvent(kTurnEventRebuildRegisteredWindows, 0);
  return true;
}
