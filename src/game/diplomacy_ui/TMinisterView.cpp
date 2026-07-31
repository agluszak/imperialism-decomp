#include "game/diplomacy_ui/TMinisterView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/diplomacy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x004f2bb0
// TMinisterView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f2c40
// TMinisterView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinisterView, TView)

// FUNCTION: IMPERIALISM 0x004f2c60
TMinisterView::TMinisterView() : TView(), field60(0) {}

// SYNTHETIC: IMPERIALISM 0x004f2c90
// TMinisterView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004f2cc0
TMinisterView::~TMinisterView() {}

// FUNCTION: IMPERIALISM 0x004f2ce0
void TMinisterView::StuffValues(short nationSlot) {
  selectedCountry = g_apTerrainTypeDescriptorTable[nationSlot];
}

// FUNCTION: IMPERIALISM 0x004f2d10
char TMinisterView::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  TView* backControl = ResolveControlByTag(kControlTagBack);
  if (backControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUDiplomacyViews_00696AE0, 0xb7);
  }

  TView* okayControl = backControl->ResolveControlByTag(kControlTagOkay);
  if (okayControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUDiplomacyViews_00696AE0, 0xb9);
  }

  if (okayControl->IsActionable() != 0) {
    okayControl->Show(0, 1);
  }
  return TView::HandleMouseUp(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x004f2e00
void TMinisterView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0xa) {
    TEventHandler::DoEvent(commandId, sourceHandler, event);
    return;
  }
  int tag = sourceHandler->controlTag;
  if (commandId == 0xa) {
    if (tag == kControlTagOkay) {
      CloseBooks();
      TWindow* owner = GetWindow();
      g_pAmbitApplication->CloseAndFreeWindow(owner);
      return;
    }
    if (tag == kControlTagBack) {
      CloseBooks();
      return;
    }
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f2ea0
void TMinisterView::CloseBooks() {
  g_pDisplayMgr->CloseFloaters();
}

// FUNCTION: IMPERIALISM 0x004f2ec0
TView* TMinisterView::OpenBook(int bookId) {
  CloseBooks();
  return g_pMacViewMgr->MakeBookDialog(bookId);
}

// FUNCTION: IMPERIALISM 0x004f2ef0
void TMinisterView::FreeDisplayArea() {
  TView* dispControl = ResolveControlByTag(kControlTagDisp);
  if (dispControl != nullptr) {
    dispControl->Free();
  }
}
