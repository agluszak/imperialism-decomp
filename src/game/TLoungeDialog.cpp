#include "game/TLoungeDialog.h"

#include "game/CString.h"
#include "game/TDropShadowText.h"
#include "game/TMapPreviewView.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0044fae0
// TLoungeDialog::`scalar deleting destructor'
TLoungeDialog::~TLoungeDialog() {}
// SYNTHETIC: IMPERIALISM 0x0054d650
// TLoungeDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054d6d0
// TLoungeDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLoungeDialog, TNoHilitePicture)

TLoungeDialog::TLoungeDialog() {}

// FUNCTION: IMPERIALISM 0x0054d6f0
void TLoungeDialog::Free() {}

// FUNCTION: IMPERIALISM 0x0054d730
void TLoungeDialog::NoOpUiLifecycleHook(int arg) {
  TNoHilitePicture::NoOpUiLifecycleHook(arg);
  // The original then sets up the multiplayer lounge dialog's roster/chat controls (821
  // bytes) -- not yet ported.
}

// FUNCTION: IMPERIALISM 0x0054db40
char TLoungeDialog::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0054e1f0
void TLoungeDialog::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

namespace {

// RAII wait-cursor guard, same reconstruction as TAssetMgr.cpp's 0x5e0030: EH state 0
// opens with an inlined AfxGetApp()->BeginWaitCursor() and unwinds with the matching
// EndWaitCursor().
struct TScopedWaitCursor {
  TScopedWaitCursor() {
    AfxGetApp()->BeginWaitCursor();
  }
  ~TScopedWaitCursor() {
    AfxGetApp()->EndWaitCursor();
  }
};

} // namespace

// Under a wait cursor: restamp the 'tnam' caption from the host game name, re-rasterize
// and palette-mask the 'map ' preview then invalidate its bounds, load the lounge
// message string (0x2742/0x10) into 'mess', and refresh the dialog.
// FUNCTION: IMPERIALISM 0x0054e4c0
void TLoungeDialog::RefreshMapAndMessageControlsForCurrentContext() {
  TScopedWaitCursor waitCursor;
  TStaticText* nameControl = RefreshActiveControlThenApplyThemeStyleAndCaption(
      0x746e616d /* 'tnam' */, 0, 0xe, 0x2b6b, 1,
      static_cast<const char*>(g_pGameFlowState->gameNameString));
  nameControl->AssertValid();
  ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xc, 0x2b6b, 0x2b6c);
  TMapPreviewView* mapControl =
      static_cast<TMapPreviewView*>(ResolveControlByTag(0x6d617020 /* 'map ' */));
  mapControl->AssertValid();
  mapControl->TakeSatellitePhoto(0);
  mapControl->EnhancePhoto();
  RECT mapBounds;
  mapControl->QueryBounds(&mapBounds);
  RECT invalidBounds = mapBounds;
  InvalidateCityDialogRectRegion(&invalidBounds, 1);
  TStaticText* messControl = (TStaticText*)ResolveControlByTag(0x6d657373 /* 'mess' */);
  messControl->AssertValid();
  CString messageText;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&messageText, 0x2742, 0x10);
  messControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&messageText, 1);
  RefreshControl();
}
