#include "game/TLoungeDialog.h"

#include "game/CString.h"
#include "game/TDropShadowText.h"
#include "game/TMapPreviewView.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TInfoBarText.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
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
void TLoungeDialog::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pGameFlowState->EnableDiplomacyQueueRoutingAndSetContextField44(this, 1);

  // 'labl' is a TInfoBarText control (vtable slot 0x204 matches
  // TInfoBarText::InitializeMapHintTextStyleAndThemeFlags exactly). The original also
  // installs it as the shared cursor-hint panel.
  TInfoBarText* lablControl = static_cast<TInfoBarText*>(ResolveControlByTag(0x6c61626c));
  g_pCursorControlPanel = lablControl;
  lablControl->AssertValid();
  lablControl->BuildAndApplyTextStyleDescriptor(0, 0xe, 0x2b6b);
  lablControl->InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c);
  lablControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  // Per-nation-slot roster rows: a ready-state radio ('rad0'-'rad6'), a portrait/pick
  // button ('pik0'-'pik6'), and a name label ('nam0'-'nam6'), each initialized with a
  // blank caption via the same restyle idiom as RefreshMapAndMessageControlsForCurrentContext.
  for (int i = 0; i < 7; ++i) {
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 6,
                                                          0x72616430u + i); // 'rad0'-'rad6'
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 7,
                                                          0x70696b30u + i); // 'pik0'-'pik6'
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 8,
                                                          0x6e616d30u + i); // 'nam0'-'nam6'
    // 0x6980c8 is an unlabeled data address Ghidra never recognized as a string (no
    // string-oracle entry, single xref) -- treated as the empty placeholder caption it
    // reads as.
    TStaticText* nameControl =
        RefreshActiveControlThenApplyThemeStyleAndCaption(0x6e616d30u + i, 0, 0xe, 0x2b6b, -2, "");
    nameControl->AssertValid();
    ApplyUiTextStyleAndThemeFlags((TDropShadowText*)nameControl, 0, 0xe, 0x2b6b, 0x2b6c);
  }

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xb, 0x6d617020u); // 'map '
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xd, 0x746e616du); // 'tnam'
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xe, 0x73656e64u); // 'send'

  if (!g_pGameFlowState->IsSpecialNationDialogModeActive()) {
    LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 9, 0x636e636cu); // 'clnc'
    g_pGameFlowState->ResetNationStatusSlotsAndInitializeNameControls(this);
    if (g_pSimMgr->field44 == 1) {
      g_pGameFlowState->SetDialogModeTagInitAndInvokeNoOpHook();
      RefreshMapAndMessageControlsForCurrentContext();
      g_pGameFlowState->DispatchTurnEventCode9WithTwoTextTokens(
          -0xd, 0, g_pLoungeLocalPlayerNameSharedText_0065c160,
          g_pLoungeLocalPlayerNameSharedText_0065c160);
      g_pGameFlowState->EmitTurnEventEAnd9SessionContextPackets(nullptr);
    }
  } else {
    // The special-nation-dialog path loads 'clnc'/'busy' conditionally on
    // GetNationStatusCodeForSlotOrActiveNation(-1) and posts more chat lines -- not yet
    // decoded.
  }

  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2742, 0xc, 0x6d657373u); // 'mess'
  selectedNationSlot = -1;
  DoIdle(1);

  // The original then re-checks IsSpecialNationDialogModeActive() and does further
  // nation-status-code-derived control setup -- not yet decoded.
}

// FUNCTION: IMPERIALISM 0x0054db40
char TLoungeDialog::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0054e1f0
void TLoungeDialog::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x29a) {
    TView* okayControl = ResolveControlByTag(kControlTagOkay);
    okayControl->AssertValid();
    okayControl->SetState(0, 0);
    okayControl->SetEnabled(0, 0);
  }
  // The original also handles a 'pick' command (calling the currently-unowned 444-byte
  // TryInvokeNationStateReplacementForSlot with sourceHandler's own +0x6c field), then a
  // large control-tag dispatch table for commandId in {0xa, 0xd, 0x14, 0x22} -- not yet
  // ported.
}

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
  messControl->SetTextAndMaybeRefresh(&messageText, 1);
  RefreshControl();
}
