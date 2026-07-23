#include "game/ui_core/TIncludeView.h"
#include "game/ui_tags_common.h"
#include "game/ui_screens/CString.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// IMPLEMENT_DYNCREATE also emits `TIncludeView::CreateObject`; the original copy at
// 0x48cc40 has the TIncludeView ctor fully inlined into it (same TU, inline-eligible),
// so the pairing is structural, not byte-exact.
// SYNTHETIC: IMPERIALISM 0x0048cc40
// TIncludeView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048cd50
// TIncludeView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIncludeView, TView)

// FUNCTION: IMPERIALISM 0x0048cd70
TIncludeView::TIncludeView()
    : TView(), turnEventCode60(-1), padding62(0), labelText6c(), completionFlag70(1), padding72(0) {
  anchorPoint64[0] = 0;
  anchorPoint64[1] = 0;
  CString empty(g_szEmptyString);
  labelText6c = empty;
  field04 = 0;
}

// SYNTHETIC: IMPERIALISM 0x0048ce40
// TIncludeView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0048ce70
TIncludeView::~TIncludeView() {}

// FUNCTION: IMPERIALISM 0x0048cf10
void TIncludeView::BuildTurnEventFactoryPacket(TView* resourceContext, TView* mainView,
                                               short eventCode, int* anchorPoint,
                                               CString* labelText, int flag) {
  if (mainView != nullptr) {
    nativeWindow50 = mainView->nativeWindow50;
  }
  controlTag = kControlTagSpSpSpSp;
  field04 = 1;
  field08 = 1;
  linkedChildHandler = mainView;
  ownerLocalX = g_turnEventDialogAnchorPoint[0];
  ownerLocalY = g_turnEventDialogAnchorPoint[1];
  frameWidth34 = mainView->frameWidth34;
  frameHeight38 = mainView->frameHeight38;
  if (mainView != nullptr) {
    mainView->AttachChildControl(this, 0);
  }
  this->resourceContext = resourceContext;
  turnEventCode60 = eventCode;
  anchorPoint64[0] = anchorPoint[0];
  anchorPoint64[1] = anchorPoint[1];
  labelText6c = *labelText;
  completionFlag70 = static_cast<short>(flag);
}

// FUNCTION: IMPERIALISM 0x0048cfd0
void TIncludeView::DoPostCreate(int arg) {
  (void)arg;
  if (turnEventCode60 != -1 && g_pTurnEventDialogFactoryRegistry != nullptr) {
    TurnEventId eventCode = DecodeTurnEventCode(turnEventCode60);
    if (ownerContext != nullptr) {
      CaptureLayoutF0(g_turnEventDialogAnchorPoint, 0);
      CaptureLayout(&ownerContext->frameWidth34, 0);
    }
    TView* dialog = g_pTurnEventDialogFactoryRegistry->InvokeDialogFactoryFromPacket(
        0, this, eventCode, g_turnEventDialogAnchorPoint);
    if (dialog == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, MB_ICONEXCLAMATION);
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x846);
    }
  }
  if (nativeWindow50 != nullptr && nativeWindow50->m_hWnd != nullptr) {
    SendMessageA(nativeWindow50->m_hWnd, 0x4ef, 1, 0);
  }
}
