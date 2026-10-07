#include "game/ui_core/TIncludeView.h"
#include "game/ui_tags_common.h"
#include "game/core/CString.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// IMPLEMENT_DYNCREATE also emits `TIncludeView::CreateObject`; the original copy at
// 0x48cc40 has the TIncludeView ctor fully inlined into it (same TU, inline-eligible),
// so the pairing is structural, not byte-exact.

IMPLEMENT_DYNCREATE(TIncludeView, TView)

// FUNCTION: IMPERIALISM 0x0048cd70
TIncludeView::TIncludeView()
    : TView(), turnEventCode(-1), padding62(0), labelText(), completionFlag(1), padding72(0) {
  anchorPoint.x = 0;
  anchorPoint.y = 0;
  CString empty(g_szEmptyString);
  labelText = empty;
  enabled = 0;
}

// FUNCTION: IMPERIALISM 0x0048ce70
TIncludeView::~TIncludeView() {}

// FUNCTION: IMPERIALISM 0x0048cf10
void TIncludeView::BuildTurnEventFactoryPacket(TView* resourceContext, TView* mainView,
                                               short eventCode, const CPoint& anchorPoint,
                                               CString* labelText, int flag) {
  if (mainView != nullptr) {
    nativeWindow = mainView->nativeWindow;
  }
  controlTag = kControlTagSpSpSpSp;
  enabled = 1;
  viewEnabled = 1;
  nextHandler = mainView;
  ownerLocalX = g_turnEventDialogAnchorPoint.x;
  ownerLocalY = g_turnEventDialogAnchorPoint.y;
  frameWidth = mainView->frameWidth;
  frameHeight = mainView->frameHeight;
  if (mainView != nullptr) {
    mainView->AttachChildControl(this, 0);
  }
  this->resourceContext = resourceContext;
  turnEventCode = eventCode;
  this->anchorPoint.x = anchorPoint.x;
  this->anchorPoint.y = anchorPoint.y;
  this->labelText = *labelText;
  completionFlag = static_cast<short>(flag);
}

// FUNCTION: IMPERIALISM 0x0048cfd0
void TIncludeView::DoPostCreate(int arg) {
  (void)arg;
  if (turnEventCode != -1 && g_pTurnEventDialogFactoryRegistry != nullptr) {
    TurnEventId eventCode = DecodeTurnEventCode(turnEventCode);
    if (ownerContext != nullptr) {
      Locate(g_turnEventDialogAnchorPoint, false);
      CPoint ownerSize(ownerContext->frameWidth, ownerContext->frameHeight);
      Resize(ownerSize, false);
    }
    TView* dialog = g_pTurnEventDialogFactoryRegistry->InvokeDialogFactoryFromPacket(
        0, this, eventCode, g_turnEventDialogAnchorPoint);
    if (dialog == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, MB_ICONEXCLAMATION);
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0x846);
    }
  }
  if (nativeWindow != nullptr && nativeWindow->m_hWnd != nullptr) {
    SendMessageA(nativeWindow->m_hWnd, 0x4ef, 1, 0);
  }
}
