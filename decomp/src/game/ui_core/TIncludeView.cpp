#include "game/ui_core/TIncludeView.h"
#include "game/ui_tags_common.h"
#include "game/core/CString.h"
#include "game/ui_core/TTurnEventDialogFactoryRegistry.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TIncludeView, TView)

// FUNCTION: IMPERIALISM 0x0048cd70
TIncludeView::TIncludeView() : turnEventCode(-1), padding62(0), completionFlag(1), padding72(0) {
  anchorPoint.x = 0;
  anchorPoint.y = 0;
  CString empty(g_szEmptyString);
  labelText = empty;
  enabled = 0;
}

// FUNCTION: IMPERIALISM 0x0048ce70
TIncludeView::~TIncludeView() {}

// FUNCTION: IMPERIALISM 0x0048cf10
void TIncludeView::IIncludeView(TView* resourceContext, TView* mainView, short eventCode,
                                const CPoint& anchorPoint, CString* labelText, short flag) {
  if (mainView != NULL) {
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
  if (mainView != NULL) {
    mainView->AttachChildControl(this, 0);
  }
  this->resourceContext = resourceContext;
  turnEventCode = eventCode;
  this->anchorPoint.x = anchorPoint.x;
  this->anchorPoint.y = anchorPoint.y;
  this->labelText = *labelText;
  completionFlag = flag;
}

// FUNCTION: IMPERIALISM 0x0048cfd0
void TIncludeView::DoPostCreate(int arg) {
  if (turnEventCode != -1 && g_pTurnEventDialogFactoryRegistry != NULL) {
    TurnEventId eventCode = DecodeTurnEventCode(turnEventCode);
    if (ownerContext != NULL) {
      Locate(g_turnEventDialogAnchorPoint, false);
      CPoint ownerSize(ownerContext->frameWidth, ownerContext->frameHeight);
      Resize(ownerSize, false);
    }
    TView* dialog = g_pTurnEventDialogFactoryRegistry->InvokeDialogFactoryFromPacket(
        0, this, eventCode, g_turnEventDialogAnchorPoint);
    if (dialog == NULL) {
      MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, MB_ICONEXCLAMATION);
      ReportAssertionFailure(g_szMcAppUiSourcePath, 0x846);
    }
  }
  if (nativeWindow != NULL && nativeWindow->m_hWnd != NULL) {
    SendMessageA(nativeWindow->m_hWnd, 0x4ef, 1, 0);
  }
}
