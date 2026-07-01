#include "game/TIncludeView.h"
#include "game/CString.h"
#include "game/TTurnEventDialogFactoryRegistry.h"
#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

extern "C" char g_szEmptyString[];

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
TIncludeView::~TIncludeView() {}

// FUNCTION: IMPERIALISM 0x0048cf10
void TIncludeView::BuildTurnEventFactoryPacket(TView* ownerContextArg, TView* mainView,
                                               short eventCode, int* anchorPoint,
                                               CString* labelText, int flag) {
  if (mainView != nullptr) {
    nativeWindow50 = mainView->nativeWindow50;
  }
  controlTag = 0x20202020;
  field04 = 1;
  field08 = 1;
  linkedChildHandler = mainView;
  ownerOffsetX = g_turnEventDialogAnchorPoint[0];
  ownerOffsetY = g_turnEventDialogAnchorPoint[1];
  field34 = mainView->field34;
  field38 = mainView->field38;
  if (mainView != nullptr) {
    mainView->AttachChildControl(this, 0);
  }
  uiResourceContext40 = ownerContextArg;
  turnEventCode60 = eventCode;
  anchorPoint64[0] = anchorPoint[0];
  anchorPoint64[1] = anchorPoint[1];
  labelText6c = *labelText;
  completionFlag70 = static_cast<short>(flag);
}

// FUNCTION: IMPERIALISM 0x0048cfd0
void TIncludeView::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  if (turnEventCode60 != -1 && g_pTurnEventDialogFactoryRegistry != nullptr) {
    int eventCode = static_cast<int>(turnEventCode60);
    if (ownerContext != nullptr) {
      CaptureLayoutF0(g_turnEventDialogAnchorPoint, 0);
      CaptureLayout(&ownerContext->field34, 0);
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
