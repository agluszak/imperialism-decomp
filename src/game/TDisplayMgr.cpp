#include "game/TDisplayMgr.h"

#include <new>

#include "game/bitmap_descriptor_helpers.h"
#include "game/CTemporaryRegion.h"
#include "game/startup_helpers.h"
#include "game/TAssetMgr.h"
#include "game/TPtrList.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/CWMgrIterator.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_control_tags.h"

namespace {

const char* kSourceFileUDisplayMgr = "D:\\Ambit\\Cross\\UDisplayMgr.cpp";
const int kClass99WindowId = 99;

static void AssignUiFontGlobalFromLiteral(CString& globalSlot, const char* literal) {
  CString local(literal);
  globalSlot = local;
}

} // namespace

// FUNCTION: IMPERIALISM 0x004972a0
int InitializeTurnOrderNavigationDialogByViewportSize_Impl(int arg) {
  (void)arg;
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x004fe710
// TDisplayMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fe780
// TDisplayMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDisplayMgr, TObject)

// FUNCTION: IMPERIALISM 0x004fe7a0
TDisplayMgr::TDisplayMgr()
    : TObject(), activeDialog(0), viewportMetric(8), dialogActiveFlag(0), field0c(0),
      eventCode0e(0), tileIcon10(0), tileIcon11(0), tileIcon12(0), tileIcon13(0), tileIcon14(0),
      tileIcon15(0), tileIcon16(0), tileIcon17(0), field18(0), clipSnapshotEvent(0), field1e(0),
      turnOrderList(0) {}

// SYNTHETIC: IMPERIALISM 0x004fe7f0
// TDisplayMgr::`scalar deleting destructor'
TDisplayMgr::~TDisplayMgr() {}

// FUNCTION: IMPERIALISM 0x004fe840
undefined TDisplayMgr::InitializeTurnOrderNavigationDialogByViewportSize() {
  TPtrList* list = new TPtrList();
  if (list == 0) {
    turnOrderList = 0;
  } else {
    turnOrderList = list;
    list->relationType = 4;
  }

  dialogActiveFlag = 0;

  AssignUiFontGlobalFromLiteral(g_cstrUiFontBelweBdBt, g_szUiFontLiteralBelweBdBt);
  AssignUiFontGlobalFromLiteral(g_cstrUiFontBelweLight, g_szUiFontLiteralBelweLight);
  AssignUiFontGlobalFromLiteral(g_cstrUiFontPalatino, g_szUiFontLiteralPalatino);

  GlobalViewportRectDefaultsRecord** rectDefaultsHandle =
      InitializeGlobalRectDefaultsIfUninitialized();
  GlobalViewportRectDefaultsRecord* rectRecord = *rectDefaultsHandle;
  RECT viewportRect;
  CopyRect(&viewportRect, reinterpret_cast<RECT*>(&rectRecord->left));
  int width = rectRecord->right - rectRecord->left;
  int height = rectRecord->bottom - rectRecord->top;
  if (width < 0x281 && height < 0x1e1) {
    eventCode0e = 0x7d1;
  } else {
    eventCode0e = 0x7d2;
  }

  OrphanRetStub_004fed50(0);

  TView* dialogRoot = g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(eventCode0e);
  if (dialogRoot == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0xb0);
  }
  activeDialog = dialogRoot;
  field18 = InitializeTurnOrderNavigationDialogByViewportSize_Impl(0x80);
  EnsurePrimaryRenderSurfaceContextAllocated();
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fea60
void TDisplayMgr::Free() {
  delete g_pPrimaryRenderSurfaceContext;
  g_pPrimaryRenderSurfaceContext = 0;
  turnOrderList->SelfDeleteSlot28();
  delete this;
}

// FUNCTION: IMPERIALISM 0x004feab0
void TDisplayMgr::InitializeBitmapSurfaceContextWithRetry(TQuickDrawSurfaceContext** outContext,
                                                          short bitDepth, RECT* bounds) {
  short result = InitializeBitmapDescriptorRecordAndLoadSurfaceNode(outContext, bitDepth, bounds,
                                                                    field18, 0, 0);
  if (result != 0) {
    InitializeBitmapDescriptorRecordAndLoadSurfaceNode(outContext, bitDepth, bounds, field18, 0, 0);
    InitializeBitmapDescriptorRecordAndLoadSurfaceNode(outContext, bitDepth, bounds, field18, 0, 0);
  }
}

// Frees the TQuickDrawSurfaceContext record held in `slot` and clears the slot.
// The original is callee-clean (`ret 4`) with no `this`, i.e. __stdcall.
// FUNCTION: IMPERIALISM 0x004feb50
void __stdcall FreeQuickDrawSurfaceContextSlot(TQuickDrawSurfaceContext** slot) {
  delete *slot;
  *slot = 0;
}

// FUNCTION: IMPERIALISM 0x004feb80
void TDisplayMgr::EnsurePrimaryRenderSurfaceContextAllocated() {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    RECT bounds = {-64, -64, 0x280, 0x220};
    InitializeBitmapSurfaceContextWithRetry(&g_pPrimaryRenderSurfaceContext, 8, &bounds);
  }
}

// FUNCTION: IMPERIALISM 0x004febd0
undefined TDisplayMgr::WrapperFor_thunk_NoOpCallback_00498ca0_At004febd0() {
  if (dialogActiveFlag != 0 && activeDialog != 0) {
    activeDialog->RefreshCityProductionViewStateFromContext(0);
  }
  OrphanRetStub_004fed50(1);
  reinterpret_cast<void(__cdecl*)(void*)>(NoOpCallback_00498ca0)(&tileIcon14);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec20
undefined TDisplayMgr::AssertUDisplayMgrLine471() {
  if (g_nUiInvalidationAssertFlagLine471 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x1d7);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec50
undefined TDisplayMgr::AssertUDisplayMgrLine495() {
  if (g_nUiInvalidationAssertFlagLine495 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x1ef);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec80
undefined TDisplayMgr::DispatchDisplayManagerControlStringMessage() {
  CString message;
  reinterpret_cast<void(__cdecl*)(CString*, CString*)>(AssignStringSharedRefAndReturnThis)(
      &message, &message);
  reinterpret_cast<TViewMgr*>(g_pUiRuntimeContext)
      ->RunControlStringProviderAndDispatchLocalizedMessage(&message);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fed00
undefined TDisplayMgr::WrapperFor_thunk_NoOpCallback_00498ca0_At004fed00() {
  if (dialogActiveFlag != 0 && activeDialog != 0) {
    activeDialog->InvalidateOffsetRegionUsingChildClipRect(0);
    activeDialog->InvokeSlot13C();
  }
  OrphanRetStub_004fed50(0);
  reinterpret_cast<void(__cdecl*)(void*)>(NoOpCallback_00498ca0)(&tileIcon10);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fed50
undefined TDisplayMgr::OrphanRetStub_004fed50(char param_1) {
  (void)param_1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fed70
undefined TDisplayMgr::AssertUDisplayMgrLines614And616(char param_1) {
  if (dialogActiveFlag != 0) {
    if (param_1 != 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x266);
    } else {
      TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x268);
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fedc0
undefined TDisplayMgr::LoadMainViewClipSnapshotIntoQuickDrawState(undefined2 param_1) {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    return 0;
  }

  int savedFlags = 0;
  TQuickDrawSurfaceContext* savedContext = 0;
  CTemporaryRegion surfaceGuard;
  GetClip(surfaceGuard.tempRgn);
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));

  TView* mainControl = activeDialog->ResolveControlByTag(kControlTagMain);
  if (mainControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x28a);
    return 0;
  }

  TView* mainView = mainControl;
  RECT queryBounds;
  mainView->QueryBounds(&queryBounds);

  RECT clipRect;
  clipRect.left = queryBounds.left;
  clipRect.top = queryBounds.top;
  clipRect.right = queryBounds.right;
  clipRect.bottom = queryBounds.bottom;

  SetGlobalQuickDrawOrigin(static_cast<short>(mainView->ownerOffsetX),
                           static_cast<short>(mainView->ownerOffsetY));
  ClipRect(&clipRect);
  mainView->ApplyRectSlot110(&queryBounds);

  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  SetClip(surfaceGuard.tempRgn);
  clipSnapshotEvent = static_cast<short>(param_1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fefc0
void TDisplayMgr::SetMapTileIconVariantTriplet(undefined1* param_1) {
  tileIcon10 = param_1[0];
  tileIcon11 = param_1[1];
  tileIcon12 = param_1[2];
  reinterpret_cast<void(__cdecl*)(void*)>(NoOpCallback_00498ca0)(&tileIcon10);
}

// FUNCTION: IMPERIALISM 0x004ff000
undefined TDisplayMgr::DispatchUiWindowStatusTickForClass99Windows() {
  CWMgrIterator cursor;
  cursor.Reset(1);
  TWindow* window = static_cast<TWindow*>(cursor.FirstWindow());
  while (cursor.More() != 0) {
    if (window != 0) {
      if (window->IsActionable() != 0 && window->field3c == kClass99WindowId) {
        if (window->GetDialogBehaviorByte10() == 0) {
          window->CloseAndFree();
        } else {
          window->OrphanCallChain_C2_I12_0048dc90(kTagOkOkOk, 1);
        }
      }
    }
    window = static_cast<TWindow*>(cursor.NextWindow());
  }
  return 0;
}
