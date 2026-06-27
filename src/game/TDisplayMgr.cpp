#include "game/TDisplayMgr.h"

#include <new>

#include "game/QuickDrawSurfaceGuard.h"
#include "game/startup_helpers.h"
#include "game/TAssetMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSortedPtrList.h"
#include "game/TView.h"
#include "game/CWMgrIterator.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/UiRuntimeContext.h"
#include "game/diplomacy_globals.h"
#include "game/mfc.h"
#include "game/quickdraw_globals.h"
#include "game/ui_invalidation_guard.h"

extern "C" {
extern CRuntimeClass classRuntimeClass;
}

undefined4 AssignStringSharedRefAndReturnThis(void);
undefined4 InitializeBitmapDescriptorRecordAndLoadSurfaceNode(void);
undefined4 NoOpCallback_00498ca0(void);
undefined4 ApplyHitRegionToClipState(void);
undefined4 GetActiveQuickDrawSurfaceContextAndFlags(void);
undefined4 SetActiveQuickDrawSurfaceContext(void);
undefined4 GetSurfaceObjectAtContextOffset24(void);
undefined4 ReturnConstantTrueQuickDrawFlag(void);
undefined4 ApplyRectClipRegionToGlobalClipState(void);
undefined4 NoOpQuickDrawLifecycleHookB(void);

namespace DisplayMgrInvoke {

static void AssignStringSharedRefAndReturnThis(TView* view, CString* dest, CString* sharedSource) {
  reinterpret_cast<void(__cdecl*)(TView*, CString*, CString*)>(
      reinterpret_cast<void (*)()>(::AssignStringSharedRefAndReturnThis))(view, dest, sharedSource);
}

static short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(undefined4* outContext,
                                                                int elementSize, RECT* bounds,
                                                                int hintField18, int arg4,
                                                                int arg5) {
  return reinterpret_cast<short(__cdecl*)(undefined4*, int, RECT*, int, int, int)>(
      reinterpret_cast<void (*)()>(::InitializeBitmapDescriptorRecordAndLoadSurfaceNode))(
      outContext, elementSize, bounds, hintField18, arg4, arg5);
}

static void NoOpCallback_00498ca0(void* fieldPtr) {
  reinterpret_cast<void(__cdecl*)(void*)>(reinterpret_cast<void (*)()>(::NoOpCallback_00498ca0))(
      fieldPtr);
}

static void ApplyHitRegionToClipState(int clipDescriptor) {
  reinterpret_cast<void(__cdecl*)(int)>(reinterpret_cast<void (*)()>(::ApplyHitRegionToClipState))(
      clipDescriptor);
}

static void GetActiveQuickDrawSurfaceContextAndFlags(undefined4* ctx, int* flags) {
  reinterpret_cast<void(__cdecl*)(undefined4*, int*)>(
      reinterpret_cast<void (*)()>(::GetActiveQuickDrawSurfaceContextAndFlags))(ctx, flags);
}

static void SetActiveQuickDrawSurfaceContext(undefined4 ctx, int flags) {
  reinterpret_cast<void(__cdecl*)(undefined4, int)>(
      reinterpret_cast<void (*)()>(::SetActiveQuickDrawSurfaceContext))(ctx, flags);
}

static void* GetSurfaceObjectAtContextOffset24(undefined4 ctx) {
  return reinterpret_cast<void*(__cdecl*)(undefined4)>(
      reinterpret_cast<void (*)()>(::GetSurfaceObjectAtContextOffset24))(ctx);
}

static void ReturnConstantTrueQuickDrawFlag(void* surface) {
  reinterpret_cast<void(__cdecl*)(void*)>(
      reinterpret_cast<void (*)()>(::ReturnConstantTrueQuickDrawFlag))(surface);
}

static void ApplyRectClipRegionToGlobalClipState(RECT* rectBuffer) {
  reinterpret_cast<void(__cdecl*)(RECT*)>(
      reinterpret_cast<void (*)()>(::ApplyRectClipRegionToGlobalClipState))(rectBuffer);
}

static void NoOpQuickDrawLifecycleHookB(void* surface) {
  reinterpret_cast<void(__cdecl*)(void*)>(
      reinterpret_cast<void (*)()>(::NoOpQuickDrawLifecycleHookB))(surface);
}

static void InvokeSnapshotHitRegionToClipCache(int clipDescriptor) {
  ::SnapshotHitRegionToClipCache(reinterpret_cast<int*>(clipDescriptor));
}

static void FailUiAssert(const char* sourceFile, int line) {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(reinterpret_cast<void (*)()>(
      ::TemporarilyClearAndRestoreUiInvalidationFlag))(sourceFile, line);
}

} // namespace DisplayMgrInvoke

namespace {

const char* kSourceFileUDisplayMgr = "D:\\Ambit\\Cross\\UDisplayMgr.cpp";
const unsigned int kControlTagMain = 0x6d61696eu;
const unsigned int kTagOkOkOk = 0x6f6b6f6bu;
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
IMPLEMENT_DYNCREATE(TDisplayMgr, TObject)

// FUNCTION: IMPERIALISM 0x004fe7a0
TDisplayMgr::TDisplayMgr()
    : TObject(), activeDialog(0), viewportMetric(8), dialogActiveFlag(0), field0c(0),
      eventCode0e(0), tileIcon10(0), tileIcon11(0), tileIcon12(0), tileIcon13(0), tileIcon14(0),
      tileIcon15(0), tileIcon16(0), tileIcon17(0), field18(0), clipSnapshotEvent(0), field1e(0),
      ownerView(0) {}

// SYNTHETIC: IMPERIALISM 0x004fe7f0
// TDisplayMgr::`scalar deleting destructor'
TDisplayMgr::~TDisplayMgr() {}

// FUNCTION: IMPERIALISM 0x004fe840
undefined TDisplayMgr::InitializeTurnOrderNavigationDialogByViewportSize() {
  TSortedPtrList* list = new TSortedPtrList();
  if (list == 0) {
    ownerView = 0;
  } else {
    ownerView = reinterpret_cast<TView*>(list);
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
    DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0xb0);
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
  if (ownerView != 0) {
    ownerView->CallVoidSlotA0();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x004feab0
undefined TDisplayMgr::Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(
    undefined4* outContext, int elementSize, RECT* bounds) {
  short result = DisplayMgrInvoke::InitializeBitmapDescriptorRecordAndLoadSurfaceNode(
      outContext, elementSize, bounds, field18, 0, 0);
  if (result != 0) {
    DisplayMgrInvoke::InitializeBitmapDescriptorRecordAndLoadSurfaceNode(outContext, elementSize,
                                                                         bounds, field18, 0, 0);
    DisplayMgrInvoke::InitializeBitmapDescriptorRecordAndLoadSurfaceNode(outContext, elementSize,
                                                                         bounds, field18, 0, 0);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004feb50
void WrapperFor_FreeHeapBufferIfNotNull_At004feb50(undefined4* param_1) {
  delete reinterpret_cast<void*>(*param_1);
  *param_1 = 0;
}

// FUNCTION: IMPERIALISM 0x004feb80
undefined TDisplayMgr::EnsurePrimaryRenderSurfaceContextAllocated() {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    RECT bounds = {-64, -64, 0x280, 0x220};
    Helper_Uses_thunk_Cluster_GameplayHint_004962c0_At004feab0(
        reinterpret_cast<undefined4*>(&g_pPrimaryRenderSurfaceContext), 8, &bounds);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004febd0
undefined TDisplayMgr::WrapperFor_thunk_NoOpCallback_00498ca0_At004febd0() {
  if (dialogActiveFlag != 0 && activeDialog != 0) {
    activeDialog->RefreshCityProductionViewStateFromContext(0);
  }
  OrphanRetStub_004fed50(1);
  DisplayMgrInvoke::NoOpCallback_00498ca0(&tileIcon14);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec20
undefined TDisplayMgr::AssertUDisplayMgrLine471() {
  if (g_nUiInvalidationAssertFlagLine471 == 0) {
    DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0x1d7);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec50
undefined TDisplayMgr::AssertUDisplayMgrLine495() {
  if (g_nUiInvalidationAssertFlagLine495 == 0) {
    DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0x1ef);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fec80
undefined TDisplayMgr::DispatchDisplayManagerControlStringMessage() {
  CString message;
  DisplayMgrInvoke::AssignStringSharedRefAndReturnThis(reinterpret_cast<TView*>(this), &message,
                                                       &message);
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
  DisplayMgrInvoke::NoOpCallback_00498ca0(&tileIcon10);
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
      DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0x266);
    } else {
      DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0x268);
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
  undefined4 savedContext = 0;
  QuickDrawSurfaceGuard surfaceGuard;
  int clipDescriptor = reinterpret_cast<int>(surfaceGuard.surfaceWrapper);
  DisplayMgrInvoke::ApplyHitRegionToClipState(clipDescriptor);
  DisplayMgrInvoke::GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  DisplayMgrInvoke::SetActiveQuickDrawSurfaceContext(
      reinterpret_cast<undefined4>(g_pPrimaryRenderSurfaceContext), savedFlags);
  DisplayMgrInvoke::ReturnConstantTrueQuickDrawFlag(
      DisplayMgrInvoke::GetSurfaceObjectAtContextOffset24(
          reinterpret_cast<undefined4>(g_pPrimaryRenderSurfaceContext)));

  TControl* mainControl = activeDialog->ResolveControlByTag(kControlTagMain);
  if (mainControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    DisplayMgrInvoke::FailUiAssert(kSourceFileUDisplayMgr, 0x28a);
    return 0;
  }

  TView* mainView = reinterpret_cast<TView*>(mainControl);
  RECT queryBounds;
  mainView->QueryBounds(&queryBounds);

  RECT clipRect;
  clipRect.left = queryBounds.left;
  clipRect.top = queryBounds.top;
  clipRect.right = queryBounds.right;
  clipRect.bottom = queryBounds.bottom;

  SetGlobalQuickDrawOrigin(static_cast<short>(mainView->ownerOffsetX),
                           static_cast<short>(mainView->ownerOffsetY));
  DisplayMgrInvoke::ApplyRectClipRegionToGlobalClipState(&clipRect);
  mainView->ApplyRectSlot110(&queryBounds);

  DisplayMgrInvoke::NoOpQuickDrawLifecycleHookB(DisplayMgrInvoke::GetSurfaceObjectAtContextOffset24(
      reinterpret_cast<undefined4>(g_pPrimaryRenderSurfaceContext)));
  DisplayMgrInvoke::SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  DisplayMgrInvoke::InvokeSnapshotHitRegionToClipCache(clipDescriptor);
  clipSnapshotEvent = static_cast<short>(param_1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004fefc0
undefined TDisplayMgr::SetMapTileIconVariantTriplet(undefined1* param_1) {
  tileIcon10 = param_1[0];
  tileIcon11 = param_1[1];
  tileIcon12 = param_1[2];
  DisplayMgrInvoke::NoOpCallback_00498ca0(&tileIcon10);
  return 0;
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
          window->OrphanCallChain_C2_I10_0048e120();
        } else {
          window->OrphanCallChain_C2_I12_0048dc90(kTagOkOkOk, 1);
        }
      }
    }
    window = static_cast<TWindow*>(cursor.NextWindow());
  }
  return 0;
}
