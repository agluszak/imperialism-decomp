#include "game/TDisplayMgr.h"

#include <new>
#include <windows.h>

#include "game/bitmap_descriptor_helpers.h"
#include "game/CTemporaryRegion.h"
#include "game/TAssetMgr.h"
#include "game/TPtrList.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/CWMgrIterator.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
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

// FUNCTION: IMPERIALISM 0x004931e0
void PlayDefaultMessageBeep(...) {
  MessageBeep(static_cast<UINT>(-1));
}

// FUNCTION: IMPERIALISM 0x00497230
GlobalViewportRectDefaultsRecord** InitializeGlobalRectDefaultsIfUninitialized() {
  if (g_pGlobalViewportRectDefaultsRecord == nullptr) {
    g_globalViewportRectDefaultsRecord.field0 = 0;
    g_globalViewportRectDefaultsRecord.viewportBounds.left = 0;
    g_globalViewportRectDefaultsRecord.viewportBounds.top = 0;
    g_globalViewportRectDefaultsRecord.viewportBounds.right = 0x280;
    g_globalViewportRectDefaultsRecord.viewportBounds.bottom = 0x1e0;
    g_pGlobalViewportRectDefaultsRecord = &g_globalViewportRectDefaultsRecord;
  }
  return &g_pGlobalViewportRectDefaultsRecord;
}

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
      eventCode0e(0), field18(0), clipSnapshotEvent(0), field1e(0), turnOrderList(0) {
  hiliteColor.rgbBlue = 0;
  hiliteColor.rgbGreen = 0;
  hiliteColor.rgbRed = 0;
  hiliteColor.rgbReserved = 0;
  savedHiliteColor.rgbBlue = 0;
  savedHiliteColor.rgbGreen = 0;
  savedHiliteColor.rgbRed = 0;
  savedHiliteColor.rgbReserved = 0;
}

// SYNTHETIC: IMPERIALISM 0x004fe7f0
// TDisplayMgr::`scalar deleting destructor'
TDisplayMgr::~TDisplayMgr() {}

// FUNCTION: IMPERIALISM 0x004fe840
void TDisplayMgr::InitializeWindowAndMBarSize() {
  TPtrList* list = new TPtrList();
  if (list == 0) {
    turnOrderList = 0;
  } else {
    turnOrderList = list;
    list->recordSize14 = 4;
  }

  dialogActiveFlag = 0;

  AssignUiFontGlobalFromLiteral(g_cstrUiFontBelweBdBt, g_szUiFontLiteralBelweBdBt);
  AssignUiFontGlobalFromLiteral(g_cstrUiFontBelweLight, g_szUiFontLiteralBelweLight);
  AssignUiFontGlobalFromLiteral(g_cstrUiFontPalatino, g_szUiFontLiteralPalatino);

  GlobalViewportRectDefaultsRecord** rectDefaultsHandle =
      InitializeGlobalRectDefaultsIfUninitialized();
  GlobalViewportRectDefaultsRecord* rectRecord = *rectDefaultsHandle;
  RECT viewportRect;
  CopyRect(&viewportRect, &rectRecord->viewportBounds);
  int width = rectRecord->viewportBounds.right - rectRecord->viewportBounds.left;
  int height = rectRecord->viewportBounds.bottom - rectRecord->viewportBounds.top;
  if (width < 0x281 && height < 0x1e1) {
    eventCode0e = kTurnEventSphereWindow;
  } else {
    eventCode0e = kTurnEventMoveableMainWindow;
  }

  SetMenuHeight(0);

  TView* dialogRoot = g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(
      DecodeTurnEventCode(eventCode0e));
  if (dialogRoot == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0xb0);
  }
  activeDialog = dialogRoot;
  field18 = InitializeTurnOrderNavigationDialogByViewportSize_Impl(0x80);
  ExamineGWorld();
}

// FUNCTION: IMPERIALISM 0x004fea60
void TDisplayMgr::Free() {
  delete g_pPrimaryRenderSurfaceContext;
  g_pPrimaryRenderSurfaceContext = 0;
  turnOrderList->SelfDelete();
  delete this;
}

// FUNCTION: IMPERIALISM 0x004feab0
void TDisplayMgr::MakeNewGWorld(TQuickDrawSurfaceContext*& outContext, short bitDepth,
                                const RECT& bounds) {
  short result = NewGWorld(&outContext, bitDepth, &bounds, field18, 0, 0);
  if (result != 0) {
    NewGWorld(&outContext, bitDepth, &bounds, field18, 0, 0);
    NewGWorld(&outContext, bitDepth, &bounds, field18, 0, 0);
  }
}

// Frees the TQuickDrawSurfaceContext record held in `slot` and clears the slot.
// `this` is unused, but the callsites all dispatch through g_pDisplayMgr.
// FUNCTION: IMPERIALISM 0x004feb50
void TDisplayMgr::RemoveGWorld(TQuickDrawSurfaceContext*& surface) {
  delete surface;
  surface = 0;
}

// FUNCTION: IMPERIALISM 0x004feb80
void TDisplayMgr::ExamineGWorld() {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    RECT bounds = {-64, -64, 0x280, 0x220};
    MakeNewGWorld(g_pPrimaryRenderSurfaceContext, 8, bounds);
  }
}

// FUNCTION: IMPERIALISM 0x004febd0
void TDisplayMgr::AboutToLoseControl(unsigned char) {
  if (dialogActiveFlag != 0 && activeDialog != 0) {
    activeDialog->GetDrawableRegion(0);
  }
  SetMenuHeight(1);
  HiliteColor(&savedHiliteColor);
}

// FUNCTION: IMPERIALISM 0x004fec20
void TDisplayMgr::CloseBooks() {
  if (g_nUiInvalidationAssertFlagLine471 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x1d7);
  }
}

// FUNCTION: IMPERIALISM 0x004fec50
void TDisplayMgr::DismissTouchyFloaters(TToolboxEvent*) {
  if (g_nUiInvalidationAssertFlagLine495 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x1ef);
  }
}

// FUNCTION: IMPERIALISM 0x004fec80
void TDisplayMgr::ModalMessage(CString message, const POINT& messagePosition) {
  g_pUiRuntimeContext->ModalMessage(message, messagePosition);
}

// FUNCTION: IMPERIALISM 0x004fed00
void TDisplayMgr::RegainControl(unsigned char) {
  if (dialogActiveFlag != 0 && activeDialog != 0) {
    activeDialog->InvalidateOffsetRegionUsingChildClipRect(0);
    activeDialog->ForceRedraw();
  }
  SetMenuHeight(0);
  HiliteColor(&hiliteColor);
}

// FUNCTION: IMPERIALISM 0x004fed50
void TDisplayMgr::SetMenuHeight(unsigned char) {}

// FUNCTION: IMPERIALISM 0x004fed70
void TDisplayMgr::SetBitDepth(unsigned char bitDepth) {
  if (dialogActiveFlag != 0) {
    if (bitDepth != 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x266);
    } else {
      TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x268);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004fedc0
void TDisplayMgr::UpdateTheGWorld(short eventCode) {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    return;
  }

  int savedFlags = 0;
  TQuickDrawSurfaceContext* savedContext = 0;
  CTemporaryRegion surfaceGuard;
  GetClip(surfaceGuard.tempRgn);
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedFlags);
  LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));

  TView* mainControl = activeDialog->ResolveControlByTag(kControlTagMain);
  if (mainControl == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x28a);
    return;
  }

  TView* mainView = mainControl;
  CRect queryBounds;
  mainView->QueryBounds(&queryBounds);

  RECT clipRect;
  clipRect.left = queryBounds.left;
  clipRect.top = queryBounds.top;
  clipRect.right = queryBounds.right;
  clipRect.bottom = queryBounds.bottom;

  SetGlobalQuickDrawOrigin(static_cast<short>(mainView->ownerLocalX),
                           static_cast<short>(mainView->ownerLocalY));
  ClipRect(&clipRect);
  mainView->Draw(&queryBounds);

  UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  SetGWorld(savedContext, savedFlags);
  SetClip(surfaceGuard.tempRgn);
  clipSnapshotEvent = eventCode;
}

// FUNCTION: IMPERIALISM 0x004fefc0
void TDisplayMgr::SetHiliteColor(const RGBQUAD* color) {
  hiliteColor.rgbBlue = color->rgbBlue;
  hiliteColor.rgbGreen = color->rgbGreen;
  hiliteColor.rgbRed = color->rgbRed;
  HiliteColor(&hiliteColor);
}

// FUNCTION: IMPERIALISM 0x004ff000
void TDisplayMgr::CloseFloaters() {
  CWMgrIterator cursor;
  cursor.Reset(1);
  TWindow* window = static_cast<TWindow*>(cursor.FirstWindow());
  while (cursor.More() != 0) {
    if (window != 0) {
      if (window->IsActionable() != 0 && window->controlValue3c == kClass99WindowId) {
        if (window->IsModal() != 0) {
          window->Dismiss(kTagOkOkOk, 1);
        } else {
          window->CloseAndFree();
        }
      }
    }
    window = static_cast<TWindow*>(cursor.NextWindow());
  }
}
