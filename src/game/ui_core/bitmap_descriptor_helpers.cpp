#include "game/ui_core/bitmap_descriptor_helpers.h"

#include "game/gfx/CDib.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/mfc.h"

namespace {

// The loader's original vtable has no destructor slot; every caller owns this exact type.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
static void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader != 0) {
    loader->ReleaseBitmapResource();
    loader->flags &= static_cast<unsigned char>(~1);
    delete loader;
  }
  delete loaderHandle;
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

} // namespace

// FUNCTION: IMPERIALISM 0x00495c40
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds) {
  CDC* targetDc = g_pQuickDrawMemoryDc;
  if (targetDc == 0) {
    targetDc = g_pScopedMapQuickDrawDcHandleObject;
  }

  g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(targetDc, FALSE);

  POINT destination = {bounds->left, bounds->top};
  targetDc = g_pQuickDrawMemoryDc;
  if (targetDc == 0) {
    targetDc = g_pScopedMapQuickDrawDcHandleObject;
  }
  (*handle)->bitmapResource->StretchDibitsFromStoredBitmapToHdc(targetDc, &destination);
}

// FUNCTION: IMPERIALISM 0x00496090
void BindGWorldSurfaceToMemoryDC(CDib* dibSurface, HDC referenceDc) {
  if (g_pQuickDrawMemoryDc != nullptr) {
    delete g_pQuickDrawMemoryDc;
    g_pQuickDrawMemoryDc = nullptr;
  }

  g_pQuickDrawMemoryDc = new CDC();
  HDC memoryDc = CreateCompatibleDC(referenceDc);
  g_pQuickDrawMemoryDc->Attach(memoryDc);
  if (dibSurface != nullptr && dibSurface->m_hBitmap != nullptr) {
    SelectObject(memoryDc, dibSurface->m_hBitmap);
  }
}

// FUNCTION: IMPERIALISM 0x004961b0
void SetGWorld(TQuickDrawSurfaceContext* contextPtr, int flags) {
  if (g_pActiveQuickDrawSurfaceContextHead == contextPtr) {
    return;
  }

  if (g_pActiveQuickDrawSurfaceContextHead != nullptr &&
      g_pActiveQuickDrawSurfaceContextHead != &g_defaultQuickDrawSurfaceSentinel) {
    if (g_hQuickDrawSavedBitmap != nullptr && g_pQuickDrawMemoryDc != nullptr) {
      SelectObject(g_pQuickDrawMemoryDc->GetSafeHdc(), g_hQuickDrawSavedBitmap);
    }
    g_hQuickDrawSavedBitmap = nullptr;
    if (g_pQuickDrawMemoryDc != nullptr) {
      delete g_pQuickDrawMemoryDc;
      g_pQuickDrawMemoryDc = nullptr;
    }
  }

  if (contextPtr != &g_defaultQuickDrawSurfaceSentinel) {
    TBitmapSurfaceContextDescriptor* descriptor =
        static_cast<TBitmapSurfaceContextDescriptor*>(contextPtr);
    TBitmapSurfaceNode* node = descriptor->GetPixMap();
    BindGWorldSurfaceToMemoryDC(node != nullptr ? node->dib : nullptr, nullptr);
  }

  g_pActiveQuickDrawSurfaceContextHead = contextPtr;
  g_nActiveQuickDrawSurfaceFlags = flags;
  g_pActiveQuickDrawSurfaceContext = contextPtr;
}

// FUNCTION: IMPERIALISM 0x00496270
void GetGWorld(TQuickDrawSurfaceContext** outContext, int* outFlags) {
  *outContext = g_pActiveQuickDrawSurfaceContextHead;
  *outFlags = g_nActiveQuickDrawSurfaceFlags;
}

// FUNCTION: IMPERIALISM 0x004962a0
TBitmapSurfaceNode** GetGWorldPixMap(TQuickDrawSurfaceContext* context) {
  return static_cast<TBitmapSurfaceNode**>(context->blitSurface.surfaceObject);
}

// FUNCTION: IMPERIALISM 0x004962c0
short NewGWorld(TQuickDrawSurfaceContext** outContext, short bitDepth, const RECT* bounds,
                int unusedHint, int unusedArg4, int unusedArg5) {
  (void)unusedHint;
  (void)unusedArg4;
  (void)unusedArg5;

  TBitmapSurfaceContextDescriptor* descriptor = new TBitmapSurfaceContextDescriptor;
  *outContext = descriptor;

  RECT copiedBounds;
  CopyRect(&copiedBounds, bounds);
  descriptor->InitializeSurfaceNode(copiedBounds.right - copiedBounds.left,
                                    copiedBounds.bottom - copiedBounds.top, bitDepth);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004972c0
unsigned char LockPixels(TBitmapSurfaceNode** pixMap) {
  (void)pixMap;
  return 1;
}

// FUNCTION: IMPERIALISM 0x004972e0
void UnlockPixels(TBitmapSurfaceNode** pixMap) {
  (void)pixMap;
}

// FUNCTION: IMPERIALISM 0x00497300
unsigned char* GetPixBaseAddr(TBitmapSurfaceNode** pixMap) {
  return (*pixMap)->pixelBits;
}

// FUNCTION: IMPERIALISM 0x00497c00
int QDLoadResource(TBitmapResourceLoader** handle) {
  (void)handle;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3b70
TQuickDrawSurfaceContext*
LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId) {
  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetGWorld(&savedContext, &savedFlags);

  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = loaderHandle != nullptr ? *loaderHandle : nullptr;
  if (loader == nullptr) {
    delete loaderHandle;
    return 0;
  }

  RECT bitmapRect;
  CopyRect(&bitmapRect, &loader->bitmapRect);
  TQuickDrawSurfaceContext* outContext = 0;
  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->MakeNewGWorld(outContext, 8, bitmapRect);
  }
  if (outContext == 0) {
    ReleaseBitmapLoaderHandle(loaderHandle);
    return 0;
  }

  SetGWorld(outContext, savedFlags);
  TBitmapSurfaceNode** pixMap = GetGWorldPixMap(outContext);
  LockPixels(pixMap);

  QDLoadResource(loaderHandle);
  loader = *loaderHandle;
  loader->EnsureBitmapResourceLoadedAndCopyRectSize();
  loader->flags |= 1;
  ResetQuickDrawStrokeState();
  BlitBitmapResourceLoaderToActiveDc(loaderHandle, &bitmapRect);

  ReleaseBitmapLoaderHandle(loaderHandle);

  UnlockPixels(pixMap);
  SetGWorld(savedContext, savedFlags);
  return outContext;
}
