#include "game/bitmap_descriptor_helpers.h"

#include <string.h>

#include "game/CDib.h"
#include "game/TAnimation.h"
#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"

namespace {

const char kQuickDrawDebugSourcePath[] = "D:\\Ambit\\QuickDraw.cpp";

static void StretchDibitsFromCdibToDc(CDib* dib, CDC* dcWrapper, int x, int y) {
  if (dib == nullptr || dib->m_pInfoHeader == nullptr || dcWrapper == nullptr) {
    return;
  }

  HDC hdc = dcWrapper->GetSafeHdc();
  int width = dib->m_pInfoHeader->bmiHeader.biWidth;
  int height = dib->m_pInfoHeader->bmiHeader.biHeight;
  if (height < 0) {
    height = -height;
  }
  StretchDIBits(hdc, x, y, width, height, 0, 0, width, height, dib->m_dibBits, dib->m_pInfoHeader,
                DIB_RGB_COLORS, SRCCOPY);
}

static void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  delete *loaderHandle;
  ::operator delete(loaderHandle);
}

static void ResetBitmapSurfaceContextDescriptor(TBitmapSurfaceContextDescriptor* descriptor) {
  descriptor->field00 = 0;
  descriptor->blitSurface.pixelBits = 0;
  descriptor->blitSurface.stride = 0;
  descriptor->blitSurface.pad06 = 0;
  descriptor->field1c = 0;
  descriptor->surfaceDib = 0;
  descriptor->clipRect.left = 0;
  descriptor->clipRect.top = 0;
  descriptor->clipRect.right = 0;
  descriptor->clipRect.bottom = 0;
  descriptor->SetSurfaceNodeSlot(nullptr);
  descriptor->quickDrawColor = 0;
  descriptor->transparentBlitColor = 0;
  descriptor->debugSourcePath = kQuickDrawDebugSourcePath;
}

static TBitmapSurfaceNode* InitializeBitmapSurfaceNode(int width, int height, int bitDepth) {
  TBitmapSurfaceNode* node =
      static_cast<TBitmapSurfaceNode*>(::operator new(sizeof(TBitmapSurfaceNode)));
  memset(node, 0, sizeof(TBitmapSurfaceNode));

  node->dib = new CDib(width, height, bitDepth);
  if (node->dib == nullptr) {
    ::operator delete(node);
    return nullptr;
  }

  if (g_pModuleLibraryCacheState != nullptr) {
    CDib* paletteDib = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(0x3b6);
    if (paletteDib != nullptr && paletteDib->m_pInfoHeader != nullptr &&
        node->dib->m_pInfoHeader != nullptr &&
        paletteDib->m_paletteCount == node->dib->m_paletteCount) {
      memcpy(node->dib->m_colorTablePixels, paletteDib->m_colorTablePixels,
             node->dib->m_paletteCount * sizeof(RGBQUAD));
    }
  }

  node->dib->BuildPaletteFromRgbQuadBuffer();
  node->dib->EnsureDibSectionCreated(nullptr);

  node->pixelBits = node->dib->m_dibBits;
  if (node->dib->m_pInfoHeader != nullptr) {
    const int rowBits = node->dib->m_pInfoHeader->bmiHeader.biWidth *
                        node->dib->m_pInfoHeader->bmiHeader.biBitCount;
    node->stride = static_cast<short>(((rowBits + 31) / 32) * 4);
    node->pixelWidth10 = node->dib->m_pInfoHeader->bmiHeader.biWidth;
    node->pixelHeight14 = abs(node->dib->m_pInfoHeader->bmiHeader.biHeight);
  } else {
    node->pixelWidth10 = width;
    node->pixelHeight14 = height;
  }
  node->requestedHeight18 = height;
  return node;
}

static bool
InitializeBitmapDescriptorNodeFromResourceSurfaceImpl(TBitmapSurfaceContextDescriptor* descriptor,
                                                      int width, int height, int bitDepth) {
  TBitmapSurfaceNode** surfaceNodeSlot =
      static_cast<TBitmapSurfaceNode**>(::operator new(sizeof(TBitmapSurfaceNode*)));
  *surfaceNodeSlot = nullptr;
  descriptor->SetSurfaceNodeSlot(surfaceNodeSlot);

  TBitmapSurfaceNode* node = InitializeBitmapSurfaceNode(width, height, bitDepth);
  *surfaceNodeSlot = node;
  if (node == nullptr || node->pixelBits == nullptr) {
    return false;
  }

  // Original (0x495eb0): +0x4 = dib bits pointer, +0x8 = (biWidth + 3) & ~3 as a
  // 16-bit stride, clip rect = the dib's width/height, +0x20 = the CDib itself.
  descriptor->blitSurface.pixelBits = node->dib->m_dibBits;
  descriptor->blitSurface.stride =
      static_cast<short>((node->dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  descriptor->clipRect.left = 0;
  descriptor->clipRect.top = 0;
  descriptor->clipRect.right = node->pixelWidth10;
  descriptor->clipRect.bottom = node->pixelHeight14;
  descriptor->surfaceDib = node->dib;
  return true;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00495c40
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds) {
  CDC* dcTarget = g_pQuickDrawMemoryDc;
  if (dcTarget == nullptr && g_pScopedMapQuickDrawDcHandleObject != nullptr) {
    dcTarget = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (handle == nullptr || bounds == nullptr) {
    return;
  }

  TBitmapResourceLoader* loader = *handle;
  if (loader == nullptr || loader->bitmapResource == nullptr || dcTarget == nullptr) {
    return;
  }

  StretchDibitsFromCdibToDc(loader->bitmapResource, dcTarget, bounds->left, bounds->top);
}

// FUNCTION: IMPERIALISM 0x00495d00
TBitmapSurfaceNode* InitializeBitmapSurfaceFromResourceDescriptor(TBitmapSurfaceNode* node,
                                                                  int width, int height,
                                                                  int bitDepth) {
  (void)node;
  return InitializeBitmapSurfaceNode(width, height, bitDepth);
}

// FUNCTION: IMPERIALISM 0x00495e20
void TBitmapSurfaceContextDescriptor::Reset() {
  ResetBitmapSurfaceContextDescriptor(this);
}

// FUNCTION: IMPERIALISM 0x00495eb0
bool TBitmapSurfaceContextDescriptor::InitializeSurfaceNode(int width, int height, int bitDepth) {
  return InitializeBitmapDescriptorNodeFromResourceSurfaceImpl(this, width, height, bitDepth);
}

// FUNCTION: IMPERIALISM 0x00495fd0
void TBitmapSurfaceContextDescriptor::ReleaseSurfaceNode() {
  TBitmapSurfaceNode** slot = GetSurfaceNodeSlot();
  if (slot != nullptr) {
    TBitmapSurfaceNode* node = *slot;
    if (node != nullptr) {
      delete node->dib;
      ::operator delete(node);
    }
    ::operator delete(slot);
  }
  SetSurfaceNodeSlot(nullptr);
  blitSurface.pixelBits = 0;
  blitSurface.stride = 0;
  blitSurface.pad06 = 0;
  surfaceDib = 0;
}

// FUNCTION: IMPERIALISM 0x00496090
void SetActiveQuickDrawSurfaceContext_Impl(CDib* dibSurface, HDC referenceDc) {
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
void SetActiveQuickDrawSurfaceContext(TQuickDrawSurfaceContext* contextPtr, int flags) {
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
    TBitmapSurfaceNode* node = descriptor->GetSurfaceNode();
    SetActiveQuickDrawSurfaceContext_Impl(node != nullptr ? node->dib : nullptr, nullptr);
  }

  g_pActiveQuickDrawSurfaceContextHead = contextPtr;
  g_nActiveQuickDrawSurfaceFlags = flags;
  g_pActiveQuickDrawSurfaceContext = contextPtr;
}

// FUNCTION: IMPERIALISM 0x00496270
void GetActiveQuickDrawSurfaceContextAndFlags(TQuickDrawSurfaceContext** outContext,
                                              int* outFlags) {
  *outContext = g_pActiveQuickDrawSurfaceContextHead;
  *outFlags = g_nActiveQuickDrawSurfaceFlags;
}

// FUNCTION: IMPERIALISM 0x004962a0
void* GetSurfaceNodeSlot(TQuickDrawSurfaceContext* context) {
  return context->surfaceObject;
}

// FUNCTION: IMPERIALISM 0x004962c0
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(TQuickDrawSurfaceContext** outContext,
                                                         short bitDepth, RECT* bounds,
                                                         int hintField18, int arg4, int arg5) {
  (void)hintField18;
  (void)arg4;
  (void)arg5;

  TBitmapSurfaceContextDescriptor* descriptor = static_cast<TBitmapSurfaceContextDescriptor*>(
      ::operator new(sizeof(TBitmapSurfaceContextDescriptor)));
  ResetBitmapSurfaceContextDescriptor(descriptor);

  *outContext = descriptor;

  const int width = bounds->right - bounds->left;
  const int height = bounds->bottom - bounds->top;
  const bool loaded = descriptor->InitializeSurfaceNode(width, height, bitDepth);
  return loaded ? 0 : static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x004972c0
unsigned char ReturnConstantTrueQuickDrawFlag(void* surfaceObject) {
  (void)surfaceObject;
  return 1;
}

// FUNCTION: IMPERIALISM 0x004972e0
void NoOpQuickDrawLifecycleHookB(void* surfaceObject) {
  (void)surfaceObject;
}

// FUNCTION: IMPERIALISM 0x00497300
void* GetSurfaceNodePixelBits(void* surfaceObject) {
  return **reinterpret_cast<void***>(surfaceObject);
}

// FUNCTION: IMPERIALISM 0x00497c00
undefined4 QDLoadResource(TBitmapResourceLoader** handle) {
  (void)handle;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c3b70
TQuickDrawSurfaceContext*
LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId) {
  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);

  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  TBitmapResourceLoader* loader = loaderHandle != nullptr ? *loaderHandle : nullptr;
  if (loader == nullptr) {
    ::operator delete(loaderHandle);
    return 0;
  }

  RECT bitmapRect = loader->bitmapRect;
  TQuickDrawSurfaceContext* outContext = 0;
  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&outContext, 8, &bitmapRect);
  }
  if (outContext == 0) {
    ReleaseBitmapLoaderHandle(loaderHandle);
    return 0;
  }

  SetActiveQuickDrawSurfaceContext(outContext, savedFlags);
  void* surfaceObject = GetSurfaceNodeSlot(outContext);
  ReturnConstantTrueQuickDrawFlag(surfaceObject);

  loader->EnsureBitmapResourceLoadedAndCopyRectSize();
  loader->flags |= 1;
  ResetQuickDrawStrokeState();
  BlitBitmapResourceLoaderToActiveDc(loaderHandle, &bitmapRect);

  ReleaseBitmapLoaderHandle(loaderHandle);

  NoOpQuickDrawLifecycleHookB(surfaceObject);
  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  return outContext;
}
