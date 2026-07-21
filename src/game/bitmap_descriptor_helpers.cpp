#include "game/bitmap_descriptor_helpers.h"

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
  descriptor->blitSurface.field18 = 0;
  descriptor->blitSurface.surfaceDib = 0;
  descriptor->blitSurface.clipRect.left = 0;
  descriptor->blitSurface.clipRect.top = 0;
  descriptor->blitSurface.clipRect.right = 0;
  descriptor->blitSurface.clipRect.bottom = 0;
  descriptor->SetSurfaceNodeSlot(nullptr);
  descriptor->blitSurface.quickDrawColor = 0;
  descriptor->blitSurface.transparentBlitColor = 0;
  descriptor->debugSourcePath = kQuickDrawDebugSourcePath;
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

// Constructor of the QuickDraw bitmap-surface node: `new`s a backing CDib(width, height,
// bitDepth), seeds its color table from the module cache's shared default LOGPALETTE, builds
// the palette + DIB section, and caches the pixel bits / dword-aligned stride / dimensions.
// Real __thiscall ctor (returns `this`); reached as `new TBitmapSurfaceNode(...)` from
// TBitmapSurfaceContextDescriptor::InitializeSurfaceNode (0x495eb0). The +0x18 field stores
// the low 16 bits of `bitDepth` (a 16-bit write), not a height.
// FUNCTION: IMPERIALISM 0x00495d00
TBitmapSurfaceNode::TBitmapSurfaceNode(int width, int height, int bitDepth) {
  dib = new CDib(width, height, bitDepth);
  dib->CopyRgbQuadTableFrom(g_pModuleLibraryCacheState->ResolveDefaultLogPalette());
  dib->BuildPaletteFromRgbQuadBuffer();
  dib->EnsureDibSectionCreated(nullptr);
  pixelBits = dib->m_dibBits;
  stride = static_cast<short>((dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  CPoint dims;
  CPoint* d = dib->CopyBitmapDimensionsToPoint(&dims);
  field08 = 0;
  bitDepth18 = static_cast<short>(bitDepth);
  field0c = 0;
  pixelWidth10 = d->x;
  pixelHeight14 = d->y;
}

// FUNCTION: IMPERIALISM 0x00495e20
void TBitmapSurfaceContextDescriptor::Reset() {
  ResetBitmapSurfaceContextDescriptor(this);
}

// FUNCTION: IMPERIALISM 0x00495eb0
bool TBitmapSurfaceContextDescriptor::InitializeSurfaceNode(int width, int height, int bitDepth) {
  SetSurfaceNodeSlot(
      static_cast<TBitmapSurfaceNode**>(::operator new(sizeof(TBitmapSurfaceNode*))));
  *GetSurfaceNodeSlot() = new TBitmapSurfaceNode(width, height, bitDepth);

  // Original (0x495eb0): +0x4 = dib bits pointer, +0x8 = (biWidth + 3) & ~3 as a 16-bit
  // stride, clip rect = the CDib's own width/height (re-read through
  // CopyBitmapDimensionsToPoint, not the cached node fields), +0x20 = the CDib itself. The
  // node is re-read through the slot each time (no cached local), matching the original.
  blitSurface.pixelBits = static_cast<unsigned char*>((*GetSurfaceNodeSlot())->dib->m_dibBits);
  blitSurface.stride =
      static_cast<short>(((*GetSurfaceNodeSlot())->dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  CPoint dims;
  CPoint* d = (*GetSurfaceNodeSlot())->dib->CopyBitmapDimensionsToPoint(&dims);
  blitSurface.clipRect.left = 0;
  blitSurface.clipRect.top = 0;
  blitSurface.clipRect.right = d->x;
  blitSurface.clipRect.bottom = d->y;
  blitSurface.surfaceDib = (*GetSurfaceNodeSlot())->dib;
  return *GetSurfaceNodeSlot() != nullptr;
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
  blitSurface.surfaceDib = 0;
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
  return context->blitSurface.surfaceObject;
}

// FUNCTION: IMPERIALISM 0x004962c0
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(TQuickDrawSurfaceContext** outContext,
                                                         short bitDepth, const RECT* bounds,
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
    g_pDisplayMgr->MakeNewGWorld(outContext, 8, bitmapRect);
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
