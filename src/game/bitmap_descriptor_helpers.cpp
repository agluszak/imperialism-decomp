#include "game/bitmap_descriptor_helpers.h"

#include <string.h>

#include "game/CDib.h"
#include "game/TAnimation.h"
#include "game/TDisplayMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/quickdraw_globals.h"
#include "game/mfc.h"

extern "C" TModuleLibraryCacheTableStateB* g_pModuleLibraryCacheState;
extern void* g_pScopedMapQuickDrawDcHandleObject;

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
  StretchDIBits(hdc, x, y, width, height, 0, 0, width, height, dib->m_dibBits,
                dib->m_pInfoHeader, DIB_RGB_COLORS, SRCCOPY);
}

static void ReleaseBitmapLoaderHandle(TBitmapResourceLoader** loaderHandle) {
  if (loaderHandle == nullptr) {
    return;
  }
  delete *loaderHandle;
  ::operator delete(loaderHandle);
}

struct BitmapSurfaceNode {
  void* pixelBits;
  short stride;
  short field06;
  int field08;
  int field0c;
  int field10;
  int field14;
  int field18;
  CDib* dib;
  short bitDepth;
  int headerPointer;
};

struct BitmapSurfaceContextDescriptor {
  int field00;
  int field04;
  short field08;
  short pad0a;
  int rectLeft;
  int rectTop;
  int rectRight;
  int rectBottom;
  short field1c;
  short pad1e;
  int field20;
  int* surfaceNodeSlot;
  char pad28[8];
  const char* debugSourcePath;
};

static void ResetBitmapSurfaceContextDescriptor(BitmapSurfaceContextDescriptor* descriptor) {
  descriptor->field00 = 0;
  descriptor->field04 = 0;
  descriptor->field08 = 0;
  descriptor->field1c = 0;
  descriptor->field20 = 0;
  descriptor->rectLeft = 0;
  descriptor->rectTop = 0;
  descriptor->rectRight = 0;
  descriptor->rectBottom = 0;
  descriptor->surfaceNodeSlot = nullptr;
  descriptor->debugSourcePath = kQuickDrawDebugSourcePath;
}

static BitmapSurfaceNode* InitializeBitmapSurfaceNode(int width, int height, int bitDepth) {
  BitmapSurfaceNode* node =
      static_cast<BitmapSurfaceNode*>(::operator new(sizeof(BitmapSurfaceNode)));
  memset(node, 0, sizeof(BitmapSurfaceNode));

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
    const int rowBits =
        node->dib->m_pInfoHeader->bmiHeader.biWidth * node->dib->m_pInfoHeader->bmiHeader.biBitCount;
    node->stride = static_cast<short>(((rowBits + 31) / 32) * 4);
    node->field10 = node->dib->m_pInfoHeader->bmiHeader.biWidth;
    node->field14 = abs(node->dib->m_pInfoHeader->bmiHeader.biHeight);
  } else {
    node->field10 = width;
    node->field14 = height;
  }
  node->bitDepth = static_cast<short>(bitDepth);
  node->field18 = height;
  node->headerPointer = reinterpret_cast<int>(node->dib->m_pInfoHeader);
  return node;
}

static bool InitializeBitmapDescriptorNodeFromResourceSurface(
    BitmapSurfaceContextDescriptor* descriptor, int width, int height, int bitDepth) {
  int* surfaceNodeSlot = static_cast<int*>(::operator new(sizeof(BitmapSurfaceNode*)));
  *reinterpret_cast<BitmapSurfaceNode**>(surfaceNodeSlot) = nullptr;
  descriptor->surfaceNodeSlot = surfaceNodeSlot;

  BitmapSurfaceNode* node = InitializeBitmapSurfaceNode(width, height, bitDepth);
  *reinterpret_cast<BitmapSurfaceNode**>(surfaceNodeSlot) = node;
  if (node == nullptr || node->pixelBits == nullptr) {
    return false;
  }

  descriptor->field04 = node->dib->m_pInfoHeader != nullptr
                            ? node->dib->m_pInfoHeader->bmiHeader.biHeight
                            : 0;
  descriptor->field08 = node->stride;
  descriptor->rectLeft = 0;
  descriptor->rectTop = 0;
  descriptor->rectRight = node->field10;
  descriptor->rectBottom = node->field14;
  descriptor->field20 = node->headerPointer;
  return true;
}

} // namespace

// GLOBAL: IMPERIALISM 0x006a1ca0
TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;

// Statically initialized to the sentinel address (the dword at 0x006950f8 holds
// 0x006a1ca0 in the original), not null — the restore path in
// BuildStrategicMapCommodityIconAtlasFrom700To722 captures this before the first
// SetActiveQuickDrawSurfaceContext and would otherwise restore a null context.
// GLOBAL: IMPERIALISM 0x006950f8
TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead =
    &g_defaultQuickDrawSurfaceSentinel;
// GLOBAL: IMPERIALISM 0x006a1da0
CDC* g_pQuickDrawMemoryDc = nullptr;
// GLOBAL: IMPERIALISM 0x006a1dbc
HGDIOBJ g_hQuickDrawSavedBitmap = nullptr;
// GLOBAL: IMPERIALISM 0x006a1db0
int g_nActiveQuickDrawSurfaceFlags = 0;

// FUNCTION: IMPERIALISM 0x00495c40
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds) {
  CDC* dcTarget = g_pQuickDrawMemoryDc;
  if (dcTarget == nullptr && g_pScopedMapQuickDrawDcHandleObject != nullptr) {
    dcTarget = static_cast<CDC*>(g_pScopedMapQuickDrawDcHandleObject);
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
BitmapSurfaceNode* InitializeBitmapSurfaceFromResourceDescriptor(BitmapSurfaceNode* node, int width,
                                                                 int height, int bitDepth) {
  (void)node;
  return InitializeBitmapSurfaceNode(width, height, bitDepth);
}

// FUNCTION: IMPERIALISM 0x00495e20
void InitializeBitmapDescriptorRecordState(int record) {
  ResetBitmapSurfaceContextDescriptor(reinterpret_cast<BitmapSurfaceContextDescriptor*>(record));
}

// FUNCTION: IMPERIALISM 0x00495eb0
bool InitializeBitmapDescriptorNodeFromResourceSurface(int record, int width, int height,
                                                       int bitDepth) {
  return InitializeBitmapDescriptorNodeFromResourceSurface(
      reinterpret_cast<BitmapSurfaceContextDescriptor*>(record), width, height, bitDepth);
}

// FUNCTION: IMPERIALISM 0x00495fd0
void WrapperFor_FreeHeapBufferIfNotNull_At00495fd0(int record) {
  BitmapSurfaceContextDescriptor* descriptor =
      reinterpret_cast<BitmapSurfaceContextDescriptor*>(record);
  if (descriptor->surfaceNodeSlot == nullptr) {
    return;
  }

  BitmapSurfaceNode* node =
      *reinterpret_cast<BitmapSurfaceNode**>(descriptor->surfaceNodeSlot);
  if (node != nullptr) {
    delete node->dib;
    ::operator delete(node);
  }
  ::operator delete(descriptor->surfaceNodeSlot);
  descriptor->surfaceNodeSlot = nullptr;
  descriptor->field04 = 0;
  descriptor->field08 = 0;
  descriptor->field20 = 0;
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
void SetActiveQuickDrawSurfaceContext(TQuickDrawSurfaceContext* context, undefined4 flags) {
  if (g_pActiveQuickDrawSurfaceContextHead == context) {
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

  if (context != &g_defaultQuickDrawSurfaceSentinel) {
    BitmapSurfaceContextDescriptor* descriptor =
        reinterpret_cast<BitmapSurfaceContextDescriptor*>(context);
    BitmapSurfaceNode* node = *reinterpret_cast<BitmapSurfaceNode**>(descriptor->surfaceNodeSlot);
    SetActiveQuickDrawSurfaceContext_Impl(node != nullptr ? node->dib : nullptr, nullptr);
  }

  g_pActiveQuickDrawSurfaceContextHead = context;
  g_nActiveQuickDrawSurfaceFlags = static_cast<int>(flags);
  g_pActiveQuickDrawSurfaceContext = context;
}

// FUNCTION: IMPERIALISM 0x00496270
void GetActiveQuickDrawSurfaceContextAndFlags(undefined4* outContext, undefined4* outFlags) {
  *outContext = reinterpret_cast<undefined4>(g_pActiveQuickDrawSurfaceContextHead);
  *outFlags = static_cast<undefined4>(g_nActiveQuickDrawSurfaceFlags);
}

// FUNCTION: IMPERIALISM 0x004962a0
void* GetSurfaceObjectAtContextOffset24(int context) {
  return *reinterpret_cast<void**>(context + 0x24);
}

// FUNCTION: IMPERIALISM 0x004962c0
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(int* outContext, short bitDepth,
                                                           RECT* bounds, int hintField18, int arg4,
                                                           int arg5) {
  (void)hintField18;
  (void)arg4;
  (void)arg5;

  BitmapSurfaceContextDescriptor* descriptor = static_cast<BitmapSurfaceContextDescriptor*>(
      ::operator new(sizeof(BitmapSurfaceContextDescriptor)));
  ResetBitmapSurfaceContextDescriptor(descriptor);

  *outContext = reinterpret_cast<int>(descriptor);

  const int width = bounds->right - bounds->left;
  const int height = bounds->bottom - bounds->top;
  const bool loaded =
      InitializeBitmapDescriptorNodeFromResourceSurface(descriptor, width, height, bitDepth);
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

// Frameless (FPO) in the original; force FPO locally so /Oy- doesn't add an ebp
// frame (heuristics #2).
#pragma optimize("y", on)
// FUNCTION: IMPERIALISM 0x00497300
void* GetSurfaceHeaderFromSurfaceObject(void* surfaceObject) {
  return **reinterpret_cast<void***>(surfaceObject);
}
#pragma optimize("", on)

// FUNCTION: IMPERIALISM 0x005c3b70
int LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId) {
  undefined4 savedContext = 0;
  undefined4 savedFlags = 0;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);

  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(resourceId);
  TBitmapResourceLoader* loader = loaderHandle != nullptr ? *loaderHandle : nullptr;
  if (loader == nullptr) {
    ::operator delete(loaderHandle);
    return 0;
  }

  RECT bitmapRect = loader->bitmapRect;
  int outContext = 0;
  if (g_pDisplayMgr != nullptr) {
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&outContext, 8, &bitmapRect);
  }
  if (outContext == 0) {
    ReleaseBitmapLoaderHandle(loaderHandle);
    return 0;
  }

  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(outContext),
                                   savedFlags);
  void* surfaceObject = GetSurfaceObjectAtContextOffset24(outContext);
  ReturnConstantTrueQuickDrawFlag(surfaceObject);

  loader->EnsureBitmapResourceLoadedAndCopyRectSize();
  loader->flags |= 1;
  ResetQuickDrawStrokeState();
  BlitBitmapResourceLoaderToActiveDc(loaderHandle, &bitmapRect);

  ReleaseBitmapLoaderHandle(loaderHandle);

  NoOpQuickDrawLifecycleHookB(surfaceObject);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<TQuickDrawSurfaceContext*>(savedContext),
                                   savedFlags);
  return outContext;
}
