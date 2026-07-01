#include "game/ClipStateRegion.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"

extern void* g_pScopedMapQuickDrawDcHandleObject;

undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);

int* Sprite__CollectNonTransparentPixels(void* this_obj, uint this_ptr);

static int RegisterClipRegionHandle(CBrush* brush, HRGN region);

// FUNCTION: IMPERIALISM 0x00495610
undefined4 DestroyClipStateRegionWrapperObject(ClipStateRegionWrapper* wrapperObject) {
  if ((wrapperObject != 0) && (wrapperObject->inner != 0)) {
    reinterpret_cast<void(__cdecl*)()>(WrapperFor_DeleteRegionHandleFromClipState_At00495520)();
    delete wrapperObject->inner;
  }
  delete wrapperObject;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00495820
ClipStateRegionWrapper* CreateClipStateRegionWrapperObject(void) {
  ClipStateRegionInner* innerObject = new ClipStateRegionInner();
  if (innerObject == 0) {
    return 0;
  }

  HRGN region = CreateRectRgn(0, 0, 0, 0);
  innerObject->attachRegistered = RegisterClipRegionHandle(&innerObject->brush, region) ? 1 : 0;

  ClipStateRegionWrapper* outerWrapper = new ClipStateRegionWrapper();
  if (outerWrapper == 0) {
    delete innerObject;
    return 0;
  }
  outerWrapper->inner = innerObject;
  return outerWrapper;
}

// FUNCTION: IMPERIALISM 0x004977a0
void CombineTwoRegionsIntoDestinationAndUpdateBox(ClipStateRegionWrapper* src1,
                                                  ClipStateRegionWrapper* src2,
                                                  ClipStateRegionWrapper* dst) {
  CBrush* brush2 = &src2->inner->brush;
  HRGN hrgnSrc2 = brush2 != nullptr ? static_cast<HRGN>(brush2->m_hObject) : nullptr;
  CBrush* brush1 = &src1->inner->brush;
  HRGN hrgnSrc1 = brush1 != nullptr ? static_cast<HRGN>(brush1->m_hObject) : nullptr;
  HRGN hrgnDst = static_cast<HRGN>(dst->inner->brush.m_hObject);
  CombineRgn(hrgnDst, hrgnSrc1, hrgnSrc2, RGN_OR);
  GetRgnBox(hrgnDst, &dst->inner->boundingBox);
}

// FUNCTION: IMPERIALISM 0x00497810
void ResetClipRegionAndReadBoundingRect(ClipStateRegionWrapper* region) {
  ClipStateRegionInner* inner = region->inner;
  inner->brush.DeleteObject();
  HRGN newRegion = CreateRectRgn(0, 0, 0, 0);
  RegisterClipRegionHandle(&inner->brush, newRegion);
  GetRgnBox(static_cast<HRGN>(inner->brush.m_hObject), &inner->boundingBox);
}

// FUNCTION: IMPERIALISM 0x00497bb0
void CombineOptionalSourceRegionIntoDestinationAndUpdateBox(ClipStateRegionWrapper* src,
                                                            ClipStateRegionWrapper* dst) {
  CBrush* brushSrc = &src->inner->brush;
  HRGN hrgnSrc = brushSrc != nullptr ? static_cast<HRGN>(brushSrc->m_hObject) : nullptr;
  HRGN hrgnDst = static_cast<HRGN>(dst->inner->brush.m_hObject);
  CombineRgn(hrgnDst, hrgnSrc, nullptr, RGN_COPY);
  GetRgnBox(hrgnDst, &dst->inner->boundingBox);
}

// FUNCTION: IMPERIALISM 0x00497c00
undefined4 NoOpRuntimeCallback_00497c00(TBitmapResourceLoader** handle) {
  (void)handle;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00497ef0
int RebuildSpriteNonTransparentPolygonRegion(ClipStateRegionWrapper* region, void* spriteSurface) {
  void* animation = *reinterpret_cast<void**>(static_cast<char*>(spriteSurface) + 0x1c);
  int* polygonPoints = Sprite__CollectNonTransparentPixels(animation, 0xffffffff);
  region->inner->brush.DeleteObject();
  HRGN polygonRegion =
      CreatePolygonRgn(reinterpret_cast<POINT*>(polygonPoints + 2), polygonPoints[0], WINDING);
  int attached = RegisterClipRegionHandle(&region->inner->brush, polygonRegion);
  delete[] polygonPoints;
  return attached;
}

// FUNCTION: IMPERIALISM 0x00497f60
void RebuildMapTileNeighborHighlightPolygonsForAllTiles_Impl(void) {
  g_pTempMapTileClipRegion = CreateRectRgn(0, 0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00497f90
void WrapperFor_LookupHandleMapEntryWithCreate_At00497f90(ClipStateRegionWrapper* dst) {
  CGdiObject* tempObject = CGdiObject::FromHandle(g_pTempMapTileClipRegion);
  HRGN hrgnSrc = tempObject != nullptr ? static_cast<HRGN>(tempObject->m_hObject) : nullptr;
  CombineRgn(static_cast<HRGN>(dst->inner->brush.m_hObject), hrgnSrc, nullptr, RGN_COPY);
  DeleteObject(g_pTempMapTileClipRegion);
  g_pTempMapTileClipRegion = nullptr;
}

// FUNCTION: IMPERIALISM 0x00498180
void DrawFrameRectOrUpdateClipRegion(RECT* rect) {
  if (g_pTempMapTileClipRegion != nullptr) {
    HRGN rectRegion = CreateRectRgnIndirect(rect);
    CBrush clipBrush;
    RegisterClipRegionHandle(&clipBrush, rectRegion);
    CombineRgn(static_cast<HRGN>(g_pTempMapTileClipRegion),
               static_cast<HRGN>(g_pTempMapTileClipRegion), static_cast<HRGN>(clipBrush.m_hObject),
               RGN_XOR);
    clipBrush.DeleteObject();
    return;
  }

  CBrush brush;
  brush.CreateSolidBrush(static_cast<COLORREF>(g_Quick_Draw_Color_State_006950FC));

  RECT frameRect;
  CopyRect(&frameRect, rect);
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    OffsetRect(&frameRect, g_nQuickDrawOriginX, g_nQuickDrawOriginY);
  }

  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == nullptr) {
    dc = static_cast<CDC*>(g_pScopedMapQuickDrawDcHandleObject);
  }
  if (dc != nullptr) {
    FrameRect(dc->GetSafeHdc(), &frameRect, static_cast<HBRUSH>(brush.GetSafeHandle()));
  }
}

// Reorder-wrapper over the Win32 IntersectRect: callers pass (src1, src2, dst).
// FUNCTION: IMPERIALISM 0x00498bb0
int IntersectRectWrapper(RECT* src1, RECT* src2, RECT* dst) {
  return IntersectRect(dst, src1, src2);
}

// Real behavior is a lazily-constructed CMapPtrToPtr cached on the current thread's
// AFX module-thread-state (AfxGetModuleThreadState()+0x20 in the original). That state
// struct's layout isn't modeled here, and this map is only ever touched from the UI
// thread, so a single process-wide lazy singleton is behaviorally equivalent for this
// single-threaded game. Was an unported stub (returned null unconditionally), which
// crashed the first time a real clip region was registered.
// FUNCTION: IMPERIALISM 0x006139c6
static CMapPtrToPtr* afxMapHIMAGELIST_6139c6() {
  static CMapPtrToPtr* s_map = nullptr;
  if (s_map == nullptr) {
    s_map = new CMapPtrToPtr();
  }
  return s_map;
}

// Ghidra mislabels this as CBrush::; clip-state registration over retail MFC CBrush.
// FUNCTION: IMPERIALISM 0x00613a4c
static int RegisterClipRegionHandle(CBrush* brush, HRGN region) {
  if (region == NULL) {
    return 0;
  }
  CMapPtrToPtr* handleMap = afxMapHIMAGELIST_6139c6();
  brush->Attach(region);
  void*& slot = (*handleMap)[reinterpret_cast<void*>(region)];
  slot = brush;
  return 1;
}
