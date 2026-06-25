#include "game/ClipStateRegion.h"
#include "game/mfc.h"

undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);
undefined4 afxMapHIMAGELIST_6139c6(void);

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

// Reorder-wrapper over the Win32 IntersectRect: callers pass (src1, src2, dst).
// FUNCTION: IMPERIALISM 0x00498bb0
int IntersectRectWrapper(RECT* src1, RECT* src2, RECT* dst) {
  return IntersectRect(dst, src1, src2);
}

// Ghidra mislabels this as CBrush::; clip-state registration over retail MFC CBrush.
// FUNCTION: IMPERIALISM 0x00613a4c
static int RegisterClipRegionHandle(CBrush* brush, HRGN region) {
  if (region == NULL) {
    return 0;
  }
  CMapPtrToPtr* handleMap = reinterpret_cast<CMapPtrToPtr*>(
      reinterpret_cast<void*(__cdecl*)(int)>(afxMapHIMAGELIST_6139c6)(1));
  brush->Attach(region);
  void*& slot = (*handleMap)[reinterpret_cast<void*>(region)];
  slot = brush;
  return 1;
}
