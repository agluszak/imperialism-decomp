#include "game/ClipStateRegion.h"
#include "game/mfc.h"

#include <new>

undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);
undefined4 afxMapHIMAGELIST_6139c6(void);

static int RegisterClipRegionHandle(CBrush* brush, HRGN region);

// FUNCTION: IMPERIALISM 0x00495610
undefined4 DestroyClipStateRegionWrapperObject(int* wrapperObject) {
  if ((wrapperObject != 0) && (*wrapperObject != 0)) {
    reinterpret_cast<void(__cdecl*)()>(WrapperFor_DeleteRegionHandleFromClipState_At00495520)();
    FreeHeapBufferIfNotNull(*wrapperObject);
  }
  FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(wrapperObject));
  return 0;
}

// FUNCTION: IMPERIALISM 0x00495820
undefined4 CreateClipStateRegionWrapperObject(void) {
  int* outerWrapper =
      reinterpret_cast<int*>(AllocateWithFallbackHandler(static_cast<undefined4>(4)));
  ClipStateRegionInner* innerObject = reinterpret_cast<ClipStateRegionInner*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(0x1c)));
  if (innerObject == 0) {
    return 0;
  }

  new (innerObject) ClipStateRegionInner();
  HRGN region = CreateRectRgn(0, 0, 0, 0);
  innerObject->attachRegistered = RegisterClipRegionHandle(&innerObject->brush, region) ? 1 : 0;

  if (outerWrapper != 0) {
    *outerWrapper = reinterpret_cast<int>(innerObject);
  }
  return reinterpret_cast<int>(outerWrapper);
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
