#include "game/ClipStateRegion.h"
#include "game/MfcRuntime.h"

#include <new>

undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);
extern "C" int __stdcall CreateRectRgn(int left, int top, int right, int bottom);

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
  int* outerWrapper = reinterpret_cast<int*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(4)));
  ClipStateRegionInner* innerObject = reinterpret_cast<ClipStateRegionInner*>(
      AllocateWithFallbackHandler(static_cast<undefined4>(0x1c)));
  if (innerObject == 0) {
    return 0;
  }

  new (innerObject) ClipStateRegionInner();
  CreateRectRgn(0, 0, 0, 0);
  innerObject->attachRegistered =
      innerObject->brush.AttachRegionHandleToClipStateAndRegister() ? 1 : 0;

  if (outerWrapper != 0) {
    *outerWrapper = reinterpret_cast<int>(innerObject);
  }
  return reinterpret_cast<int>(outerWrapper);
}
