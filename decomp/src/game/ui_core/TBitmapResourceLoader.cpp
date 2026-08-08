#include "game/ui_core/TBitmapResourceLoader.h"

#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x004953e0
unsigned char __cdecl GetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle) {
  return (*loaderHandle)->flags;
}

// FUNCTION: IMPERIALISM 0x00495400
void __cdecl SetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle,
                                          unsigned char newFlags) {
  TBitmapResourceLoader* loader = *loaderHandle;
  unsigned char oldFlags = loader->flags;
  loader->flags = newFlags;
  if (oldFlags != 0 && newFlags == 0) {
    loader->ReleaseBitmapResource();
    loader->flags &= 0xfe;
  }
}

// FUNCTION: IMPERIALISM 0x00495440
unsigned char TBitmapResourceLoader::GetLoaderFlags() const {
  return flags;
}

// FUNCTION: IMPERIALISM 0x00495460
void TBitmapResourceLoader::SetLoaderFlags(unsigned char newFlags) {
  unsigned char oldFlags = flags;
  flags = newFlags;
  if (oldFlags != 0 && newFlags == 0) {
    ReleaseBitmapResource();
    flags &= 0xfe;
  }
}

// FUNCTION: IMPERIALISM 0x00495b70
void TBitmapResourceLoader::EnsureBitmapResourceLoadedAndCopyRectSize() {
  if (bitmapResource == NULL) {
    bitmapResource = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(bitmapResourceId);
    if (bitmapResource == NULL) {
      bitmapResource =
          g_pModuleLibraryCacheState->BuildIndexedBmpResourceById(bitmapResourceId, 0x42, 0x42, 0);
    }
  }

  CPoint bitmapSize;
  CPoint* copiedSize = bitmapResource->CopyBitmapDimensionsToPoint(&bitmapSize);
  bitmapRect.left = 0;
  bitmapRect.top = 0;
  bitmapRect.right = copiedSize->x;
  bitmapRect.bottom = copiedSize->y;
}

// FUNCTION: IMPERIALISM 0x00495c00
void TBitmapResourceLoader::ReleaseBitmapResource() {
  if (bitmapResource != NULL) {
    g_pModuleLibraryCacheState->ReleaseRecordById(bitmapResourceId);
  }
  bitmapResource = NULL;
}

// Base slot-0x02 stub: reports an assert (D:\Ambit\QuickDraw.h:417) and returns 0.
// FUNCTION: IMPERIALISM 0x004a1100
int TBitmapResourceLoader::ReportUnimplementedResourceVirtualSlot02() {
  TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\QuickDraw.h", 0x1a1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1130
TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId) {
  TBitmapResourceLoader** handleSlot = new TBitmapResourceLoader*;
  TBitmapResourceLoader* loader = new TBitmapResourceLoader(resourceId);
  *handleSlot = loader;
  return handleSlot;
}
