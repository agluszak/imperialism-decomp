#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/gfx/CDib.h"
#include "game/mfc.h"

struct TBitmapResourceLoaderState {
  unsigned char flags;
  unsigned char pad05[3];
  RECT bitmapRect;
  CDib* bitmapResource;
  short bitmapResourceId;
  short pad1e;

  explicit TBitmapResourceLoaderState(unsigned short resourceId)
      : flags(0), bitmapResource(NULL), bitmapResourceId(static_cast<short>(resourceId)) {}
};

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x0064c340
class TBitmapResourceLoader : public TBitmapResourceLoaderState {
public:
  explicit TBitmapResourceLoader(unsigned short resourceId)
      : TBitmapResourceLoaderState(resourceId) {
    EnsureBitmapResourceLoadedAndCopyRectSize();
  }

  ~TBitmapResourceLoader() {
    ReleaseBitmapResource();
  }

  virtual void EnsureBitmapResourceLoadedAndCopyRectSize(); // slot 0x00 0x495b70
  virtual void ReleaseBitmapResource();                     // slot 0x01 0x495c00
  // slot 0x02 0x4a1100 -- asserts (QuickDraw.h:417) and returns 0.
  virtual int ReportUnimplementedResourceVirtualSlot02();
  unsigned char GetLoaderFlags() const;        // 0x00495440
  void SetLoaderFlags(unsigned char newFlags); // 0x00495460
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId);
unsigned char __cdecl GetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle);
void __cdecl SetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle,
                                          unsigned char newFlags);

ASSERT_SIZE(TBitmapResourceLoaderState, 0x1c);
ASSERT_SIZE(TBitmapResourceLoader, 0x20);
