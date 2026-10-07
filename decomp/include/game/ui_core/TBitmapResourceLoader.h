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
    LoadBitmapBounds();
  }

  ~TBitmapResourceLoader() {
    ReleaseBitmapResource();
  }

  virtual void LoadBitmapBounds();
  virtual void ReleaseBitmapResource();
  virtual int ReportUnimplemented();
  unsigned char GetLoaderFlags() const;
  void SetLoaderFlags(unsigned char newFlags);
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId);
unsigned char __cdecl GetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle);
void __cdecl SetBitmapResourceLoaderFlags(TBitmapResourceLoader** loaderHandle,
                                          unsigned char newFlags);

ASSERT_SIZE(TBitmapResourceLoaderState, 0x1c);
ASSERT_SIZE(TBitmapResourceLoader, 0x20);
