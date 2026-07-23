#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CDib.h"
#include "game/mfc.h"

struct TBitmapResourceLoaderState {
  unsigned char flags;
  unsigned char pad05[3];
  RECT bitmapRect;
  CDib* bitmapResource;
  short bitmapResourceId;
  short pad1e;

  explicit TBitmapResourceLoaderState(unsigned short resourceId)
      : flags(0), bitmapResource(nullptr), bitmapResourceId(static_cast<short>(resourceId)) {}
};

// Lightweight bitmap loader allocated by CreateBitmapResourceLoaderHandle. Confirmed
// exactly 3 slots (dword at +0xc, right after the 3 declared virtuals, reads as a
// literal NULL); no destructor slot in the original.
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
  // slot 0x02 0x4a1100 -- provisional name; asserts (QuickDraw.h:417) and returns 0.
  virtual undefined4 ReportUnimplementedResourceVirtualSlot02();
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// 0x4a1130 -- allocates the loader handle-slot plus a loader for `resourceId`.
TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId);

ASSERT_SIZE(TBitmapResourceLoaderState, 0x1c);
ASSERT_SIZE(TBitmapResourceLoader, 0x20);
