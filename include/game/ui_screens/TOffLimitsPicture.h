#pragma once

#include "compat.h"

#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660fb0
class TOffLimitsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TOffLimitsPicture)
  virtual ~TOffLimitsPicture() override;        // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x573900
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x573850
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x573890
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill
  // arity mismatch: merges srcRegion into this object's own ownClipRegion90.
  virtual void ForwardCopyRgn(RgnHandle srcRegion); // slot 0x73 0x573940
  // TPicture ends at 0x90; this object's own 4-byte slice is a lazily-created clip
  // region wrapper (destroyed by Free(), merged into by
  // ForwardCopyRgn, and read/written by
  // TMapUberPicture::DisplayMiniMap -- see its own evidence).
  RgnHandle ownClipRegion90;

  TOffLimitsPicture();
};
ASSERT_SIZE(TOffLimitsPicture, 0x94);
