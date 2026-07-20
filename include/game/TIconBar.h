#pragma once

#include "compat.h"
#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657a28
class TIconBar : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TIconBar)
  virtual ~TIconBar() override;

  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual void SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) override;
  virtual undefined OrphanCallChain_C2_I15_00506110(char param_1);
  virtual undefined OrphanTiny_SetWordEcxOffset_96_005060f0(undefined2 param_1);

  // TNoHilitePicture's own slice ends at 0x94 (see TMegaPicture.h). RTTI oracle
  // confirms sizeof(TIconBar) == 0x9c.
  //
  // field94: atlas frame/row index into the icon strip bitmap (atlas674), set by
  // SetPictureResourceIdAndRefresh as nPictureId - 700; ApplyRectSlot110 reads it as
  // field94*0x20 to pick the source column.
  short field94;
  // field96: tick/segment count (written by OrphanTiny_SetWordEcxOffset_96_005060f0);
  // ApplyRectSlot110 divides the bar's content width by (field96+1) to get the per-tick
  // slot width and draws field96 copies of the atlas frame across the bar.
  short field96;
  // tickSlotWidth98: per-tick slot width computed by ApplyRectSlot110 (content width /
  // (field96+1), clamped to 0x20); read back by TIconSlider's thumb-position helpers
  // (OrphanLeaf_NoCall_Ins04_00506560, OrphanCallChain_C1_I36_00506710,
  // DispatchPictureResourceCommand).
  short tickSlotWidth98;
  unsigned char pad9a[2];

  TIconBar();
};

ASSERT_SIZE(TIconBar, 0x9c);
