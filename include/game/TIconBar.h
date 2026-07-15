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

  // TNoHilitePicture's own slice ends at 0x94 (see TMegaPicture.h); the ctor never
  // touches this region, so its own layout/semantics are unconfirmed beyond field96
  // (written by OrphanTiny_SetWordEcxOffset_96_005060f0). RTTI oracle confirms
  // sizeof(TIconBar) == 0x9c.
  short field94;
  short field96;
  unsigned char pad98[4];

  TIconBar();
};

ASSERT_SIZE(TIconBar, 0x9c);
