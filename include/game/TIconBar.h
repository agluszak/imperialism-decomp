#pragma once

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

  TIconBar();
};

