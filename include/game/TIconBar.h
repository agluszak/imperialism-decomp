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
  virtual void SetNumIcons(short numIcons);
  virtual void SetNumIcons(short numIcons, unsigned char refreshNow);

  void IIconBar(TView* panel, int* position, int* size, int layoutParam4, int layoutParam5,
                short pictureId, int numIcons);

  // TNoHilitePicture's own slice ends at 0x94 (see TMegaPicture.h). RTTI oracle
  // confirms sizeof(TIconBar) == 0x9c.
  //
  // iconAtlasFrame94: atlas frame/row index into the icon strip bitmap (atlas674), set by
  // SetPictureResourceIdAndRefresh as nPictureId - 700; ApplyRectSlot110 reads it as
  // iconAtlasFrame94*0x20 to pick the source column.
  short iconAtlasFrame94;
  // numIcons96: tick/segment count. ApplyRectSlot110 divides the bar's content width by
  // (numIcons96+1) to get the spacing and draws numIcons96 copies of the atlas frame.
  short numIcons96;
  // iconSpacing98: per-tick spacing computed by ApplyRectSlot110 (content width /
  // (numIcons96+1), clamped to 0x20); TIconSlider uses it for value/position conversion.
  short iconSpacing98;
  unsigned char pad9a[2];

  TIconBar();
};

ASSERT_SIZE(TIconBar, 0x9c);
