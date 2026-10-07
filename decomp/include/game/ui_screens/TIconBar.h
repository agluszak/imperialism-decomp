#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657a28
class TIconBar : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TIconBar)
  virtual ~TIconBar() override;

  virtual void Draw(RECT* rectBuffer) override;
  virtual void SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) override;
  virtual void SetNumIcons(short numIcons);
  virtual void SetNumIcons(short numIcons, unsigned char refreshNow);

  void IIconBar(TView* panel, int* position, int* size, int layoutParam4, int layoutParam5,
                short pictureId, short numIcons);

  short iconAtlasFrame;
  short numIcons;
  short iconSpacing;
  unsigned char pad9a[2];

  TIconBar();
};

ASSERT_SIZE(TIconBar, 0x9c);
