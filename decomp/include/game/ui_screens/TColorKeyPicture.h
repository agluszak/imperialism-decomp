#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"

struct TQuickDrawSurfaceContext;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660b48
class TColorKeyPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TColorKeyPicture)
  virtual ~TColorKeyPicture() override;
  virtual void Free() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) override;

  TColorKeyPicture();

  TQuickDrawSurfaceContext* colorKeySurface;
};
ASSERT_SIZE(TColorKeyPicture, 0x98);
