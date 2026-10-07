#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660d78
class TMegaPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TMegaPicture)
  virtual ~TMegaPicture() override;
  virtual void Free() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) override;
  virtual void ClearModeBits(unsigned short mask, char useAndMask, char refreshNow);
  // Overwrites modeFlags wholesale, then optionally refreshes.
  virtual void SetMode(unsigned short value, bool refreshNow);
  struct TQuickDrawSurfaceContext* surfaceContext; // the picture's own bitmap
  unsigned short modeFlags; // bit0 = transparent-blit + opaque-fill-first, bit2 =
                            // use contentSubRect instead of the full passed-in rect
  unsigned char pad9a[2];
  CRect contentSubRect; // cached content sub-rect (used when modeFlags & 4)

  TMegaPicture();

  void IMegaPicture(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                    int layoutParam5, short pictureId, unsigned short flags);
};

ASSERT_SIZE(TMegaPicture, 0xac);
