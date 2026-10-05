#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660d78
class TMegaPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TMegaPicture)
  virtual ~TMegaPicture() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x573650
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x573270
  virtual void
  SetPictureRsrcID(short nPictureId,
                                 unsigned char fRefreshNow) override; // slot 0x72 0x573430
  virtual void ClearModeBits(unsigned short mask, char useAndMask,
                                                     char refreshNow); // slot 0x74 0x5736c0
  // Overwrites modeFlags wholesale, then optionally refreshes.
  virtual void SetMode(unsigned short value,
                                            bool refreshNow); // slot 0x75 0x573690
  struct TQuickDrawSurfaceContext* surfaceContext; // +0x94 the picture's own bitmap
  unsigned short modeFlags; // +0x98 bit0 = transparent-blit + opaque-fill-first, bit2 =
                          // use contentSubRect instead of the full passed-in rect
  unsigned char pad9a[2];
  CRect contentSubRect; // +0x9c cached content sub-rect (used when modeFlags & 4)

  TMegaPicture();

  void IMegaPicture(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                    int layoutParam5, short pictureId, unsigned short flags);
};

ASSERT_SIZE(TMegaPicture, 0xac);
