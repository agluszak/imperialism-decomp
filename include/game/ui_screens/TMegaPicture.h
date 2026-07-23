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
  SetPictureResourceIdAndRefresh(short nPictureId,
                                 unsigned char fRefreshNow) override; // slot 0x72 0x573430
  // Clears (useAndMask != 0: flags98 &= mask) or subtracts (flags98 -= mask) bits, then
  // optionally refreshes.
  virtual void ClearOrSubtractFlags98AndMaybeRefresh(unsigned short mask, char useAndMask,
                                                     char refreshNow); // slot 0x74 0x5736c0
  // Overwrites flags98 wholesale, then optionally refreshes.
  virtual void AssignFlags98AndMaybeRefresh(unsigned short value,
                                            char refreshNow); // slot 0x75 0x573690
  // TNoHilitePicture adds a 1-byte field90 at +0x90 and tail-pads to a 4-byte boundary
  // as a base subobject (MSVC does not reuse base tail padding for derived members), so
  // these fields (read by Draw) start immediately at +0x94, with no gap.
  struct TQuickDrawSurfaceContext* surfaceContext94; // +0x94 the picture's own bitmap
  unsigned short flags98; // +0x98 bit0 = transparent-blit + opaque-fill-first, bit2 =
                          // use contentSubRect9c instead of the full passed-in rect
  unsigned char pad9a[2];
  CRect contentSubRect9c; // +0x9c cached content sub-rect (used when flags98 & 4)

  TMegaPicture();
};

ASSERT_SIZE(TMegaPicture, 0xac);
