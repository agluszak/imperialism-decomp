#pragma once

#include "game/TNoHilitePicture.h"

struct TQuickDrawSurfaceContext;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660b48
class TColorKeyPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TColorKeyPicture)
  virtual ~TColorKeyPicture() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x573090
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x572e60
  virtual void SetPictureResourceIdAndRefresh(short nPictureId,
                                              bool fRefreshNow) override; // slot 0x72 0x573040

  TColorKeyPicture();

  // Released through TDisplayMgr::RemoveGWorld both before changing
  // the picture resource and from Free(), proving the concrete pointer type.
  TQuickDrawSurfaceContext* colorKeySurface94;
};
