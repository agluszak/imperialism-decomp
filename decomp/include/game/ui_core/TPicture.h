#pragma once

#include "compat.h"
#include "game/ui_core/TControl.h"
#include "game/mfc.h"

class TObject;
class CDib;

// VTABLE: IMPERIALISM 0x0064a930
class TPicture : public TControl {
public:
  DECLARE_DYNCREATE(TPicture)
  virtual ~TPicture() override;
  virtual TObject* ShallowClone() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void ReleasePicture();
  virtual void SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow);
  short glyphBase;
  short reserved86; // copied by ShallowClone; no other accesses observed
  short bitmapId;
  short resourceNamespaceId; // high word of the resource registry key
  CDib* cachedBitmap;

  TPicture();
  TPicture(const TPicture& source);
  void CopyPictureStateFromSource(TPicture* source);

  void IPicture(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                int layoutParam5, short pictureId);
};

ASSERT_SIZE(TPicture, 0x90);
