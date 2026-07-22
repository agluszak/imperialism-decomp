#pragma once

#include "compat.h"
#include "game/TControl.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TObject;
class CDib;

// VTABLE: IMPERIALISM 0x0064a930
class TPicture : public TControl {
public:
  DECLARE_DYNCREATE(TPicture)
  virtual ~TPicture() override;                 // slot 0x01 (scalar deleting destructor)
  virtual TObject* ShallowClone() override;     // slot 0x08 0x48f640
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x48f3c0
  virtual void ResetPictureResourceEntry();     // slot 0x71 0x48f520
  virtual void SetPictureResourceIdAndRefresh(short nPictureId,
                                              unsigned char fRefreshNow); // slot 0x72 0x48f570
  short glyphBase84;
  short reserved86; // 0x86, copied by ShallowClone; no other accesses observed
  short bitmapId;
  short resourceNamespaceId; // 0x8a, high word of the resource registry key
  CDib* cachedBitmap;        // 0x8c

  TPicture();

  // TPicture-family clone of TView::InitializeUiResourceEntryFrameAndParent: seeds the
  // frame/parent base fields, attaches to the panel, and loads the picture resource via
  // the SetPictureResourceIdAndRefresh virtual. layoutParam4/5 are never read.
  // 0x48f330, __thiscall, RET 0x18.
  void InitializePictureEntryBaseAndRefresh(TView* panel, int* offsetLayout, int* sizeLayout,
                                            int layoutParam4, int layoutParam5, short pictureId);
};

ASSERT_SIZE(TPicture, 0x90);
