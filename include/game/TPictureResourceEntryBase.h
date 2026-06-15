#pragma once

#include "compat.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

class TPictureResourceEntryBase : public TControl {
public:
  short glyphBase84;
  short field86;
  short bitmapId;
  short field8A;
  int field8C;

  TPictureResourceEntryBase();
  virtual ~TPictureResourceEntryBase() override;
  // Slot 0x08 override (0x0048f640): clone via slot 0x09 then copy extended picture-resource
  // fields (offsets 0x60-0x8c); TControl's cannot-clone stub is not used on this branch.
  virtual void* CloneEngineerDialogStateToNewInstance() override;
  // Slot 0x44 override (0x0048f3c0): ctrl-modifier hint overlay blit used by picture controls.
  void ApplyRectSlot110(RECT* rectBuffer) override;

  virtual void ResetPictureResourceEntry(); // slot 0x1c4
  virtual void SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow); // slot 0x1c8
  virtual bool IsSelected(short value = -1, bool refreshNow = true); // slot 0x1cc

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
};

ASSERT_SIZE(TPictureResourceEntryBase, 0x90);
