#pragma once

#include "compat.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureResourceEntryBase : public TControl {
public:
  short glyphBase84;
  short field86;
  short bitmapId;
  short field8A;
  int field8C;

  TPictureResourceEntryBase();
  virtual ~TPictureResourceEntryBase() override;

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
};

ASSERT_SIZE(TPictureResourceEntryBase, 0x90);
