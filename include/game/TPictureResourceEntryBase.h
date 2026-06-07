#pragma once

#include "compat.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureResourceEntryBase : public TControl {
public:
  short glyphBase84;
  char pad_86_to_8f[0x0a];

  TPictureResourceEntryBase();
  virtual ~TPictureResourceEntryBase();

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};

ASSERT_SIZE(TPictureResourceEntryBase, 0x90);
