#pragma once

#include "compat.h"
#include "game/TView.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TView {
public:
  short selectedCivilianClass;
  unsigned char pad_62_to_6b[0x0a];
  unsigned char legendInitialized;
  unsigned char pad_6d_to_6f[0x03];
  unsigned char pad_70_to_16f[0x100];

  TCivDescription() : TView() {
    selectedCivilianClass = -1;
    legendInitialized = 0;
  }

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }
};

ASSERT_SIZE(TCivDescription, 0x170);
