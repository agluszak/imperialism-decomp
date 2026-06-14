#pragma once

#include "game/TMinister.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// AI interior minister branch (sparse overrides vs TMinister).
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  TInteriorMinister();
};
