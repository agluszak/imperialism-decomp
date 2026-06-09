#pragma once

#include "decomp_types.h"

struct ApplicationUiRootControllerState {
  void* vftable;
  char pad_04[0x20];
  int screenModeAt24;
};

extern ApplicationUiRootControllerState* g_pApplicationUiRootController;
