#pragma once

#include "decomp_types.h"

class InputState {
public:
  char pad_00[0x10];
  u32 active_key_mask;
  char pad_14[0x24];
  int slot_table_ptr;
  u32 slot_count;

  void HandleKeyDown(int key_id);
};
