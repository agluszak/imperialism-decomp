#pragma once

#include "decomp_types.h"

class InputState {
public:
  char pad_00[0x10];
  unsigned short active_key_mask;
  char pad_12[0x26];
  int slot_table_ptr;
  u32 unknown_3c;
  u32 slot_count;

  void HandleKeyDown(int key_id);
};
