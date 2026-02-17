#pragma once

#include "decomp_types.h"

class Config {
public:
  void *vtable_ptr;
  char pad_04[0x1c];
  int callback_block_20[8];
  int field_40;
  char pad_44[0x28];
  int field_6c;
  int field_70;
  int shared_ref_74;
  int callback_block_78[7];
  int callback_block_94[7];
  int shared_ref_b0;
  int shared_ref_b4;
  int shared_ref_b8;
  char pad_bc[0x1c];
  int field_d8;
  char pad_dc[0x18];
  int field_f4;

  int *InitDefaults();
};
