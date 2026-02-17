#pragma once

#include "decomp_types.h"

#include <windows.h>

struct ListBoxItemCount {
  int value;
};

class ListBox {
public:
  static void __stdcall AddOrUpdateItemData(
      ListBoxItemCount *item_count_ptr,
      undefined4 control_id,
      LPARAM *item_data_ptr);
};

void __stdcall SelectComboBoxItemByParam(
    int *state_flag,
    undefined4 owner_id,
    LPARAM *lparam_in);
