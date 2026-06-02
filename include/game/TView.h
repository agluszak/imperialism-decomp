#pragma once

#include "decomp_types.h"
#include "game/TEventHandler.h"
#include "game/string_shared.h"

// Runtime thunk exported from the binary for the base UI resource constructor.
undefined4 thunk_ConstructUiResourceEntryBase(void);

// VTABLE: IMPERIALISM 0x649858
class TView : public TEventHandler {
public:
  int field10;
  int field14;
  int field18;
  unsigned char padding_1c_to_1f[0x04];
  int field20;
  unsigned char padding_24_to_2b[0x08];
  int field2c;
  int field30;
  int field34;
  int field38;
  int field3c;
  unsigned char padding_40_to_43[0x04];
  int field44;
  int field48;
  unsigned char flag4c;
  unsigned char flag4d;
  unsigned short field4e;
  int field50;
  unsigned short field54;
  unsigned char padding_56_to_57[0x02];
  StringShared sharedStringRef;
  int field5c;

  void thunk_ConstructUiResourceEntryBase();
  TView* ConstructUiResourceEntryBase();
  void thunk_NoOpUiLifecycleHook(int passthroughArg = 0);
  virtual ~TView();
};
