#pragma once

#include "compat.h"

struct StrategicMapCallbackRecord {
  StrategicMapCallbackRecord();
  ~StrategicMapCallbackRecord();

  void AppendPackedColorDword(int surface, int packedColor);

  int dispatchTable00;
  char* ownedBuffer04;
  int field08;
  int field0c;
  int field10;
  int field14;
  int field18;
  int subobjectDispatchTable1c;
  char* ownedBuffer20;
  int field24;
  int field28;
  int field2c;
};

ASSERT_SIZE(StrategicMapCallbackRecord, 0x30);
