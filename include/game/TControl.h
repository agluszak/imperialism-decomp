#pragma once

#include "game/TView.h"

class TControl : public TView {
public:
  int hasCommandTagResource;
  unsigned char commandTagResourceByte;
  unsigned char padding_65_to_67[3];
  int field68;
  int field6C;
  int field70;
  int field74;
  int commandTagDefaultParam0;
  int commandTagDefaultParam1;
  unsigned short commandTagDefaultParam2;

  void thunk_ConstructUiCommandTagResourceEntryBase();
  void ConstructUiCommandTagResourceEntryBase();
};
