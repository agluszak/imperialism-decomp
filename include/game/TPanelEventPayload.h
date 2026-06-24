#pragma once

#include "game/TCivUnit.h"

struct TPanelEventPayload {
  int controlTag;                            // 0x00
  TCivUnit* selectedEntryContext; // 0x04
  void* padding_08;
};
