#pragma once

#include "game/TCivilianOrderState.h"

struct TPanelEventPayload {
  int controlTag;                            // 0x00
  TCivilianOrderState* selectedEntryContext; // 0x04
  void* padding_08;
};
