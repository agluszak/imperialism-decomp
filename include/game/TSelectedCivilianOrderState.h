#pragma once

#include "game/TCivUnit.h"

class TSelectedCivilianOrderState {
public:
  char pad_00[0x04];
  TCivUnit* selectedEntry; // 0x04

  void SetActiveCivilianSelection(TCivUnit* entryContext, int refreshCommandPanel);
  void QueueImmediateCivilianCommandAndCycleSelection(int commandType);
  void ShowDisbandCivilianConfirmationDialog();
};

extern "C" TSelectedCivilianOrderState* g_pSelectedCivilianOrderState;
