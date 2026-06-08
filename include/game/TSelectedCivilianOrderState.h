#pragma once

#include "game/TCivilianOrderState.h"

class TSelectedCivilianOrderState {
public:
  char pad_00[0x04];
  TCivilianOrderState* selectedEntry; // 0x04

  void SetActiveCivilianSelection(TCivilianOrderState* entryContext, int refreshCommandPanel);
  void QueueImmediateCivilianCommandAndCycleSelection(int commandType);
  void ShowDisbandCivilianConfirmationDialog();
};

extern "C" TSelectedCivilianOrderState* g_pSelectedCivilianOrderState;
