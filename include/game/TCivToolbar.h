#pragma once

#include "game/TCluster.h"

// VTABLE: IMPERIALISM 0x667f00
class TCivToolbar : public TCluster {
public:
  short civilianClassId; // 0x88
  short pad_8a;

  TCivToolbar();

  void RefreshCivilianCommandPanelForSelection(int* selectedCivilianOrderEntry);
  void RefreshCivilianStackButtonsForTile(short tileIndex);
  void HandleCivilianMapCommandPanelAction(int eventClass, struct PanelEventPayload* eventPayload, int eventFlags);
};
