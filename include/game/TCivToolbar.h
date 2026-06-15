#pragma once

#include "game/TCluster.h"
#include "game/TPanelEventPayload.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x667f00
class TCivToolbar : public TCluster {
public:
  short civilianClassId; // 0x88
  short pad_8a;

  TCivToolbar();
  CRuntimeClass* GetRuntimeClass() const override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  void
  RefreshCivilianCommandPanelForSelection(class TCivilianOrderState* selectedCivilianOrderEntry);
  void RefreshCivilianStackButtonsForTile(short tileIndex);
  void CycleMapInteractionSelectionAfterHandledClick();
};
