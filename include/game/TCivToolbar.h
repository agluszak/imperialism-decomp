#pragma once

#include "game/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x667f00
class TCivToolbar : public TCluster {
public:
  virtual ~TCivToolbar() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0058eed0
  short civilianClassId;                        // 0x88
  short pad_8a;

  TCivToolbar();
  DECLARE_DYNCREATE(TCivToolbar)
  void RefreshCivilianCommandPanelForSelection(class TCivUnit* selectedCivilianOrderEntry);
  void RefreshCivilianStackButtonsForTile(short tileIndex);
};
