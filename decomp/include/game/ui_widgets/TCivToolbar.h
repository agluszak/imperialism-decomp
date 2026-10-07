#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x667f00
class TCivToolbar : public TCluster {
public:
  virtual ~TCivToolbar() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  short civilianClassId;

  TCivToolbar();
  DECLARE_DYNCREATE(TCivToolbar)
  void SetSelectedUnit(class TCivUnit* selectedCivilianOrderEntry);
  void RefreshCivilianStackButtonsForTile(short tileIndex);
};
ASSERT_SIZE(TCivToolbar, 0x8c);
