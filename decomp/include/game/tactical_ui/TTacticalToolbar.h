#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

class TTacticalUnit;
class TArmyTacUnit;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644d98
class TTacticalToolbar : public TCluster {
public:
  DECLARE_DYNCREATE(TTacticalToolbar)
  virtual ~TTacticalToolbar() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005acf90
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5ac840
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5ac950
  virtual void
  UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit); // slot 0x73 0x5acb50
  virtual void UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit); // slot 0x74 0x5acc90
  class TTacticalBattle* battle;                                       // +0x88
  class TTacticalUnit* currentUnit;                        // +0x8c current-unit control source
  class TArmyTacUnit* otherSideCurrentUnit;                // +0x90
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface; // +0x94 the 0xee2 atlas

  void SetActionMode(int mode);

  // NOOP: verified empty in original 0x005ac7b7
  TTacticalToolbar() {}
};
ASSERT_SIZE(TTacticalToolbar, 0x98);
