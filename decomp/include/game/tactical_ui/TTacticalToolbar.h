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
  virtual ~TTacticalToolbar() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit);
  virtual void UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit);
  class TTacticalBattle* battle;
  class TTacticalUnit* currentUnit; // +0x8c current-unit control source
  class TArmyTacUnit* otherSideCurrentUnit;
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface; // +0x94 the 0xee2 atlas

  void SetActionMode(int mode);

  // NOOP: verified empty in original 0x005ac7b7
  TTacticalToolbar() {}
};
ASSERT_SIZE(TTacticalToolbar, 0x98);
