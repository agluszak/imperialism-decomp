#pragma once

#include "game/TCluster.h"

class TTacticalUnit;
class TArmyTacUnit;
#include "game/mfc.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

// VTABLE: IMPERIALISM 0x00644d98
class TTacticalToolbar : public TCluster {
public:
  DECLARE_DYNCREATE(TTacticalToolbar)
  virtual ~TTacticalToolbar() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005acf90
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5ac840
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5ac950
  // Updates the toolbar's current-unit 'curr' control from the newly selected unit
  // (stores it at +0x8c, reads its unitTypeC/side20). The old "Diplomacy" name was a
  // Ghidra mislabel.
  virtual undefined
  UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit); // slot 0x73 0x5acb50
  virtual undefined TacticalToolbarSlot74(int param_1);                // slot 0x74 0x5acc90
  // Toolbar slice (base TCluster ends at +0x88). battle88/unitSpriteAtlasSurface94 are
  // wired by the live-battle initializer 0x5a9d90; currentUnit8C by slot 0x73.
  class TTacticalBattle* battle88;    // +0x88
  class TTacticalUnit* currentUnit8C; // +0x8c current-unit control source
  // Draw (0x5ac950) reads a second current-unit pointer here, alongside
  // currentUnit8C, to draw each side's xp progress bar -- same slot shape, other side.
  class TArmyTacUnit* otherSideCurrentUnit90;                // +0x90
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface94; // +0x94 the 0xee2 atlas

  // Arms/disarms the 'targ'/'done'/'retr'/'auto' control cluster for the live-battle
  // vs deployment phase (mode 1 = battle live). Resolves the child controls on
  // itself via slot 0x25. 0x5acd60, __thiscall, ret 4.
  void ConfigureTacticalTargetDoneRetreatAutoControls(int mode);

  TTacticalToolbar();
};
