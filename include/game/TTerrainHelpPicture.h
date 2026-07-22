#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

class TDeluxeText;

// VTABLE: IMPERIALISM 0x00642038
class TTerrainHelpPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTerrainHelpPicture)
  virtual ~TTerrainHelpPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005059d0
  // Applies the highlight style to the selected 'i00a'..'i00l' item pane (normal style
  // to the rest) and fills the 'item' caption + 'info' description panes from
  // menuItemIds94[selectedIndex]. Slot 0x73, 0x5057a0.
  virtual void HighlightSelectedMenuItemAndRefreshDetailText(int selectedIndex);

  // 'info' pane resolved and styled by BuildMapTileActionContextMenu; also read by the
  // slot-0x73 rebuild.
  TDeluxeText* infoTextPane90; // +0x90
  // Menu item ids (string group 0x2755) built from the selected tile's record; 0 = empty
  // slot. Read back by the slot-0x73 rebuild.
  short menuItemIds94[12]; // +0x94..0xab

  TTerrainHelpPicture();

  // Fills the tile context-menu dialog pane ('DLOG'): builds the 12 menu item ids from
  // the tile record, pushes them into the 'i00a'..'i00l' item panes, refreshes the
  // 'tile'/'til2' previews, and assembles the 'titl' location text. 0x504e90,
  // __thiscall, RET 0x4.
  void BuildMapTileActionContextMenu(short nTileIndex);
};

ASSERT_SIZE(TTerrainHelpPicture, 0xac);
