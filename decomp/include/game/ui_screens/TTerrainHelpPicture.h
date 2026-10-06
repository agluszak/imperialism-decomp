#pragma once

#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/mfc.h"

class TDeluxeText;

// VTABLE: IMPERIALISM 0x00642038
class TTerrainHelpPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTerrainHelpPicture)
  virtual ~TTerrainHelpPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005059d0
  virtual void HighlightSelectedMenuItemAndRefreshDetailText(int selectedIndex);

  TDeluxeText* infoTextPane; // +0x90
  short menuItemIds[12];     // +0x94..0xab

  TTerrainHelpPicture();

  void BuildMapTileActionContextMenu(short nTileIndex);
};

ASSERT_SIZE(TTerrainHelpPicture, 0xac);
