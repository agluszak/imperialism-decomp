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
  virtual ~TTerrainHelpPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void HighlightSelectedMenuItemAndRefreshDetailText(int selectedIndex);

  TDeluxeText* infoTextPane;
  short menuItemIds[12];

  TTerrainHelpPicture();

  void BuildMapTileActionContextMenu(short nTileIndex);
};

ASSERT_SIZE(TTerrainHelpPicture, 0xac);
