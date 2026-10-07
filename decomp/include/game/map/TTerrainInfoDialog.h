#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00658d70
class TTerrainInfoDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TTerrainInfoDialog)
  virtual ~TTerrainInfoDialog() override; // slot 0x01 (scalar deleting destructor)

  TTerrainInfoDialog();
};

ASSERT_SIZE(TTerrainInfoDialog, 0x94);
