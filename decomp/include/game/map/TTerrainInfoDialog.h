#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00658d70
class TTerrainInfoDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TTerrainInfoDialog)
  virtual ~TTerrainInfoDialog() override;

  TTerrainInfoDialog();
};

ASSERT_SIZE(TTerrainInfoDialog, 0x94);
