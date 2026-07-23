#pragma once

#include "compat.h"
#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00658d70
class TTerrainInfoDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TTerrainInfoDialog)
  virtual ~TTerrainInfoDialog() override; // slot 0x01 (scalar deleting destructor)
  // RTTI oracle: sizeof(TTerrainInfoDialog) == 0x94, identical to TNoHilitePicture -- this
  // class adds no data members of its own; its ctor (0x51b140) just installs its own vtable
  // over the real TNoHilitePicture base construction.

  TTerrainInfoDialog();
};

ASSERT_SIZE(TTerrainInfoDialog, 0x94);
