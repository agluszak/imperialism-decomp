#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

class TTown;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652f58
class TPlaceCityDialog : public TPicture {
public:
  DECLARE_DYNCREATE(TPlaceCityDialog)
  virtual ~TPlaceCityDialog() override;         // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;                // slot 0x28 0x4d1e60
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4d1e40
  virtual void StuffValues(TTown* town);        // slot 0x73 0x4d1880

  TPlaceCityDialog();

  TTown* town90;
};
ASSERT_SIZE(TPlaceCityDialog, 0x94);
