#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"

class TTown;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652f58
class TPlaceCityDialog : public TPicture {
public:
  DECLARE_DYNCREATE(TPlaceCityDialog)
  virtual ~TPlaceCityDialog() override;
  virtual void Close() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void StuffValues(TTown* town);

  TPlaceCityDialog();

  TTown* town;
};
ASSERT_SIZE(TPlaceCityDialog, 0x94);
