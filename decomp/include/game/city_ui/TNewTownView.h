#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TTown;

// VTABLE: IMPERIALISM 0x00650270
class TNewTownView : public TView {
public:
  DECLARE_DYNCREATE(TNewTownView)
  virtual ~TNewTownView() override;
  virtual void Close() override;
  virtual void StuffValues(TTown* town);

  // NOOP: verified empty in original 0x004bd7d3
  TNewTownView() {}

  TTown* town;
};
ASSERT_SIZE(TNewTownView, 0x64);
