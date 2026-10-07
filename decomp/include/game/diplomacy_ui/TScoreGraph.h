#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006563d0
class TScoreGraph : public TView {
public:
  DECLARE_DYNCREATE(TScoreGraph)
  virtual ~TScoreGraph() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;

  // NOOP: verified empty in original 0x004fe203
  TScoreGraph() {}
};
ASSERT_SIZE(TScoreGraph, 0x60);
