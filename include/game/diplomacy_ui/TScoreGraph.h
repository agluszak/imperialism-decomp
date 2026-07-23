#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006563d0
class TScoreGraph : public TView {
public:
  DECLARE_DYNCREATE(TScoreGraph)
  virtual ~TScoreGraph() override;              // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4fe2b0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fe390

  TScoreGraph();
};
