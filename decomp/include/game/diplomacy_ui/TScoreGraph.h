#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006563d0
class TScoreGraph : public TView {
public:
  DECLARE_DYNCREATE(TScoreGraph)
  virtual ~TScoreGraph() override;              // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4fe2b0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fe390

  // NOOP: verified empty in original 0x004fe203 (no standalone TScoreGraph::TScoreGraph body exists: CreateObject 0x004fe1d0 inlines this default ctor, calling the TView base ctor directly at that site)
  TScoreGraph() {}
};
ASSERT_SIZE(TScoreGraph, 0x60);
