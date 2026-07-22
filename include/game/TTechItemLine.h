#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066aec8
class TTechItemLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTechItemLine)
  virtual ~TTechItemLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5b1160

  int nationSlot10; // +0x10 — forwarded to ConstructTTechItemViewBaseState
  int techId14;     // +0x14 — forwarded to ConstructTTechItemViewBaseState

  TTechItemLine();
};

ASSERT_SIZE(TTechItemLine, 0x18);
