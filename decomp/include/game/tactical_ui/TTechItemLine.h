#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066aec8
class TTechItemLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTechItemLine)
  // FUNCTION: IMPERIALISM 0x005b1070
  virtual ~TTechItemLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5b1160

  int nationSlot; // +0x10 — forwarded to ITechItemView
  int techId;     // +0x14 — forwarded to ITechItemView

  // NOOP: verified empty in original 0x005b10c3
  TTechItemLine() {}

  void ITechItemLine(short rowArg, short colArg, int* bounds, int nationSlot, int techId);
};

ASSERT_SIZE(TTechItemLine, 0x18);
