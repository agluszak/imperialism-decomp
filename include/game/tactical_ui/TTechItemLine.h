#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066aec8
class TTechItemLine : public TLineData {
public:
  DECLARE_DYNCREATE(TTechItemLine)
  virtual ~TTechItemLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x5b1160

  int nationSlot10; // +0x10 — forwarded to ITechItemView
  int techId14;     // +0x14 — forwarded to ITechItemView

  // NOOP: verified empty in original 0x005b10c3 (no standalone TTechItemLine::TTechItemLine body exists: CreateObject 0x005b1090 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TTechItemLine() {}

  // Two-phase init (MacApp IViewClass idiom): shared TLineData row/bounds, then this
  // line's two forwarded ids. 0x005b1120, __thiscall.
  void ITechItemLine(short rowArg, short colArg, int* bounds, int nationSlot, int techId);
};

ASSERT_SIZE(TTechItemLine, 0x18);
