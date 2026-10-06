#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d990
class TMiniCivLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniCivLine)
  // FUNCTION: IMPERIALISM 0x004ab650
  virtual ~TMiniCivLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4ab740

  TCivUnit* civUnit;

  // NOOP: verified empty in original 0x004ab6a3 (no standalone TMiniCivLine::TMiniCivLine body exists: CreateObject 0x004ab670 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TMiniCivLine() {}
  void IMiniCivLine(short rowArg, short colArg, int* bounds, TCivUnit* item);
};

ASSERT_SIZE(TMiniCivLine, 0x14);
