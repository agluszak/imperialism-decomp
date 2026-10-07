#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d990
class TMiniCivLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniCivLine)
  // FUNCTION: IMPERIALISM 0x004ab650
  virtual ~TMiniCivLine() override {}
  virtual void InstallViews(TView* panel, int* offsetLayout) override;

  TCivUnit* civUnit;

  // NOOP: verified empty in original 0x004ab6a3
  TMiniCivLine() {}
  void IMiniCivLine(short rowArg, short colArg, int* bounds, TCivUnit* item);
};

ASSERT_SIZE(TMiniCivLine, 0x14);
