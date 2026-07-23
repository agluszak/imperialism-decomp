#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d990
class TMiniCivLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniCivLine)
  virtual ~TMiniCivLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4ab740

  // The civilian unit this line row is bound to; InstallViews hands it (with
  // the inherited field08/field0c layout pair) to the TMiniCivView it creates.
  TCivUnit* civUnit10;

  TMiniCivLine();
};

ASSERT_SIZE(TMiniCivLine, 0x14);
