#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

class TCivUnit;

// VTABLE: IMPERIALISM 0x0064d990
class TMiniCivLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniCivLine)
  virtual ~TMiniCivLine() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x4ab740
  // slot 0x0b RemoveViews inherited unchanged (0x56f480)

  // The civilian unit this line row is bound to; InstallViews hands it (with
  // the inherited field08/field0c layout pair) to the TMiniCivView it creates.
  TCivUnit* civUnit10;

  TMiniCivLine();
};

ASSERT_SIZE(TMiniCivLine, 0x14);
