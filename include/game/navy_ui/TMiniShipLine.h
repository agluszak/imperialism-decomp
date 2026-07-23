#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065db28
class TMiniShipLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniShipLine)
  virtual ~TMiniShipLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x569c80

  TMiniShipLine();

  // Original object size is 0x14 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  TShip* field10;
};
