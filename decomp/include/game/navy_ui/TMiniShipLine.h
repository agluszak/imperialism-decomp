#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065db28
class TMiniShipLine : public TLineData {
public:
  DECLARE_DYNCREATE(TMiniShipLine)
  // FUNCTION: IMPERIALISM 0x00569b90
  virtual ~TMiniShipLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x569c80

  // NOOP: verified empty in original 0x00569be3 (no standalone TMiniShipLine::TMiniShipLine body exists: CreateObject 0x00569bb0 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TMiniShipLine() {}

  // Two-phase init (MacApp IViewClass idiom): sets the shared TLineData row/bounds
  // then this line's field10. 0x00569c40, __thiscall.
  void IMiniShipLine(short rowArg, short colArg, int* bounds, TShip* item);

  // Original object size is 0x14 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  TShip* field10;
};
ASSERT_SIZE(TMiniShipLine, 0x14);
