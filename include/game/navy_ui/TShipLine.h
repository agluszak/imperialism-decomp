#pragma once

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

class TMapOrderChildLinkNode;
class TShip;
class TTaskForce;

// VTABLE: IMPERIALISM 0x0065cde8
class TShipLine : public TLineData {
public:
  DECLARE_DYNCREATE(TShipLine)
  // FUNCTION: IMPERIALISM 0x00564fc0
  virtual ~TShipLine() override {} // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x565100

  // NOOP: verified empty in original 0x00565063 (no standalone TShipLine::TShipLine body exists: CreateObject 0x00565030 inlines this default ctor, calling the TLineData base ctor directly at that site)
  TShipLine() {}

  // Two-phase init (MacApp IViewClass idiom): shared TLineData row/bounds, then the
  // child link and its owning force. shipNode10 is derived from the link's payload
  // rather than passed. 0x005650c0, __thiscall.
  void IShipLine(short rowArg, short colArg, int* bounds, TMapOrderChildLinkNode* childLink,
                 TTaskForce* force);
  // Source ship, its task-force child-link cell (for checkbox state), and the owning
  // task force used by the row's TShipView event path.
  TShip* shipNode10;
  TMapOrderChildLinkNode* childLink14;
  TTaskForce* taskForce18;
};

ASSERT_SIZE(TShipLine, 0x1c);
