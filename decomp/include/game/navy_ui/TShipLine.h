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

  // NOOP: verified empty in original 0x00565063
  TShipLine() {}

  void IShipLine(short rowArg, short colArg, int* bounds, TMapOrderChildLinkNode* childLink,
                 TTaskForce* force);
  TShip* shipNode;
  TMapOrderChildLinkNode* childLink;
  TTaskForce* taskForce;
};

ASSERT_SIZE(TShipLine, 0x1c);
