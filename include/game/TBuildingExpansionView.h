#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;

// VTABLE: IMPERIALISM 0x006528d8
class TBuildingExpansionView : public TPicture {
public:
  DECLARE_DYNCREATE(TBuildingExpansionView)
  virtual ~TBuildingExpansionView() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues(short buildingSlotId, TCity* city,
                           TCityProductionView* productionView); // slot 0x73 0x4ce5a0
  virtual void DoClosingAction(unsigned long dialogActionTag);   // slot 0x74 0x4cebb0

  TBuildingExpansionView();

  // Windows StuffValues stores the first argument as a word, then the two typed pointers.
  short buildingSlotId90;
  unsigned char padding92[2];
  TCity* city94;
  TCityProductionView* productionView98;
};
