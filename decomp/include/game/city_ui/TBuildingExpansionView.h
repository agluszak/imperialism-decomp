#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;

// VTABLE: IMPERIALISM 0x006528d8
class TBuildingExpansionView : public TPicture {
public:
  DECLARE_DYNCREATE(TBuildingExpansionView)
  virtual ~TBuildingExpansionView() override;
  virtual void StuffValues(short buildingSlotId, TCity* city, TCityProductionView* productionView);
  virtual void DoClosingAction(unsigned long dialogActionTag);

  TBuildingExpansionView();

  // Windows StuffValues stores the first argument as a word, then the two typed pointers.
  short buildingSlotId;
  unsigned char padding92[2];
  TCity* city;
  TCityProductionView* productionView;
};
ASSERT_SIZE(TBuildingExpansionView, 0x9c);
