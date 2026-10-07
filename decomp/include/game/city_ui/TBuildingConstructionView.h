#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;

// VTABLE: IMPERIALISM 0x00651d88
class TBuildingConstructionView : public TPicture {
public:
  DECLARE_DYNCREATE(TBuildingConstructionView)
  virtual void StuffValues(short buildingSlotId, TCity* city, TCityProductionView* productionView);
  virtual void DoClosingAction(unsigned long dialogActionTag);
  TCity* city; // owning city context
  short buildingSlotId;
  // +0x96 — cost/description format mode (1 or 2) selected by StuffValues per slot.
  short formatMode;
  TCityProductionView* productionView;

  TBuildingConstructionView();
};

ASSERT_SIZE(TBuildingConstructionView, 0x9c);
