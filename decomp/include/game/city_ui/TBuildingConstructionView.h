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
  virtual void StuffValues(short buildingSlotId, TCity* city,
                           TCityProductionView* productionView); // slot 0x73 0x4c9eb0
  virtual void DoClosingAction(unsigned long dialogActionTag);   // slot 0x74 0x4ca8f0
  TCity* city90;                                                 // +0x90 owning city context
  short buildingSlotId;                                          // +0x94
  // +0x96 — cost/description format mode (1 or 2) selected by StuffValues per slot.
  short formatMode;
  TCityProductionView* productionView98; // +0x98

  TBuildingConstructionView();
};

ASSERT_SIZE(TBuildingConstructionView, 0x9c);
