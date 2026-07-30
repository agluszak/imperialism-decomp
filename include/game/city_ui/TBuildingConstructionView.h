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
  // TPicture's own slice ends at 0x90 (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TBuildingConstructionView) == 0x9c. The ctor (0x4c9e30) zeroes pCity (+0x90)
  // and productionView98 (+0x98); StuffValues writes the 16-bit building slot at +0x94.
  TCity* city90;          // +0x90 owning city context
  short buildingSlotId94; // +0x94
  // +0x96 — cost/description format mode (1 or 2) selected by StuffValues per slot.
  short formatMode96;
  // +0x98 — StuffValues stores its 3rd argument here as a TCityProductionView* (read back
  // by DoClosingAction), but also reuses the same 4 bytes as the 'tex2' string-resource
  // group. Modeled as an explicit union so both accesses use the same storage without a cast.
  union {
    TCityProductionView* productionView98;
    int dialogContextFlags98;
  };

  TBuildingConstructionView();
};

ASSERT_SIZE(TBuildingConstructionView, 0x9c);
