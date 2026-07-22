#pragma once

#include "compat.h"
#include "game/TPicture.h"
#include "game/mfc.h"

class TCity;
class TCityProductionView;
// VTABLE: IMPERIALISM 0x00651d88
class TBuildingConstructionView : public TPicture {
public:
  DECLARE_DYNCREATE(TBuildingConstructionView)
  virtual ~TBuildingConstructionView() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues(short buildingSlotId, TCity* city,
                           TCityProductionView* productionView); // slot 0x73 0x4c9eb0
  virtual void DoClosingAction(unsigned long dialogActionTag);   // slot 0x74 0x4ca8f0
  // TPicture's own slice ends at 0x90 (ASSERT_SIZE); RTTI oracle confirms
  // sizeof(TBuildingConstructionView) == 0x9c. The ctor (0x4c9e30) zeroes pCity (+0x90)
  // and productionView98 (+0x98); StuffValues writes the 16-bit building slot at +0x94.
  TCity* city90;                         // +0x90 owning city context
  short buildingSlotId94;                // +0x94
  unsigned char padding96[2];            // +0x96
  TCityProductionView* productionView98; // +0x98

  TBuildingConstructionView();
};

ASSERT_SIZE(TBuildingConstructionView, 0x9c);
