#pragma once

#include "game/city_ui/TBuildingView.h"
#include "game/mfc.h"

class TUnitOrder;

// VTABLE: IMPERIALISM 0x00652b10
class TArmoryView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TArmoryView)
  virtual ~TArmoryView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;    // slot 0x07 0x4d0470
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                         // slot 0x0f 0x004cf350
  virtual void DoStartup() override;                                    // slot 0x75 0x4cee20
  virtual void UpdateFields() override;                                 // slot 0x76 0x4cf5c0
  virtual void RefreshCityViewProductionDetails(short nBuildingSlotId); // slot 0x79 0x4cfbd0

  TArmoryView();

  // Original object size is 0xac. Windows has no accesses in the +0xa0 dword.
  unsigned char paddingA0[4];
  // 0xa4 -- selected production-row index (0..8), set from the 'rec0'..'rec8'/'sele' tab
  // controls in DoEvent; a 16-bit store in the original (0x4cf350), not a full int.
  short selectedRowIndexA4;
  char pad_a6[2];
  // Selected city production order. RefreshCityViewProductionDetails indexes
  // city94->orderSlotsE4 at selectedRowIndexA4 + 0x19, the TUnitOrder band.
  TUnitOrder* selectedUnitOrderA8;
};
