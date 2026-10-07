#pragma once

#include "game/app/TObject.h"
#include "game/unit_domain_types.h"

// VTABLE: IMPERIALISM 0x0066ee18
class TUnit : public TObject {
public:
  // --- TObject overrides ---
  DECLARE_DYNCREATE(TUnit)
  // FUNCTION: IMPERIALISM 0x005c2510
  ~TUnit() override {} // slot 0x04

  // slot 0x08 Serialize is inherited from TObject unchanged (0x485e90)

  void WriteTo(TStream* stream) override;  // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override;                    // slot 0x1c

  virtual void MoveTo(short nTileIndex);                // slot 0x28
  virtual void ContinueOrders();                        // slot 0x2c, Mac oracle
  virtual void Vaporize();                              // slot 0x30
  virtual void SetOrders(UnitOrder order, int payload); // slot 0x34

  short orderType; // 0x04
  short tileIndex;
  UnitOrder unitOrder;                    // 0x08
  short orderTargetIndex;                 // 0x0c
  short pad0E;                            // 0x0e
  TUnit* previousAtLocation;              // 0x10
  TUnit* nextAtLocation;                  // 0x14
  short ownerNationSlot;                  // 0x18
  short unitRosterId;                     // 0x1a
  unsigned char militaryRegistrationFlag; // 0x1c
  unsigned char pad1d[3];                 // 0x1d
  int persistentUnitId;                   // 0x20

  TUnit() {
    previousAtLocation = 0;
    nextAtLocation = 0;
    tileIndex = static_cast<short>(0xffff);
    militaryRegistrationFlag = 0;
  }

  void RegisterUnitOrderWithOwnerManager(short nOrderType, int anchorIndex,
                                         short nOrderOwnerNationId, short arg3);
};

ASSERT_SIZE(TUnit, 0x24);
