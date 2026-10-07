#pragma once

#include "game/app/TObject.h"
#include "game/unit_domain_types.h"

// VTABLE: IMPERIALISM 0x0066ee18
class TUnit : public TObject {
public:
  // --- TObject overrides ---
  DECLARE_DYNCREATE(TUnit)
  // FUNCTION: IMPERIALISM 0x005c2510
  ~TUnit() override {}

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  virtual void MoveTo(short nTileIndex);
  virtual void ContinueOrders();
  virtual void Vaporize();
  virtual void SetOrders(UnitOrder order, int payload);

  short orderType;
  short tileIndex;
  UnitOrder unitOrder;
  short orderTargetIndex;
  short pad0E;
  TUnit* previousAtLocation;
  TUnit* nextAtLocation;
  short ownerNationSlot;
  short unitRosterId;
  bool militaryRegistrationFlag;
  unsigned char pad1d[3];
  int persistentUnitId;

  TUnit() {
    previousAtLocation = 0;
    nextAtLocation = 0;
    tileIndex = -1;
    militaryRegistrationFlag = false;
  }

  void IUnit(short nOrderType, int anchorIndex, short nOrderOwnerNationId, short arg3);
};

ASSERT_SIZE(TUnit, 0x24);
