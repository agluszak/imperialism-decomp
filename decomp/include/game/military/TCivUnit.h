#pragma once

#include "decomp_types.h"
#include "game/military/TUnit.h"
#include "game/civilian_domain_types.h"

// VTABLE: IMPERIALISM 0x0066ee60
class TCivUnit : public TUnit {
public:
  DECLARE_DYNCREATE(TCivUnit)
  // FUNCTION: IMPERIALISM 0x005c2920
  virtual ~TCivUnit() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void MoveTo(short newTileIndex) override;
  virtual void ContinueOrders() override;
  virtual void Vaporize() override;
  virtual void SetOrders(UnitOrder order, short payload) override;
  virtual void ClearOrders();
  short remainingTurns;
  short completionMarker;

  TCivUnit();

  void ICivUnit(CivilianUnitKind unitKind, int anchorIndex, short nOrderOwnerNationId);
  CivilianUnitKind GetCivilianUnitKind() const {
    return DecodeCivilianUnitKind(this->orderType);
  }
  bool CanBeOrdered();
  void TickCivWorkOrderCountdownAndComplete();
};

ASSERT_SIZE(TCivUnit, 0x28);
