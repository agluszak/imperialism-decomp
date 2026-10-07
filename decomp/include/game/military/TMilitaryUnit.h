#pragma once

#include "compat.h"
#include "game/core/CString.h"
#include "game/military/TUnit.h"
#include "game/military_domain_types.h"

class TMission;

// VTABLE: IMPERIALISM 0x0066eea8
class TMilitaryUnit : public TUnit {
public:
  DECLARE_DYNCREATE(TMilitaryUnit)

  CString name; // display name (naming pass in TCountry.cpp)

  short orderTargetTiles[3];
  short orderTargetTilesMirror[3];

  short strength;          // init 0x1f4; scaled by 0.002 in
  short eraIndex;          // derived from unit kind / 8
  short experiencePercent; // init 0; divided by 100 in
  short battleStateFlags;  // init 0
  short strengthSnapshot;  // init 0
  TMission* ownerMission;  // owning mission back-pointer

  TMilitaryUnit();
  virtual ~TMilitaryUnit() override;

  void IMilitaryUnit(MilitaryUnitKindStorage unitKind, int nodeContext, short nationSlot,
                     short registerArg3 = 0);

  // --- TObject/TUnit overrides ---
  void ReadFrom(TStream* stream) override;
  void WriteTo(TStream* stream) override;
  void MoveTo(short anchorIndex) override;
  void Vaporize() override;

  // --- TMilitaryUnit virtual functions ---
  virtual void ClearPath();

  short GetArmsCarried() const;
  ArmyUnitCategoryStorage GetCategory() const;
  short GetTurnDistanceTo(short provinceId) const;
  bool IsWithinXTurnsOf(short turnLimit, short targetTile) const;
  short GetAttribute(short statIndex) const;

  static short GetTypeArmsCarried(int unitTypeSlot);
  static ArmyUnitCategoryStorage GetTypeCategory(MilitaryUnitKindStorage unitTypeSlot);
  static short GetTypeAttribute(MilitaryUnitKindStorage unitTypeSlot, short statIndex);
  // Sets or clears `mask` in battleStateFlags.
  void SetOrClearBattleStateFlags(short mask, bool setFlag);
  MilitaryUnitKindStorage UpgradeType();
  bool CanUpgrade();
  void UpgradeRequirements(short& candidateSlot, short& armsCost, short& cashCost, short& fuelCost);
  bool Upgrade();

  MilitaryUnitKind GetMilitaryUnitKind() const {
    return DecodeMilitaryUnitKind(this->orderType);
  }

  static TMilitaryUnit* FindUnitByUID(int unitId);
};

ASSERT_SIZE(TMilitaryUnit, 0x44);
