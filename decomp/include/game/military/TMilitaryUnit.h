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

  CString name24; // 0x24 display name (naming pass in TCountry.cpp)

  short orderTargetTiles[3];       // 0x28, 0x2a, 0x2c
  short orderTargetTilesMirror[3]; // 0x2e, 0x30, 0x32

  short strength34;        // 0x34 init 0x1f4; scaled by 0.002 in 0x53cc10
  short eraIndex;          // 0x36 derived from unit kind / 8
  short experiencePercent; // 0x38 init 0; divided by 100 in 0x53cc10
  short battleStateFlags;  // 0x3a init 0
  short strengthSnapshot;  // 0x3c init 0
  short pad3E;             // 0x3e
  TMission* ownerMission;  // 0x40 owning mission back-pointer

  TMilitaryUnit();
  virtual ~TMilitaryUnit() override;

  void IMilitaryUnit(MilitaryUnitKindStorage unitKind, int nodeContext, short nationSlot,
                     short registerArg3 = 0);

  // --- TObject/TUnit overrides ---
  void ReadFrom(TStream* stream) override;
  void WriteTo(TStream* stream) override;
  void MoveTo(short nTileIndex) override;
  void Vaporize() override;

  // --- TMilitaryUnit virtual functions ---
  virtual void ClearPath();

  short GetArmsCarried() const;                                   // 0x5c3400
  ArmyUnitCategoryStorage GetCategory() const;                    // 0x5c3490
  short GetTurnDistanceTo(short provinceId) const;                // 0x5c34d0
  bool IsWithinXTurnsOf(short turnLimit, short targetTile) const; // 0x5c3500
  short GetAttribute(short statIndex) const;                      // 0x5c3530

  static short GetTypeArmsCarried(int unitTypeSlot);                                    // 0x5c3450
  static ArmyUnitCategoryStorage GetTypeCategory(MilitaryUnitKindStorage unitTypeSlot); // 0x5c34b0
  static short GetTypeAttribute(MilitaryUnitKindStorage unitTypeSlot,
                                short statIndex); // 0x5c3580
  // Sets or clears `mask` in battleStateFlags. 0x004a3b30, __thiscall, 2 args.
  void SetOrClearBattleStateFlags(short mask, bool setFlag);
  MilitaryUnitKindStorage UpgradeType();
  bool CanUpgrade();
  void UpgradeRequirements(short& candidateSlot, short& armsCost, short& cashCost, short& fuelCost);
  bool Upgrade();

  MilitaryUnitKind GetMilitaryUnitKind() const {
    return DecodeMilitaryUnitKind(this->orderType);
  }

  static TMilitaryUnit* FindUnitByUID(int unitId); // 0x5c38e0
};

ASSERT_SIZE(TMilitaryUnit, 0x44);
