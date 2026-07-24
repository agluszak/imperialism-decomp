#pragma once

#include "compat.h"
#include "game/ui_screens/CString.h"
#include "game/military/TUnit.h"
#include "game/military_domain_types.h"

class TMission;

// Military unit (RTTI CRuntimeClass descriptor 0x0066ed70, object size 0x44).
// This single class was previously reconstructed twice under two different
// names by independent sessions before it was recognized as one class
// (evidence: TMilitaryUnitOrderState::GetRuntimeClass at 0x5c2dd0 returned the
// literal 0x66ed70 CRuntimeClass address, and this class's four
// "battlefield-unit" getters (0x5c3400/0x5c3490/0x5c34d0/0x5c3530) read
// [ecx+0x4]/[ecx+0x6] -- exactly the inherited TUnit::orderType/tileIndex06
// slots):
//  - the per-nation military-recruit ORDER object queued by TGreatPower's
//    slot-0x32 order family (ctor 0x5c2df0; the DYNCREATE CreateObject
//    factory at 0x5c2cb0 is a twin that fully inlines the same ctor body
//    rather than calling out to 0x5c2df0 -- claimed as SYNTHETIC alongside
//    GetRuntimeClass in the .cpp per the IMPLEMENT_DYNCREATE macro), and
//  - once resolved, a list entry of TGreatPower::militaryUnitList44
//    (CIterator walk), and
//  - a node of the per-region stationed-unit chain (cityScoreTable +0x98,
//    intrusively linked through the inherited TUnit::nextOnTile field) --
//    the retired TStationedUnitNode model.
// Real C++ base is TUnit: the ctor disassembly writes TUnit's vtable
// (0x0066ee18) first, then overwrites it with this class's own 0x0066eea8 --
// vptr-write evidence outranks the RTTI oracle's base_descriptor field (which
// reports TObject directly), so IMPLEMENT_DYNCREATE in the .cpp still names
// TUnit as the base per the class-recovery evidence order.
// VTABLE: IMPERIALISM 0x0066eea8
class TMilitaryUnit : public TUnit {
public:
  DECLARE_DYNCREATE(TMilitaryUnit)

  CString name24; // 0x24 display name (naming pass in TCountry.cpp)

  // 0x28-0x33: three (target, mirror) short pairs written by
  // ClearPath (0x5c3190) from the inherited
  // TUnit::tileIndex06 "current tile" value at recruit-order init time; exact
  // per-slot semantics (order targets vs a confirm/mirror copy) unconfirmed.
  short orderTargetTiles28[3];       // 0x28, 0x2a, 0x2c
  short orderTargetTilesMirror2E[3]; // 0x2e, 0x30, 0x32

  // field_34/36/38/3A round-trip through ReadFrom/WriteTo (0x5c2fd0/0x5c30a0);
  // field_3C/pad3E/ownerMission40 do not -- transient/derived, not persisted.
  short field_34;           // 0x34 init 0x1f4; strength scalar (scaled by 0.002 in 0x53cc10)
  short field_36;           // 0x36 derived from recruit cap value (IMilitaryUnit)
  short field_38;           // 0x38 init 0; percent-scaled quality (divided by 100 in 0x53cc10)
  short field_3A;           // 0x3a init 0
  short field_3C;           // 0x3c init 0
  short pad3E;              // 0x3e
  TMission* ownerMission40; // 0x40 owning mission back-pointer (order-list adoption)

  TMilitaryUnit();
  virtual ~TMilitaryUnit() override;

  // Mac name oracle: IMilitaryUnit. Four-stack-arg thiscall (ret 0x10); the trailing short forwards into
  // RegisterUnitOrderWithOwnerManager (default 0 preserves the 3-arg callers' codegen).
  void IMilitaryUnit(MilitaryUnitKindStorage unitKind, int nodeContext, short nationSlot,
                     short registerArg3 = 0);

  // --- TObject/TUnit overrides ---
  void ReadFrom(TStream* stream) override;
  void WriteTo(TStream* stream) override;
  void MoveTo(int nTileIndex) override;
  void DetachUnitOrderFromOwnerAndReset() override;

  // --- TMilitaryUnit virtual functions ---
  virtual void ClearPath();

  // --- non-virtual battlefield-unit accessors; operate on the inherited
  // TUnit fields (orderType@0x04 read as a unit-type-id index into the
  // per-unit-type tables, tileIndex06@0x06 read as the stationed province id) ---
  short GetArmsCarried() const;                                   // 0x5c3400
  ArmyUnitCategoryStorage GetCategory() const;                    // 0x5c3490
  short GetTurnDistanceTo(short provinceId) const;                // 0x5c34d0
  bool IsWithinXTurnsOf(short turnLimit, short targetTile) const; // 0x5c3500
  short GetAttribute(short statIndex) const;                      // 0x5c3530

  static short GetTypeArmsCarried(int unitTypeSlot);                                    // 0x5c3450
  static ArmyUnitCategoryStorage GetTypeCategory(MilitaryUnitKindStorage unitTypeSlot); // 0x5c34b0
  static short GetTypeAttribute(MilitaryUnitKindStorage unitTypeSlot,
                                short statIndex); // 0x5c3580
  // Sets or clears the bits of `mask` in field_3A. 0x004a3b30, __thiscall, 2 args.
  void SetOrClearWordMaskBits3a(short mask, bool setFlag);
  // Era-upgrade candidate for this unit's type (types 0..0xf upgrade to type+8;
  // Sapper/Combat Engineer and Era-1/Era-2 General upgrade to type+1), gated on
  // the owner nation's ability rows;
  // -1 when no upgrade applies. 0x5c35c0.
  MilitaryUnitKindStorage UpgradeType();
  bool CanUpgrade();
  // Returns the candidate unit type and its arms, cash and optional fuel costs.
  // The optional resource is zero unless the candidate profile uses resource id 0xc.
  void UpgradeRequirements(short& candidateSlot, short& armsCost, short& cashCost, short& fuelCost);
  // Pays the upgrade's resource/cash costs from the owner nation's stock counters and
  // treasury (fails without changing anything if any cost is unaffordable), then sets
  // the unit's type to the upgraded id. 0x5c3670.
  bool Upgrade();

  MilitaryUnitKind GetMilitaryUnitKind() const {
    return DecodeMilitaryUnitKind(this->orderType);
  }

  static TMilitaryUnit* FindUnitByUID(int unitId); // 0x5c38e0
};

ASSERT_SIZE(TMilitaryUnit, 0x44);
