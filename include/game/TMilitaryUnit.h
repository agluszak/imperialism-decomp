#pragma once

#include "compat.h"
#include "game/CString.h"
#include "game/TObject.h"

class TMission;

// Military unit (RTTI: descriptor 0x66ed70, object size 0x44, base TObject).
// One object serves both surfaces that were previously modelled as two separate
// classes:
//  - list entry of TGreatPower::militaryUnitList44 (CIterator walk), and
//  - node of the per-region stationed-unit chain (cityScoreTable +0x98,
//    intrusively linked through next14) — the retired TStationedUnitNode model.
// Constructor/vtable/serialization (CreateObject 0x5c2cb0) are not ported yet;
// this is a field/getter surface model only.
class TMilitaryUnit : public TObject {
public:
  short unitTypeId04;          // 0x04 index into the per-unit-type tables
  short stationedProvinceId06; // 0x06 province/context the unit is stationed in
  unsigned char pad08[0x14 - 0x08];
  TMilitaryUnit* next14; // 0x14 next in the stationed-unit chain
  unsigned char pad18[0x1a - 0x18];
  short nameTag1a; // 0x1a — 0 means unnamed (slot 0x0f naming pass)
  unsigned char pad1c[0x24 - 0x1c];
  CString displayName24; // 0x24
  unsigned char pad28[0x34 - 0x28];
  short field_34; // 0x34 strength scalar (scaled by 0.002 in 0x53cc10)
  unsigned char pad36[0x38 - 0x36];
  short field_38; // 0x38 percent-scaled quality (divided by 100 in 0x53cc10)
  unsigned char pad3a[0x40 - 0x3a];
  TMission* ownerMission40; // 0x40 owning mission back-pointer (order-list adoption)

  short GetUnitMovementClassId();                   // 0x5c3490
  short GetUnitTypeCostPoints();                    // 0x5c3400
  short IsNotStationedInProvince(short provinceId); // 0x5c34d0
  short GetUnitTypeStatPercent(short statIndex);    // 0x5c3530
};

ASSERT_SIZE(TMilitaryUnit, 0x44);
