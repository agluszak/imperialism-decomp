#pragma once

#include "game/app/TObject.h"
#include "game/unit_domain_types.h"

// Base class for the per-nation pending unit-order objects (civilian work,
// military recruit, navy task-force). The concrete subclasses each install their
// own vtable in the packed 0x0066ee18 region:
//   TUnit     -> 0x0066ee18 (this base, 18-slot table; 0x0e-0x11 null)
//   TCivUnit  -> 0x0066ee60
//   military recruit    -> 0x0066eea8
// VTABLE: IMPERIALISM 0x0066ee18
class TUnit : public TObject {
public:
  // --- TObject overrides ---
  DECLARE_DYNCREATE(TUnit)
  ~TUnit() override; // slot 0x04

  // slot 0x08 Serialize is inherited from TObject unchanged (0x485e90)

  void WriteTo(TStream* stream) override;  // slot 0x14
  void ReadFrom(TStream* stream) override; // slot 0x18
  void Free() override;                    // slot 0x1c

  // --- TUnit virtual functions ---
  // Mac oracle: MoveTo(short) on TUnit/TCivUnit/TMilitaryUnit. The argument is the
  // destination tile index (-1 = detach only); the overrides relink the unit between
  // the per-tile / per-city-record order chains. Base body is a no-op.
  virtual void MoveTo(int nTileIndex);                  // slot 0x28
  virtual void ContinueOrders();                        // slot 0x2c, Mac oracle
  virtual void DetachUnitOrderFromOwnerAndReset();      // slot 0x30
  virtual void SetOrders(UnitOrder order, int payload); // slot 0x34

  short orderType; // 0x04
  // 0x06 — anchor index of the order (-1 = unassigned); the domain depends on the
  // unit type: for civilian units it is a map tile index (read as the recruit/
  // civilian target tile by TMapMgr and matched against the terrain table by
  // TGreatPower slot 0x298), but for TMilitaryUnit it holds the stationed
  // city-record index (0..0x180 rows of TMapMgr::cityScoreTable) — established at
  // TMapMgr 0x518d90 and by the TSuperArmyRoster selection flow (bd 7v4).
  short tileIndex06;
  UnitOrder unitOrder; // 0x08
  short field_C;       // 0x0c
  short field_E;       // 0x0e
  // Doubly-linked-list back-pointer for the tile's civilian-order chain (terrainState-
  // Table[tileIndex06].firstCivilianOrder20, threaded via nextOnTile); null when this is
  // the chain head. Recovered from TCivUnit::MoveTo (0x5c2b70), which dereferences
  // it at +0x14 (TUnit::nextOnTile's own offset).
  TUnit* field_10;        // 0x10
  TUnit* nextOnTile;      // 0x14
  short field_18;         // 0x18
  short field_1A;         // 0x1a
  unsigned char field_1C; // 0x1c
  unsigned char pad1d[3]; // 0x1d
  int field_20;           // 0x20

  // Inlined base initializer (the 0x5c28c0 / 0x5c2df0 ctors open-code this). Kept
  // header-inline so MSVC folds it into each subclass ctor and dead-store-
  // eliminates the base vptr write, leaving the single derived vptr write the
  // originals emit.
  // In-class inline: the original has no out-of-line TUnit::TUnit -- every
  // caller absorbs it, so an out-of-line definition pessimizes them into a call.
  TUnit() {
    field_10 = 0;
    nextOnTile = 0;
    tileIndex06 = static_cast<short>(0xffff);
    unitOrder = kUnitOrderIdle;
    field_1C = 0;
  }

  void RegisterUnitOrderWithOwnerManager(short nOrderType, int anchorIndex,
                                         short nOrderOwnerNationId, short arg3);
};

ASSERT_SIZE(TUnit, 0x24);
