#pragma once

#include "game/TObject.h"

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

  // slot 0x20 ShallowClone is inherited unchanged (0x4798d0)
  // slot 0x24 ShallowFree is inherited unchanged (0x415ce0)

  // --- TUnit virtual functions ---
  virtual void VTableSlot10(int pOwnerContext);           // slot 0x28
  virtual void ContinueOrders();                          // slot 0x2c, Mac oracle
  virtual void DetachUnitOrderFromOwnerAndReset();        // slot 0x30
  virtual void SetOrderModeSlot34(int mode, int payload); // slot 0x34

  short orderType; // 0x04
  // 0x06 — map tile index the order is anchored to (-1 = unassigned); read as
  // the recruit/civilian target tile by TMapMgr and matched against the terrain
  // table by TGreatPower slot 0x298.
  short tileIndex06;
  int field_8;   // 0x08
  short field_C; // 0x0c
  short field_E; // 0x0e
  // Doubly-linked-list back-pointer for the tile's civilian-order chain (terrainState-
  // Table[tileIndex06].firstCivilianOrder20, threaded via nextOnTile); null when this is
  // the chain head. Recovered from TCivUnit::VTableSlot10 (0x5c2b70), which dereferences
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
  TUnit();

  void RegisterUnitOrderWithOwnerManager(short nOrderType, int pOwnerContext,
                                         short nOrderOwnerNationId, short arg3);
};

ASSERT_SIZE(TUnit, 0x24);
