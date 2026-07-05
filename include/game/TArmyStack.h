#pragma once

#include "game/TObject.h"
#include "game/TUnit.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// A node in TArmyStack's embedded intrusive unit chain (head14/cursor18).
struct TArmyStackUnitNode {
  TUnit* unit;              // +0x00
  TArmyStackUnitNode* next; // +0x04
};

// TODO(manifest): describe TArmyStack and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TArmyStack -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064ca38
class TArmyStack : public TObject {
public:
  // === BEGIN GENERATED DECLS (TArmyStack) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyStack)
  virtual ~TArmyStack(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a7960
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a77b0
  virtual void Free() override;                    // slot 0x07 0x4a7c20
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // === END GENERATED DECLS (TArmyStack) ===
  // Field layout from ProcessTileUnitListsAndApplyRandomStatusUpdates's construction site
  // (0x4a1f80, `new TArmyStack()` + scatter-init) and OrphanCallChain_C12_I108_004a2390's
  // (0x4a2390) reads. TObject's own vptr occupies the first 4 bytes.
  short field4;                // +0x04 -- zeroed at construction
  short field6;                // +0x06 -- zeroed at construction
  unsigned char categoryFlag8; // +0x08 -- compared against TArmyMgr::perTileOwnerNationCodeCache1c
  // +0x09 -- cached g_anFortLevelAttackerPenaltyPercentByLevel lookup for the
  // most-recently-processed unit in UpdateDualLinkedEntryMetersAndBlinkState's Phase 1/2
  // scan; that scan stops early once this hits 0.
  unsigned char fortLevelAttackerPenaltyCache9;
  short fieldA;         // +0x0a -- zeroed at construction
  unsigned char fieldC; // +0x0c -- zeroed at construction
  unsigned char padD;
  short ownerNationCodeE; // +0x0e -- region/owner-nation code
  short tileIndex10;      // +0x10 -- originating tile index / order-target province
  unsigned char pad12[2];
  TArmyStackUnitNode* head14;   // +0x14 -- head of an embedded {TUnit*, next} node chain
  TArmyStackUnitNode* cursor18; // +0x18 -- traversal cursor over the chain

  // Resets cursor18 to head14 and returns its unit (nullptr if the chain is empty).
  // 0x004a3b70, __thiscall, no args.
  TUnit* ResetCursorAndGetHeadUnit();
  // Advances cursor18 to its next node and returns that node's unit (nullptr if there is
  // no next node, or the cursor was already null). 0x004a3b90, __thiscall, no args.
  TUnit* AdvanceCursorAndGetUnit();
  // Walks the whole chain from head14 (via ResetCursorAndGetHeadUnit/
  // AdvanceCursorAndGetUnit) and, for every unit with a positive field_34 (strength),
  // grows field_38 (percent-scaled quality) by 35 if boosted else 20, capped at 400.
  // 0x004a82b0, __thiscall, 1 arg.
  void ApplyMeterGrowthToEligibleUnits(bool boosted);
  // Walks the chain accumulating a weighted meter sum and eligible-entry count into the
  // two out-params, seeded by `counter`. 0x004a7e70, 355 bytes. TODO stub body (not yet
  // ported); signature verified via TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState's
  // callsite disassembly.
  void AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(int* outWeightedSum, int* outCount,
                                                                int counter);
  // Applies a randomized decay to eligible entries using the accumulated weighted sum/
  // count from the method above. 0x004a8040, 482 bytes. TODO stub body (not yet ported).
  void ApplyRandomizedMeterDecayToEligibleLinkedEntries(int weightedSum, int count, int counter);

  TArmyStack();
};

// === BEGIN GENERATED (TArmyStack) — refreshed by `just gen-class TArmyStack`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064ca38 (10 slots), object size 0x1c, base TObject
//   slot 0x00  byte 0x00  0x004a76d0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004a7720  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004a7960  override  WriteTo
//   slot 0x06  byte 0x18  0x004a77b0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004a7c20  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0x1c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TArmyStack) ===
