#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/military/TUnit.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// A node in TArmyStack's embedded intrusive unit chain (head14/cursor18).
struct TArmyStackUnitNode {
  TUnit* unit;              // +0x00
  TArmyStackUnitNode* next; // +0x04
};

// VTABLE: IMPERIALISM 0x0064ca38
class TArmyStack : public TObject {
public:
  DECLARE_DYNCREATE(TArmyStack)
  virtual ~TArmyStack() override;                  // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a7960
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a77b0
  virtual void Free() override;                    // slot 0x07 0x4a7c20
  // Field layout from FormStacks's construction site (0x4a1f80, `new TArmyStack()` +
  // scatter-init) and ResolveNextMove's
  // (0x4a2390) reads. TObject's own vptr occupies the first 4 bytes.
  short field4; // +0x04 -- zeroed at construction
  short field6; // +0x06 -- zeroed at construction
  // +0x08 -- region/owner category; signed (indexed/compared via movsx/jge in the
  // original) and compared against TArmyMgr::perTileOwnerNationCodeCache1c.
  signed char categoryFlag8;
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

  // Walk the unit chain re-seating every unit: hand each one its own orderTargetIndex0C through
  // MoveTo (slot 0x28) and then clear its orders via SetOrders(0, -1).
  // 0x004a7d20, __thiscall.
  void ReseatChainUnitsAndClearOrders();

  // Derive this stack's composition code from its unit chain: take the min and max
  // per-unit combat class over the chain (seeded 3 / 1), look the pair up in
  // g_abStackCompositionClassTable, store it in field4, and pack field6 as
  // (field4 << 8) | (rand() & 0xff). 0x004a7c60, __thiscall.
  void ComputeStackCompositionClassCode();

  // Mac oracle: TArmyStack::InitializeStrategicBattle(unsigned char).
  // Snapshots unit strength, initializes battle-state bits, and caches the originating
  // province's fort penalty for the strategic-combat pass.
  void InitializeStrategicBattle(unsigned char boosted);

  // Resets cursor18 to head14 and returns its unit (nullptr if the chain is empty).
  // 0x004a3b70, __thiscall, no args.
  TUnit* ResetCursorAndGetHeadUnit();
  // Advances cursor18 to its next node and returns that node's unit (nullptr if there is
  // no next node, or the cursor was already null). 0x004a3b90, __thiscall, no args.
  TUnit* AdvanceCursorAndGetUnit();

  // Finds the first unit of type `unitTag` in this stack's owning country's military unit
  // list and prepends it to the embedded node chain. 0x004a7a40.
  void AddFirstCountryUnitOfTypeToStack(short unitTag);
  // Walks the whole chain from head14 (via ResetCursorAndGetHeadUnit/
  // AdvanceCursorAndGetUnit) and, for every unit with a positive strength34 (strength),
  // grows experiencePercent38 (percent-scaled quality) by 35 if boosted else 20, capped at 400.
  // 0x004a82b0, __thiscall, 1 arg.
  void ApplyMeterGrowthToEligibleUnits(bool boosted);
  bool UnitsFighting(); // 0x4a8330, Mac oracle
  // Walks the chain accumulating a weighted meter sum and eligible-entry count into the
  // two out-params, seeded by `counter`. 0x004a7e70, 355 bytes; signature verified via
  // TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState's callsite disassembly.
  void AccumulateWeightedMeterAndCountFromEligibleLinkedEntries(int* outWeightedSum, int* outCount,
                                                                int counter);
  // Applies a randomized decay to eligible entries using the accumulated weighted sum/
  // count from the method above. 0x004a8040, 482 bytes.
  void ApplyRandomizedMeterDecayToEligibleLinkedEntries(int weightedSum, int count, int counter);
  // Re-initializes the stack for one tactical-battle side: zeroes field4/field6/fieldA/
  // fieldC and stores the owner nation index, owner nation code, and originating tile.
  // 0x004a7770, __thiscall, ret 0xc.
  void IArmyStack(char ownerNationIndex, short ownerNationCode, short tileIndex);
  // Pushes a unit node at the head of the embedded chain (alloc-failure assert via
  // UArmyMgr.cpp line 0xbeb) and bumps the fieldA unit count. 0x004a7b20.
  void AddUnitToChainHead(TUnit* unit);
  // Unlinks and deletes the first node whose unit pointer matches (searches head14,
  // then walks the chain), decrementing fieldA. No-op if not found. 0x004a7ba0.
  void RemoveUnitFromChain(TUnit* unit);

  TArmyStack();
};
ASSERT_SIZE(TArmyStack, 0x1c);
