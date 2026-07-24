#pragma once

#include "game/map/TMinister.h"

class TLongintList;

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  virtual ~TDefenseMinister() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x0a (byte 0x28) GetRankingCriterionForGP overridden below (body 0x4ec3d0)
  // slots 0x0b-0x11 inherited from TMinister unchanged
  TDefenseMinister();
  void InitializeBaseOrderArrayMetrics(TGreatPower* owner);

  // Five personality-specific order-array initializers (0x4ed560/0x4ed890/0x4edb80/
  // 0x4ede60/0x4ee150), one per TDefenseMinister-derived personality's construction
  // (Napoleon/Bismarck/Pirate/Defender/Bully). Each is its own compiled address (not a
  // shared parameterized call in the original -- likely inlined at each personality's
  // ctor call site from one small source helper), so each gets its own real method here
  // per Hard Rule 4. All five zero the same base-order-array region as
  // InitializeBaseOrderArrayMetrics, then seed their own orderWeightTableB prefix and
  // threshold quad.
  void InitializeOrderArrayPreset50_0_10_50(TGreatPower* owner);  // 0x4ed560
  void InitializeOrderArrayPreset10_10_10_50(TGreatPower* owner); // 0x4ed890
  void InitializeOrderArrayPreset15_20_50_75(TGreatPower* owner); // 0x4edb80
  void InitializeOrderArrayPreset20_10_10_50(TGreatPower* owner); // 0x4ede60
  void InitializeOrderArrayPreset25_10_20_50(TGreatPower* owner); // 0x4ee150

  DECLARE_DYNCREATE(TDefenseMinister)
  void WriteTo(TStream* stream) override;                    // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;                   // 6 (0x4ec2f0)
  short GetRankingCriterionForGP(short nationSlot) override; // 0x0a (0x4ec3d0)

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void GoShopping();     // 0x48 (0x4ec450), Mac oracle
  virtual void DoArmyMovement(); // 0x4c (0x4ec4c0), Mac oracle
  // Buckets militaryUnitList44 by orderType into three TList buckets, trims a batch of
  // up to 4 (or fewer, when small) bucket-1 units plus one bucket-2 unit to garrison
  // the nation's home tile, then selects the top border-priority-scored owned regions
  // (via BuildTileRingPriorityMapForNationTileList) and assigns 2 bucket-1 + 1
  // bucket-2 unit to each.
  virtual void DoPeacetimeDeployment(); // 0x50 (0x4ec540), Mac oracle
  // Builds a per-tile priority map (one byte per map tile, 0x1950 tiles): for every
  // region in ownedRegions, examines the 6 hex neighbors and scores border proximity
  // (4 = borders foreign territory, 3 = borders a 4-tile, 2 = borders a 3-tile or a
  // water neighbor, 1 = borders a 2-tile), then a final pass adds +3 to
  // any region with a qualifying activeFlags1c/resourceTypeByEdge[1] combination and
  // +1 to each of its neighbors that CheckTileProspectingDiscoveryCandidate accepts.
  // Caller owns the returned buffer (operator new[]/delete[]).
  virtual unsigned char*
  BuildTileRingPriorityMapForNationTileList(TLongintList* ownedRegions); // 0x54 (0x4ecbb0)
  // Per-tile strategic priority heatmap (one int per map tile, 0x1950 tiles): for
  // every tile this nation owns with a qualifying activeFlags1c/gateFlag combination,
  // adds 300 to the tile itself, 200 to each of its 6 immediate hex neighbors, and 100
  // to each of the 12 tiles in the radius-2 ring; every unowned tile with a nonzero
  // adjacencyBits06 gets a flat +100. Caller owns the returned buffer (operator
  // new[]/delete[]).
  virtual int* BuildStrategicTilePriorityHeatmap(); // 0x58 (0x4ecf20)
  // Per-tile stationed-unit-strength heatmap (one int per map tile): for every tile
  // this nation owns (or, when excludeEnemyTiles == 0, that a nation we're at war
  // with owns) whose stationed-unit chain head's field_18 differs from our nation
  // slot, walks the chain accumulating a per-hex-ring (own tile / radius 1 / 2 / 3)
  // weighted strength score (g_anUnitStrengthWeightPercentBySlot[orderType] *
  // TMilitaryUnit::field_34 / 100, cumulative up to g_awUnitCombatClassBySlot's
  // combat class) and a parallel "flag" value (2 for orderType 6/7 units, else the
  // default 1), then spreads both onto weightSum/maxWeight over the matching ring via
  // the already-ported BuildHexAreaTileIndexList. Faithfully reproduces two original
  // quirks: the second allocation's null-check tests the FIRST buffer again (not the
  // second), and the closing normalization loop multiplies weightSum[0] itself by every
  // maxWeight[i] > 1 rather than weightSum[i] (the per-ring maxWeight buffer is freed;
  // the per-tile hex-ring buffers are never freed, matching the original leak).
  virtual int* BuildHexAreaTileIndexListIntoAllocatedBuffer(char excludeEnemyTiles); // 0x5c
                                                                                     // (0x4ed050)
  // One stack arg (RET 0x4 across the base and all five personality overrides).
  // Not a factory despite the old Ghidra 'Create*Instance' names: every body
  // FLDs a per-personality FP weight constant (base 0.0f; the flag selects
  // between a pair on the conditional personalities). slot 0x60 (0x4ec0a0)
  virtual double GetPersonalityWeightByFlag(char flag);

  // +0x10..0x94 -- own block (RTTI m_nObjectSize proves this range is TDefenseMinister-
  // only, not shared TMinister base state; see TMinister.h). Fully recovered from
  // WriteTo/ReadFrom's byte-for-byte (de)serialization order (0x4ec1d0/0x4ec2f0) and the
  // five personality initializers below: recruitOrderCountByType is incremented whenever
  // the personality seeds a TMilitaryUnit recruit order; orderWeightTableB contains its
  // per-type policy weights. The two 30-entry short tables plus a 4-short threshold quad
  // exactly fill the object to its 0x94 size (`new TDefenseMinister()` @ 0x4d976f pushes
  // 0x94).
  short field10;
  short field12;
  short recruitOrderCountByType[0x1e]; // +0x14..0x50
  short orderWeightTableB[0x1e];       // +0x50..0x8c
  short thresholdA;                    // +0x8c
  short thresholdB;                    // +0x8e
  short thresholdC;                    // +0x90
  short thresholdD;                    // +0x92
};

ASSERT_SIZE(TDefenseMinister, 0x94);
