#pragma once

#include "game/TMinister.h"

class TLongintList;

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  virtual ~TDefenseMinister() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x07 Free inherited unchanged (0x52ec80)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a (byte 0x28) MinisterSlot0A overridden below (body 0x4ec3d0)
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
  void WriteTo(TStream* stream) override;                          // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;                         // 6 (0x4ec2f0)
  short DispatchNationStateEventCode10(short nationSlot) override; // 0x0a (0x4ec3d0)

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void MinisterSlot12(); // 0x48 (0x4ec450)
  virtual void Call4C();         // 0x4c (0x4ec4c0)
  virtual void MinisterSlot14(); // 0x50 (0x4ec540)
  // Builds a per-tile priority map (one byte per map tile, 0x1950 tiles): for every
  // region in ownedRegions, examines the 6 hex neighbors and scores border proximity
  // (4 = borders foreign territory, 3 = borders a 4-tile, 2 = borders a 3-tile or a
  // terrainType00==5 neighbor, 1 = borders a 2-tile), then a final pass adds +3 to
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
  virtual int* BuildStrategicTilePriorityHeatmap();                         // 0x58 (0x4ecf20)
  virtual undefined BuildHexAreaTileIndexListIntoAllocatedBuffer(char arg); // 0x5c (0x4ed050)
  // One stack arg (RET 0x4 across the base and all five personality overrides).
  // Not a factory despite the old Ghidra 'Create*Instance' names: every body
  // FLDs a per-personality FP weight constant (base 0.0f; the flag selects
  // between a pair on the conditional personalities). slot 0x60 (0x4ec0a0)
  virtual double GetPersonalityWeightByFlag(char flag);

  // +0x10..0x94 -- own block (RTTI m_nObjectSize proves this range is TDefenseMinister-
  // only, not shared TMinister base state; see TMinister.h). Fully recovered from
  // WriteTo/ReadFrom's byte-for-byte (de)serialization order (0x4ec1d0/0x4ec2f0) and the
  // five personality initializers below: two parallel 30-entry short tables (orig writes
  // orderWeightTableA/B via a shared zero-loop that indexes both 0x1e apart) plus a
  // 4-short threshold quad, exactly filling the object to its 0x94 size (`new
  // TDefenseMinister()` @ 0x4d976f pushes 0x94). Semantic role of each not yet pinned
  // down beyond "per-order/policy-type weight tables + summary thresholds".
  short field10;
  short field12;
  short orderWeightTableA[0x1e]; // +0x14..0x50
  short orderWeightTableB[0x1e]; // +0x50..0x8c
  short thresholdA;              // +0x8c
  short thresholdB;              // +0x8e
  short thresholdC;              // +0x90
  short thresholdD;              // +0x92
};

ASSERT_SIZE(TDefenseMinister, 0x94);
