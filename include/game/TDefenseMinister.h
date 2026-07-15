#pragma once

#include "game/TMinister.h"

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
  // === BEGIN GENERATED DECLS (TDefenseMinister) — refreshed by recover-class; do not hand-edit ===
  virtual ~TDefenseMinister() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x07 Free inherited unchanged (0x52ec80)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a (byte 0x28) MinisterSlot0A overridden below (body 0x4ec3d0)
  // slots 0x0b-0x11 inherited from TMinister unchanged
  // === END GENERATED DECLS (TDefenseMinister) ===
  TDefenseMinister();
  void InitializeBaseOrderArrayMetrics();

  DECLARE_DYNCREATE(TDefenseMinister)
  void WriteTo(TStream* stream) override;                          // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;                         // 6 (0x4ec2f0)
  short DispatchNationStateEventCode10(short nationSlot) override; // 0x0a (0x4ec3d0)

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void MinisterSlot12();                                    // 0x48 (0x4ec450)
  virtual void Call4C();                                            // 0x4c (0x4ec4c0)
  virtual void MinisterSlot14();                                    // 0x50 (0x4ec540)
  virtual undefined BuildTileRingPriorityMapForNationTileList();    // 0x54 (0x4ecbb0)
  virtual undefined BuildStrategicTilePriorityHeatmap();            // 0x58 (0x4ecf20)
  virtual undefined BuildHexAreaTileIndexListIntoAllocatedBuffer(); // 0x5c (0x4ed050)
  virtual undefined CreateTDefenseMinisterInstance();               // 0x60 (0x4ec0a0)

  // Derived state 0x48..0x94 (sizeof = 0x94, from `new TDefenseMinister()` @ 0x4d976f
  // pushing 0x94 to operator new). Fields unrecovered; raw storage keeps the object the
  // correct size so callers' `operator new` size matches.
  unsigned char defenseState48[0x94 - 0x48];
};
