#pragma once

#include "game/TMinister.h"

// VTABLE: IMPERIALISM 0x006549b0
class TDefenseMinister : public TMinister {
public:
// === BEGIN GENERATED DECLS (TDefenseMinister) — refreshed by recover-class; do not hand-edit ===
  virtual ~TDefenseMinister(); // slot 0x01 (scalar deleting destructor)
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

  CRuntimeClass* GetRuntimeClass() const override; // slot 0 (0x4ec0c0)
  void WriteTo(TStream* stream) override;          // 5 (0x4ec1d0)
  void ReadFrom(TStream* stream) override;         // 6 (0x4ec2f0)
  short DispatchNationStateEventCode10(short nationSlot) override; // 0x0a (0x4ec3d0)

  // New virtuals introduced by TDefenseMinister (vtable 0x6549b0, bytes 0x48-0x60).
  virtual void MinisterSlot12();                                    // 0x48 (0x4ec450)
  virtual void Call4C();                                           // 0x4c (0x4ec4c0)
  virtual void MinisterSlot14();                                   // 0x50 (0x4ec540)
  virtual undefined BuildTileRingPriorityMapForNationTileList();    // 0x54 (0x4ecbb0)
  virtual undefined BuildStrategicTilePriorityHeatmap();           // 0x58 (0x4ecf20)
  virtual undefined BuildHexAreaTileIndexListIntoAllocatedBuffer(); // 0x5c (0x4ed050)
  virtual undefined CreateTDefenseMinisterInstance();             // 0x60 (0x4ec0a0)
};

// === BEGIN GENERATED (TDefenseMinister) — refreshed by `just gen-class TDefenseMinister`; do not hand-edit ===
// clang-format off
// vtable @ 0x006549b0 (25 slots), object size 0x94, base TMinister
//   slot 0x00  byte 0x00  0x004ec0c0  override  GetTMinisterClassNamePointer
//   slot 0x01  byte 0x04  0x004ec110  override  DeletingDestructTMinister
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004ec1d0  override  SetForeignMinisterPrimaryAndSecondaryTargets
//   slot 0x06  byte 0x18  0x004ec2f0  override  GetTEventHandlerClassNamePointer
//   slot 0x07  byte 0x1c  0x0052ec80  inherited VTableSlot07
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004ec3d0  override  GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0052ed50  inherited VTableSlot0B
//   slot 0x0c  byte 0x30  0x0052ee20  inherited GetTEventHandlerClassNamePointer
//   slot 0x0d  byte 0x34  0x0052eea0  inherited VTableSlot0D
//   slot 0x0e  byte 0x38  0x0052ef80  inherited GetTEventHandlerClassNamePointer
//   slot 0x0f  byte 0x3c  0x0052ef20  inherited VTableSlot0F
//   slot 0x10  byte 0x40  0x0052ef50  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x11  byte 0x44  0x0052efb0  inherited NoOpForeignMinisterUtilityStub
//   slot 0x12  byte 0x48  0x004ec450  new       OrphanCallChain_C11_I88_004874b0
//   slot 0x13  byte 0x4c  0x004ec4c0  new       GetTEventHandlerClassNamePointer
//   slot 0x14  byte 0x50  0x004ec540  new       SetForeignMinisterReadyFlag14
//   slot 0x15  byte 0x54  0x004ecbb0  new       ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x16  byte 0x58  0x004ecf20  new       UpdateControlCachedIntFromWindowText
//   slot 0x17  byte 0x5c  0x004ed050  new       OrphanRetStub_0059add0
//   slot 0x18  byte 0x60  0x004ec0a0  new       SerializeNodeMapEntries_Key32Value32_WithArchive
// object size 0x94 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TDefenseMinister) ===
