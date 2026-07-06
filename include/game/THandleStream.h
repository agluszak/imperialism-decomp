#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649410
class THandleStream : public TStream {
public:
  // clang-format off
  // === BEGIN GENERATED DECLS (THandleStream) — refreshed by recover-class; do not hand-edit ===
  virtual ~THandleStream(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x4896a0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a streamSlot28 owned by the hand declaration below (0x4896e0)
  // slot 0x0b streamSlot2c owned by the hand declaration below (0x489740)
  // slot 0x0c streamSlot30 owned by the hand declaration below (0x489700)
  // slot 0x0d streamSlot34 owned by the hand declaration below (0x489760)
  // slot 0x0e OrphanCallChain_C2_I15_00488a80 inherited unchanged (0x488a80)
  // slot 0x10 ReadInteger inherited unchanged (0x488b60)
  // slot 0x11 streamSlot44 inherited unchanged (0x488b90)
  // slot 0x12 OrphanCallChain_C1_I08_00488bc0 inherited unchanged (0x488bc0)
  // slot 0x13 ReadShort inherited unchanged (0x488bf0)
  // slot 0x14 ReadDwordFromStreamViaVtableSlot3C inherited unchanged (0x488c20)
  // slot 0x15 OrphanCallChain_C1_I13_00488ce0 inherited unchanged (0x488ce0)
  // slot 0x16 OrphanCallChain_C1_I06_00488d20 inherited unchanged (0x488d20)
  // slot 0x17 OrphanCallChain_C1_I06_00488d40 inherited unchanged (0x488d40)
  // slot 0x18 OrphanCallChain_C1_I06_00488d60 inherited unchanged (0x488d60)
  // slot 0x19 OrphanCallChain_C1_I06_00488d80 inherited unchanged (0x488d80)
  // slot 0x1a OrphanCallChain_C1_I09_00488da0 inherited unchanged (0x488da0)
  // slot 0x1b streamSlot6c inherited unchanged (0x488ca0)
  // slot 0x1c Helper_Uses_EnsureSharedStringCapacityPreserveLength_At00488c50 inherited unchanged (0x488c50)
  // slot 0x1d streamSlot74 inherited unchanged (0x488dd0)
  // slot 0x1e WriteBytesSlot78 owned by the hand declaration below (0x489810)
  // slot 0x1f OrphanCallChain_C1_I06_00488e90 inherited unchanged (0x488e90)
  // slot 0x20 OrphanCallChain_C1_I06_00488eb0 inherited unchanged (0x488eb0)
  // slot 0x21 streamSlot84 inherited unchanged (0x488ed0)
  // slot 0x22 OrphanCallChain_C1_I06_00488ef0 inherited unchanged (0x488ef0)
  // slot 0x23 WriteDwordToStreamViaVtableSlot78 inherited unchanged (0x488f10)
  // slot 0x24 OrphanCallChain_C1_I06_00488f30 inherited unchanged (0x488f30)
  // slot 0x25 OrphanCallChain_C1_I06_00488f50 inherited unchanged (0x488f50)
  // slot 0x26 OrphanCallChain_C1_I06_00488f70 inherited unchanged (0x488f70)
  // slot 0x27 OrphanCallChain_C1_I06_00488f90 inherited unchanged (0x488f90)
  // slot 0x28 OrphanCallChain_C1_I06_00488fb0 inherited unchanged (0x488fb0)
  // slot 0x29 OrphanCallChain_C1_I06_00488fd0 inherited unchanged (0x488fd0)
  // slot 0x2a CreateTFileStreamInstance inherited unchanged (0x489070)
  // slot 0x2b OrphanCallChain_C2_I21_00489030 inherited unchanged (0x489030)
  // slot 0x2c OrphanLeaf_NoCall_Ins02_00489980 inherited unchanged (0x489980)
  // slot 0x2d OrphanRetStub_004899a0 inherited unchanged (0x4899a0)
  // slot 0x2e OrphanCallChain_C2_I18_00488ff0 inherited unchanged (0x488ff0)
  // slot 0x2f AssertMcAppStreamLine304 inherited unchanged (0x488b10)
  // slot 0x30 AssertMcAppStreamLine596 inherited unchanged (0x488e00)
  virtual undefined OrphanLeaf_NoCall_Ins06_00489720(); // slot 0x31 0x489720
  // === END GENERATED DECLS (THandleStream) ===
  // clang-format on
  // Field semantics evidenced by AttachGlobalMemoryHandleAndResetPosition (0x489660):
  // +0x04 receives the HGLOBAL, +0x08 is zeroed (position), +0x0c receives
  // GlobalSize(handle), +0x10 receives the caller's mode word (ctor default 1).
  HGLOBAL attachedGlobalHandle; // +0x04
  int streamPosition;           // +0x08
  int attachedSizeBytes;        // +0x0c
  int modeFlags10;              // +0x10
  bool ownsHandleOrDirty;       // +0x14

  DECLARE_DYNCREATE(THandleStream)
  THandleStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  // Attach a global-memory handle: mode from the caller, position reset to 0,
  // size from GlobalSize. A null handle only resets position/mode. (0x489660)
  void AttachGlobalMemoryHandleAndResetPosition(HGLOBAL memoryHandle, int modeFlags);

  int streamSlot28() override;
  void streamSlot2c(int) override;
  int streamSlot30() override;
  void streamSlot34(int) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void WriteBytesSlot78(void* data, int length) override;
};

