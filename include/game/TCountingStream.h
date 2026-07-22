#pragma once

#include "TStream.h"
#include "compat.h"
#include "decomp_types.h"

// VTABLE: IMPERIALISM 0x649320
class TCountingStream : public TStream {
public:
  // clang-format off
  virtual ~TCountingStream() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x488ab0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slots 0x0a..0x0d: position/length accessors below
  // slot 0x0e OrphanCallChain_C2_I15_00488a80 inherited unchanged (0x488a80)
  // slot 0x0f ReadBytes inherited unchanged (0x488b40)
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
  // slot 0x1d SkipPaddingToEvenByteBoundary inherited unchanged (0x488dd0)
  // slot 0x1e WriteBytesSlot78 owned by the hand declaration below (0x489550)
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
  // slot 0x2e WritePaddingToEvenByteBoundary inherited unchanged (0x488ff0)
  // slot 0x2f AssertMcAppStreamLine304 inherited unchanged (0x488b10)
  // slot 0x30 AssertMcAppStreamLine596 inherited unchanged (0x488e00)
  // clang-format on
  int positionOrByteCount;
  int maxExtentOrLimit;

  DECLARE_DYNCREATE(TCountingStream)
  TCountingStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  int GetPosition() override;
  // NOOP: verified empty in original 0x00489490 (single ret; the packet dispatcher
  // calls it right after construction before measuring).
  void PrepareForUse();
  void SetPosition(int position) override;
  int GetLength() override;
  void SetLength(int length) override;
  // ReadBytes (slot 0x3c) is inherited unchanged from TStream.
  void WriteBytesSlot78(void* data, int length) override;
};
