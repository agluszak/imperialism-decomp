#pragma once

#include "game/mfc.h"
#include "TStream.h"
#include "game/ArchiveStreamAdapter.h"
#include "compat.h"
#include "decomp_types.h"

class CString;

// VTABLE: IMPERIALISM 0x00649230
class TFileStream : public TStream {
public:
  // clang-format off
  // === BEGIN GENERATED DECLS (TFileStream) — refreshed by recover-class; do not hand-edit ===
  virtual ~TFileStream(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x488ab0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a streamSlot28 owned by the hand declaration below (0x489180)
  // slot 0x0b streamSlot2c owned by the hand declaration below (0x4891c0)
  // slot 0x0c streamSlot30 owned by the hand declaration below (0x4891a0)
  // slot 0x0d streamSlot34 owned by the hand declaration below (0x4891f0)
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
  // slot 0x1c streamSlot70 owned by the hand declaration below (0x489360)
  // slot 0x1d streamSlot74 inherited unchanged (0x488dd0)
  // slot 0x1e WriteBytesSlot78 owned by the hand declaration below (0x489290)
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
  // slot 0x2a WriteLengthPrefixedCString inherited unchanged (0x489070)
  virtual void streamSlotAc(CString* sharedString) override;       // slot 0x2b 0x489390
  virtual char ReadByte(void* outByte) override;                   // slot 0x2c 0x489300
  virtual void WriteObjectSlotB4(void* object, int flag) override; // slot 0x2d 0x489330
  // slot 0x2e OrphanCallChain_C2_I18_00488ff0 inherited unchanged (0x488ff0)
  // slot 0x2f AssertMcAppStreamLine304 inherited unchanged (0x488b10)
  // slot 0x30 AssertMcAppStreamLine596 inherited unchanged (0x488e00)
  // === END GENERATED DECLS (TFileStream) ===
  // clang-format on
  ArchiveStreamAdapter* backingArchiveOrStream;

  DECLARE_DYNCREATE(TFileStream)
  TFileStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  void SetBackingArchive(ArchiveStreamAdapter* backingArchive);

  int streamSlot28() override;
  void streamSlot2c(int) override;
  int streamSlot30() override;
  void streamSlot34(int) override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void streamSlot70(CString* dest, int maxLen) override;
  void WriteBytesSlot78(void* data, int length) override;

  // 0x00489220 / 0x00489290: forward raw byte read/write to the backing
  // CArchive, asserting the backing pointer is non-null first.

  // 0x00489300 / 0x00489330: forward polymorphic object read/write to the
  // backing CArchive. The read form stores the resolved object through its
  // out-param and returns a success byte.
};

