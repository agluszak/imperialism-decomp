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
  virtual undefined OrphanTiny_ReturnZero_00488ad0() override; // slot 0x0a 0x489180
  virtual undefined OrphanRetStub_00488e30() override; // slot 0x0b 0x4891c0
  virtual undefined OrphanTiny_ReturnZero_00488af0() override; // slot 0x0c 0x4891a0
  virtual undefined OrphanRetStub_00488e50() override; // slot 0x0d 0x4891f0
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
  virtual undefined Helper_Uses_EnsureSharedStringCapacityPreserveLength_At00488c50() override; // slot 0x1c 0x489360
  // slot 0x1d streamSlot74 inherited unchanged (0x488dd0)
  virtual undefined OrphanRetStub_00488e70() override; // slot 0x1e 0x489290
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
  virtual undefined OrphanCallChain_C2_I21_00489030() override; // slot 0x2b 0x489390
  virtual undefined OrphanLeaf_NoCall_Ins02_00489980() override; // slot 0x2c 0x489300
  virtual undefined OrphanRetStub_004899a0() override; // slot 0x2d 0x489330
  // slot 0x2e OrphanCallChain_C2_I18_00488ff0 inherited unchanged (0x488ff0)
  // slot 0x2f AssertMcAppStreamLine304 inherited unchanged (0x488b10)
  // slot 0x30 AssertMcAppStreamLine596 inherited unchanged (0x488e00)
// === END GENERATED DECLS (TFileStream) ===
  ArchiveStreamAdapter* backingArchiveOrStream;

  CRuntimeClass* GetRuntimeClass() const override;
  TFileStream();
  // Destructors are compiler-generated (implicit virtual dtor from TStream).

  void SetBackingArchive(ArchiveStreamAdapter* backingArchive);

  int streamSlot28() override;
  void streamSlot2c() override;
  int streamSlot30() override;
  void streamSlot34() override;
  void ReadBytes(void* buffer, int sizeBytes) override;
  void streamSlot70() override;
  void WriteBytesSlot78(void* data, int length) override;

  // 0x00489220 / 0x00489290: forward raw byte read/write to the backing
  // CArchive, asserting the backing pointer is non-null first.

  // 0x00489300 / 0x00489330: forward polymorphic object read/write to the
  // backing CArchive. The read form stores the resolved object through its
  // out-param and returns a success byte.
  char ReadObjectFromBackingArchive(void* outObject);
  void WriteObjectToBackingArchive(void* objectRef);

  // 0x00489070: serialize a length-prefixed C-string — write the length through
  // virtual slot 0x22, then the bytes through slot 0x1e.
  void WriteLengthPrefixedCString(char* text);
  void WriteCString(const CString& text);
};

// === BEGIN GENERATED (TFileStream) — refreshed by `just gen-class TFileStream`; do not hand-edit ===
// clang-format off
// vtable @ 0x00649230 (49 slots), object size 0x08, base TStream
//   slot 0x00  byte 0x00  0x004890f0  override  GetTStreamClassNamePointer
//   slot 0x01  byte 0x04  0x00489130  override  ConstructTStreamBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00485f70  inherited OrphanRetStub_0059ad90
//   slot 0x06  byte 0x18  0x00485f90  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x07  byte 0x1c  0x00488ab0  inherited OrphanCallChain_C1_I06_00488ab0
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x00489180  override  OrphanTiny_ReturnZero_00488ad0
//   slot 0x0b  byte 0x2c  0x004891c0  override  OrphanRetStub_00488e30
//   slot 0x0c  byte 0x30  0x004891a0  override  OrphanTiny_ReturnZero_00488af0
//   slot 0x0d  byte 0x34  0x004891f0  override  OrphanRetStub_00488e50
//   slot 0x0e  byte 0x38  0x00488a80  inherited OrphanCallChain_C2_I15_00488a80
//   slot 0x0f  byte 0x3c  0x00489220  override  OrphanRetStub_00488b40
//   slot 0x10  byte 0x40  0x00488b60  inherited OrphanCallChain_C1_I09_00488b60
//   slot 0x11  byte 0x44  0x00488b90  inherited OrphanCallChain_C1_I09_00488b90
//   slot 0x12  byte 0x48  0x00488bc0  inherited OrphanCallChain_C1_I08_00488bc0
//   slot 0x13  byte 0x4c  0x00488bf0  inherited OrphanCallChain_C1_I09_00488bf0
//   slot 0x14  byte 0x50  0x00488c20  inherited ReadDwordFromStreamViaVtableSlot3C
//   slot 0x15  byte 0x54  0x00488ce0  inherited OrphanCallChain_C1_I13_00488ce0
//   slot 0x16  byte 0x58  0x00488d20  inherited OrphanCallChain_C1_I06_00488d20
//   slot 0x17  byte 0x5c  0x00488d40  inherited OrphanCallChain_C1_I06_00488d40
//   slot 0x18  byte 0x60  0x00488d60  inherited OrphanCallChain_C1_I06_00488d60
//   slot 0x19  byte 0x64  0x00488d80  inherited OrphanCallChain_C1_I06_00488d80
//   slot 0x1a  byte 0x68  0x00488da0  inherited OrphanCallChain_C1_I09_00488da0
//   slot 0x1b  byte 0x6c  0x00488ca0  inherited OrphanCallChain_C2_I19_00488ca0
//   slot 0x1c  byte 0x70  0x00489360  override  WrapperFor_operator_At00489360
//   slot 0x1d  byte 0x74  0x00488dd0  inherited OrphanCallChain_C2_I17_00488dd0
//   slot 0x1e  byte 0x78  0x00489290  override  OrphanRetStub_00488e70
//   slot 0x1f  byte 0x7c  0x00488e90  inherited OrphanCallChain_C1_I06_00488e90
//   slot 0x20  byte 0x80  0x00488eb0  inherited OrphanCallChain_C1_I06_00488eb0
//   slot 0x21  byte 0x84  0x00488ed0  inherited OrphanCallChain_C1_I06_00488ed0
//   slot 0x22  byte 0x88  0x00488ef0  inherited OrphanCallChain_C1_I06_00488ef0
//   slot 0x23  byte 0x8c  0x00488f10  inherited WriteDwordToStreamViaVtableSlot78
//   slot 0x24  byte 0x90  0x00488f30  inherited OrphanCallChain_C1_I06_00488f30
//   slot 0x25  byte 0x94  0x00488f50  inherited OrphanCallChain_C1_I06_00488f50
//   slot 0x26  byte 0x98  0x00488f70  inherited OrphanCallChain_C1_I06_00488f70
//   slot 0x27  byte 0x9c  0x00488f90  inherited OrphanCallChain_C1_I06_00488f90
//   slot 0x28  byte 0xa0  0x00488fb0  inherited OrphanCallChain_C1_I06_00488fb0
//   slot 0x29  byte 0xa4  0x00488fd0  inherited OrphanCallChain_C1_I06_00488fd0
//   slot 0x2a  byte 0xa8  0x00489070  inherited CreateTFileStreamInstance
//   slot 0x2b  byte 0xac  0x00489390  override  OrphanCallChain_C2_I21_00489030
//   slot 0x2c  byte 0xb0  0x00489300  override  OrphanLeaf_NoCall_Ins02_00489980
//   slot 0x2d  byte 0xb4  0x00489330  override  OrphanRetStub_004899a0
//   slot 0x2e  byte 0xb8  0x00488ff0  inherited OrphanCallChain_C2_I18_00488ff0
//   slot 0x2f  byte 0xbc  0x00488b10  inherited AssertMcAppStreamLine304
//   slot 0x30  byte 0xc0  0x00488e00  inherited AssertMcAppStreamLine596
// object size 0x08 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TFileStream) ===
