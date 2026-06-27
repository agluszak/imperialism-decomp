#pragma once

#include "game/TFileBasedDocument.h"
#include "game/mfc.h"

// TODO(manifest): describe TAmbitFileBasedDocument and its role. Base edge (TFileBasedDocument) recovered from RTTI CRuntimeClass chain: TAmbitFileBasedDocument -> TFileBasedDocument -> TDocument -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c170
class TAmbitFileBasedDocument : public TFileBasedDocument {
public:
// === BEGIN GENERATED DECLS (TAmbitFileBasedDocument) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TAmbitFileBasedDocument)
  virtual ~TAmbitFileBasedDocument(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanRetStub_00486530() override; // slot 0x0a 0x49e6a0
  virtual undefined OrphanRetStub_00486550() override; // slot 0x0b 0x49eb30
  virtual undefined OrphanRetStub_0049e660(); // slot 0x0c 0x49e660
  virtual undefined OrphanRetStub_0049e680(); // slot 0x0d 0x49e680
  virtual undefined AssertUAmbitLine1335(); // slot 0x0e 0x49ee70
// === END GENERATED DECLS (TAmbitFileBasedDocument) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TAmbitFileBasedDocument 0xCTOR`).

  TAmbitFileBasedDocument();
};

// === BEGIN GENERATED (TAmbitFileBasedDocument) — refreshed by `just gen-class TAmbitFileBasedDocument`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c170 (15 slots), object size 0x04, base TFileBasedDocument
//   slot 0x00  byte 0x00  0x0049e5d0  override  GetTDocumentClassNamePointer
//   slot 0x01  byte 0x04  0x0049e610  override  ConstructTDocumentBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0049e6a0  override  OrphanRetStub_00486530
//   slot 0x0b  byte 0x2c  0x0049eb30  override  OrphanRetStub_00486550
//   slot 0x0c  byte 0x30  0x0049e660  override  OrphanRetStub_0049e660
//   slot 0x0d  byte 0x34  0x0049e680  override  OrphanRetStub_0049e680
//   slot 0x0e  byte 0x38  0x0049ee70  override  AssertUAmbitLine1335
// object size 0x04 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAmbitFileBasedDocument) ===
