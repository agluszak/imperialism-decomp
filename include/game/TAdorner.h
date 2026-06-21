#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TAdorner and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TAdorner -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064bdd0
class TAdorner : public TObject {
public:
// === BEGIN GENERATED DECLS (TAdorner) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x49d6d0
  virtual ~TAdorner(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x49d990
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x49d960
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d900() override; // slot 0x0a 0x49d900
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d930() override; // slot 0x0b 0x49d930
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9c0() override; // slot 0x0c 0x49d9c0
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9f0() override; // slot 0x0d 0x49d9f0
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da20() override; // slot 0x0e 0x49da20
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da50() override; // slot 0x0f 0x49da50
  virtual undefined WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da80() override; // slot 0x10 0x49da80
// === END GENERATED DECLS (TAdorner) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TAdorner 0xCTOR`).

  TAdorner();
};

// === BEGIN GENERATED (TAdorner) — refreshed by `just gen-class TAdorner`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064bdd0 (17 slots), object size 0x0c, base TObject
//   slot 0x00  byte 0x00  0x0049d6d0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0049dab0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x0049d990  override  WriteTo
//   slot 0x06  byte 0x18  0x0049d960  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004798b0  inherited Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0049d900  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d900
//   slot 0x0b  byte 0x2c  0x0049d930  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d930
//   slot 0x0c  byte 0x30  0x0049d9c0  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9c0
//   slot 0x0d  byte 0x34  0x0049d9f0  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049d9f0
//   slot 0x0e  byte 0x38  0x0049da20  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da20
//   slot 0x0f  byte 0x3c  0x0049da50  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da50
//   slot 0x10  byte 0x40  0x0049da80  override  WrapperFor_thunk_SetGlobalUiInvalidationFlagAndReturnPrevious_At0049da80
// object size 0x0c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAdorner) ===
