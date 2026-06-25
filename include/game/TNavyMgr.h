#pragma once

#include "game/diplomacy_globals.h"

class TStream;

// TODO(manifest): describe TNavyMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNavyMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c4c8
class TNavyMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TNavyMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x556570
  virtual ~TNavyMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5568c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x556aa0
  virtual void Free() override; // slot 0x07 0x5567a0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TNavyMgr) ===
  void* orderListHead04;

  void RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot);

  TNavyMgr();
};

// GLOBAL: IMPERIALISM 0x006a43e4
extern TNavyMgr* g_pNavyOrderManager;

// === BEGIN GENERATED (TNavyMgr) — refreshed by `just gen-class TNavyMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c4c8 (10 slots), object size 0x10, base TObject
//   slot 0x00  byte 0x00  0x00556570  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005565c0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005568c0  override  WriteTo
//   slot 0x06  byte 0x18  0x00556aa0  override  ReadFrom
//   slot 0x07  byte 0x1c  0x005567a0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
// object size 0x10 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNavyMgr) ===
