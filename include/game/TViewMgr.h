#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TToolBarClusterVtbl;

// TODO(manifest): describe TViewMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TViewMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066f120
class TViewMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TViewMgr) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5d5040
  virtual ~TViewMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5d5250
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5d5200
  virtual void Free() override; // slot 0x07 0x5d51e0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined LoadTurnEventCursorTable(); // slot 0x0a 0x5d5100
  virtual undefined HandleTurnEventVtableSlot2CInitializeHotKeyDialog(); // slot 0x0b 0x5dcaa0
  virtual undefined UpdatePaletteIndexFromTurnEventCode(undefined4 param_1); // slot 0x0c 0x5d5780
  virtual undefined ApplyTurnEventPaletteColorByEventCode(undefined4 param_1); // slot 0x0d 0x5d5750
  virtual undefined ClassifyTurnStateForOverlayMode(); // slot 0x0e 0x5d5960
  virtual undefined BuildAndShowTurnOverlayByMode(CString param_1, TToolBarClusterVtbl * * param_2); // slot 0x0f 0x5d6480
  virtual undefined HandleTurnEventVtableSlot40RefreshGoldDialog(); // slot 0x10 0x5d57b0
  virtual undefined ComputeTurnEventDialogPlacementByCode(); // slot 0x11 0x5d69b0
  virtual undefined RefreshMainViewNationIndicatorForCurrentTurnEvent(); // slot 0x12 0x5d6b70
// === END GENERATED DECLS (TViewMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TViewMgr 0xCTOR`).

  TViewMgr();
};

// === BEGIN GENERATED (TViewMgr) — refreshed by `just gen-class TViewMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066f120 (19 slots), object size 0xfc, base TObject
//   slot 0x00  byte 0x00  0x005d5040  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x005d50b0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005d5250  override  WriteTo
//   slot 0x06  byte 0x18  0x005d5200  override  ReadFrom
//   slot 0x07  byte 0x1c  0x005d51e0  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005d5100  override  LoadTurnEventCursorTable
//   slot 0x0b  byte 0x2c  0x005dcaa0  override  HandleTurnEventVtableSlot2CInitializeHotKeyDialog
//   slot 0x0c  byte 0x30  0x005d5780  override  UpdatePaletteIndexFromTurnEventCode
//   slot 0x0d  byte 0x34  0x005d5750  override  ApplyTurnEventPaletteColorByEventCode
//   slot 0x0e  byte 0x38  0x005d5960  override  ClassifyTurnStateForOverlayMode
//   slot 0x0f  byte 0x3c  0x005d6480  override  BuildAndShowTurnOverlayByMode
//   slot 0x10  byte 0x40  0x005d57b0  override  HandleTurnEventVtableSlot40RefreshGoldDialog
//   slot 0x11  byte 0x44  0x005d69b0  override  ComputeTurnEventDialogPlacementByCode
//   slot 0x12  byte 0x48  0x005d6b70  override  RefreshMainViewNationIndicatorForCurrentTurnEvent
// object size 0xfc (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TViewMgr) ===
