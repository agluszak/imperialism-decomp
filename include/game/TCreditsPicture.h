#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642d58
class TCreditsPicture : public TPicture {
public:
  virtual CRuntimeClass* GetRuntimeClass() const override;
  virtual ~TCreditsPicture();

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual undefined OrphanRetStub_0043d9f0() override;

  TCreditsPicture();
};

// === BEGIN GENERATED (TCreditsPicture) — refreshed by `just gen-class TCreditsPicture`; do not hand-edit ===
// clang-format off
// vtable @ 0x00642d58 (116 slots), object size 0x90, base TPicture
//   slot 0x00  byte 0x00  0x0056ee30  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x0043dad0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0048b0b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x08  byte 0x20  0x0048f640  inherited GetTBehaviorClassNamePointer
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0048a240  inherited GetTEventHandlerClassNamePointer
//   slot 0x0b  byte 0x2c  0x0048a260  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x0c  byte 0x30  0x0048a2c0  inherited UpdateControlCachedIntFromWindowText
//   slot 0x0d  byte 0x34  0x0048a3b0  inherited OrphanRetStub_0059add0
//   slot 0x0e  byte 0x38  0x0048a3f0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0f  byte 0x3c  0x0056efc0  override  ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x37  byte 0xdc  0x0056ee50  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x44  byte 0x110  0x0056f190  override  OrphanTiny_ReturnZero_0048a730
//   slot 0x73  byte 0x1cc  0x0043d9f0  override  OrphanRetStub_0043d9f0
// clang-format on
// === END GENERATED (TCreditsPicture) ===
