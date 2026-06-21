#pragma once

#include "game/TList.h"
#include "game/mfc.h"

// TODO(manifest): describe TTaskList and its role. Base edge (TList) recovered from RTTI CRuntimeClass chain: TTaskList -> TList -> TSortedList -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066aa48
class TTaskList : public TList {
public:
// === BEGIN GENERATED DECLS (TTaskList) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5aeb70
  virtual ~TTaskList(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x488820)
  // slot 0x06 ReadFrom inherited unchanged (0x488800)
  // slot 0x07 Free inherited unchanged (0x488790)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a GetCountOrReleaseSlot28 inherited unchanged (0x4885d0)
  // slot 0x0b GetNodeByOrdinalSlot2C inherited unchanged (0x4885f0)
  // slot 0x0c AddTail30 inherited unchanged (0x488610)
  // slot 0x0d GetTEventHandlerClassNamePointer inherited unchanged (0x488630)
  // slot 0x0e ApplyProductionDistributionToCitySlots inherited unchanged (0x488650)
  // slot 0x0f QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x488670)
  // slot 0x10 GetTTaskClassNamePointer inherited unchanged (0x488690)
  // slot 0x11 ConstructTTaskBaseState inherited unchanged (0x4886b0)
  // slot 0x12 GetCountSlot48 inherited unchanged (0x4886d0)
  // slot 0x13 GetTrackedEntrySlot4C inherited unchanged (0x4886f0)
  // slot 0x14 RemoveEntryAtSlot50 inherited unchanged (0x488720)
  // slot 0x15 Call54 inherited unchanged (0x488750)
  // slot 0x16 Call58 inherited unchanged (0x4887b0)
  // slot 0x17 OrphanRetStub_0059add0 inherited unchanged (0x4887e0)
  // slot 0x18 SetEntryDataAtSlot60 inherited unchanged (0x488840)
  // slot 0x19 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x487d90)
  // slot 0x1a OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x487dd0)
  // slot 0x1b ConstructTSortedListBaseState inherited unchanged (0x487b30)
  // slot 0x1c VTableSlot1C inherited unchanged (0x487b60)
  // slot 0x1d QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x487bd0)
  // slot 0x1e GetTTaskClassNamePointer inherited unchanged (0x487cc0)
  virtual undefined CreateTTechMgrInstance() override; // slot 0x1f 0x5aed50
// === END GENERATED DECLS (TTaskList) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTaskList 0xCTOR`).

  TTaskList();
};

// === BEGIN GENERATED (TTaskList) — refreshed by `just gen-class TTaskList`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066aa48 (32 slots), object size 0x20, base TList
//   slot 0x00  byte 0x00  0x005aeb70  override  OnActivateView
//   slot 0x01  byte 0x04  0x005aec00  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00488820  inherited QueueCityOrderType10CommandIfReady
//   slot 0x06  byte 0x18  0x00488800  inherited ApplyProductionDistributionToCitySlots
//   slot 0x07  byte 0x1c  0x00488790  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004885d0  inherited InvalidateWindowRectFromHandleField1C
//   slot 0x0b  byte 0x2c  0x004885f0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0c  byte 0x30  0x00488610  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0d  byte 0x34  0x00488630  inherited GetTEventHandlerClassNamePointer
//   slot 0x0e  byte 0x38  0x00488650  inherited ApplyProductionDistributionToCitySlots
//   slot 0x0f  byte 0x3c  0x00488670  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x10  byte 0x40  0x00488690  inherited GetTTaskClassNamePointer
//   slot 0x11  byte 0x44  0x004886b0  inherited ConstructTTaskBaseState
//   slot 0x12  byte 0x48  0x004886d0  inherited OrphanLeaf_NoCall_Ins04_005adc30
//   slot 0x13  byte 0x4c  0x004886f0  inherited QueueCityOrderType10CommandIfReady
//   slot 0x14  byte 0x50  0x00488720  inherited ApplyProductionDistributionToCitySlots
//   slot 0x15  byte 0x54  0x00488750  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x16  byte 0x58  0x004887b0  inherited DeserializeCityProductionQueueCommand
//   slot 0x17  byte 0x5c  0x004887e0  inherited OrphanRetStub_0059add0
//   slot 0x18  byte 0x60  0x00488840  inherited InvalidateWindowRectFromHandleField1C
//   slot 0x19  byte 0x64  0x00487d90  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x1a  byte 0x68  0x00487dd0  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x1b  byte 0x6c  0x00487b30  inherited GetTEventHandlerClassNamePointer
//   slot 0x1c  byte 0x70  0x00487b60  inherited ApplyProductionDistributionToCitySlots
//   slot 0x1d  byte 0x74  0x00487bd0  inherited QueueCityRecruitmentSupportCommandsIfDeficit
//   slot 0x1e  byte 0x78  0x00487cc0  inherited GetTTaskClassNamePointer
//   slot 0x1f  byte 0x7c  0x005aed50  override  ConstructTTaskBaseState
// object size 0x20 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TTaskList) ===
