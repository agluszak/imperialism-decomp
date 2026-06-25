#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/TMinor.h"
#include "game/TObject.h"


// Navy task-force secondary order node (vtable 0x0065c498, eight slots).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public TObject {
public:
// === BEGIN GENERATED DECLS (TAdmiral) — refreshed by recover-class; do not hand-edit ===
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TAdmiral) ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // 0x00 0x551410
  virtual void WriteTo(TStream* stream) override;          // 0x14 0x551670
  virtual void ReadFrom(TStream* stream) override;         // 0x18 0x551700
  virtual void Free() override;                            // 0x1c 0x5515d0

  short terrainType;      // 0x04 (index into g_apTerrainTypeDescriptorTable; 0xffff = none)
  unsigned char pad06[2]; // 0x06
  int field_8;            // 0x08 — linked navy primary-order node (0x00552250)
  CString displayName;    // 0x0c
  short field_10;         // 0x10
  unsigned char pad12[2]; // 0x12
  TAdmiral* next;         // 0x14 (toward older entries)
  TAdmiral* prev;         // 0x18 (toward newer entries)

  TAdmiral(short terrainTypeIndex);
  virtual ~TAdmiral() override;

  void SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(void* primaryOrderNode);

  static void __fastcall GenerateMappedFlavorTextByNationSlotField0C(TMinor* terrainDescriptor,
                                                                     CString* dest);

  void RemoveDuplicateNavySecondaryOrdersByDisplayName();
};

// === BEGIN GENERATED (TAdmiral) — refreshed by `just gen-class TAdmiral`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c498 (10 slots), object size 0x1c, base TObject
//   slot 0x00  byte 0x00  0x00551410  new       HandleCityDialogHintClusterUpdate
//   slot 0x01  byte 0x04  0x00551550  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x00551670  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x06  byte 0x18  0x00551700  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x07  byte 0x1c  0x005515d0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
// object size 0x1c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAdmiral) ===
