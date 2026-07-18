#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/TMinor.h"
#include "game/TObject.h"

class TShip;

// Navy task-force secondary order node (vtable 0x0065c498, eight slots).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public TObject {
public:
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  DECLARE_DYNCREATE(TAdmiral)                      // GetRuntimeClass slot 0x00 0x551410
  virtual void WriteTo(TStream* stream) override;  // 0x14 0x551670
  virtual void ReadFrom(TStream* stream) override; // 0x18 0x551700
  virtual void Free() override;                    // 0x1c 0x5515d0

  short terrainType;         // 0x04 (index into g_apTerrainTypeDescriptorTable; 0xffff = none)
  unsigned char pad06[2];    // 0x06
  TShip* primaryOrderNode08; // 0x08 — linked navy primary-order node (0x00552250)
  CString displayName;       // 0x0c
  short field_10;            // 0x10
  unsigned char pad12[2];    // 0x12
  TAdmiral* next;            // 0x14 (toward older entries)
  TAdmiral* prev;            // 0x18 (toward newer entries)

  TAdmiral(short terrainTypeIndex = static_cast<short>(0xffff));
  virtual ~TAdmiral() override;

  void SetTaskForcePrimaryOrderLinkAndRefreshChildBacklinks(TShip* primaryOrderNode);
  // 0x00551850 -- drops the current primary-order link, rescans the global navy
  // primary-order list for this admiral's nation and links the preferred node
  // (folding SelectPreferredMapOrderEntryByPriorityRules over matching nodes);
  // Free()s this admiral when no node qualifies.
  void SelectNavyPrimaryOrderByNationAndRecomputePreferredChild();

  static void __fastcall GenerateMappedFlavorTextByNationSlotField0C(TMinor* terrainDescriptor,
                                                                     CString* dest);

  void RemoveDuplicateNavySecondaryOrdersByDisplayName();
};
