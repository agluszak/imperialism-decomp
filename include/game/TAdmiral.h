#pragma once

#include "decomp_types.h"
#include "game/CObject.h"
#include "game/CString.h"
#include "game/TMinor.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Navy task-force secondary order node (the slot-0x32 "navy" branch). new(0x1c) + the
// EH ctor 0x00551430 links the node at the head of the global g_pNavySecondaryOrderListHead
// doubly-linked list, then (for a real terrain-type index) generates a display name from
// g_apTerrainTypeDescriptorTable[type] and removes earlier list entries with the same name.
// EH-framed because the CString member at +0xc has a non-trivial dtor. Standalone polymorphic
// class — does NOT derive from RefCountedObjectBase (the transient 0x6485c0 write in the
// original ctor is MSVC EH sentinel glue, not list-wrapper inheritance).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public CObject {
public:
  virtual CRuntimeClass* GetRuntimeClass() override;
  virtual void VMethod05() {}
  virtual void DeserializeNavyOrderSelectionStateFromStream() {}
  virtual void DestroyAndUnlinkNavySecondaryOrderNode();

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
