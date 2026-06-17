#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/CString.h"
#include "game/TMinor.h"
#include "game/TObject.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Navy task-force secondary order node (vtable 0x0065c498, eight slots).
// VTABLE: IMPERIALISM 0x0065c498
class TAdmiral : public TObject {
public:
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
