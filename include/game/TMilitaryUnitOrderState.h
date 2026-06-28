#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/TUnit.h"
#include "game/global_data_tables.h"

extern "C" char g_szEmptyString[];
undefined4 thunk_GenerateMappedFlavorTextByNationSlotField0C(void);

// Military land-unit recruit order (ctor 0x005c2df0, size 0x44). EH-framed: installs
// base vtable 0x0066ee18 (via the inlined TUnit base ctor) then the derived
// vtable 0x0066eea8, with a real CString member at +0x24 (default-constructed, then
// assigned the empty string). The non-trivial ~CString on the member is what makes
// MSVC emit the EH unwind frame + uStack partial-construction state markers.
// VTABLE: IMPERIALISM 0x0066eea8
class TMilitaryUnitOrderState : public TUnit {
public:
  CString name24;            // 0x24
  unsigned char pad28[0x0C]; // 0x28..0x33 (set later by the recruit initializer)
  short field_34;            // 0x34 (init 0x1f4)
  short field_36;            // 0x36
  short field_38;            // 0x38
  short field_3A;            // 0x3a
  short field_3C;            // 0x3c
  short pad3E;               // 0x3e
  int field_40;              // 0x40

  TMilitaryUnitOrderState();
  ~TMilitaryUnitOrderState() override;

  void InitializeRecruitOrderState(short capValue, int nodeContext, short nationSlot);

  // --- TObject/TUnit overrides ---
  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void VTableSlot10(int pOwnerContext) override;
  void DetachUnitOrderFromOwnerAndReset() override;

  // --- TMilitaryUnitOrderState virtual functions ---
  virtual void CopyUnitCurrentTileIntoOrderTargets();
};
