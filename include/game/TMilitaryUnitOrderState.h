#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/TUnitOrderState.h"
#include "game/diplomacy_globals.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
extern "C" char g_szEmptyString[];
undefined4 thunk_GenerateMappedFlavorTextByNationSlotField0C(void);

// Military land-unit recruit order (ctor 0x005c2df0, size 0x44). EH-framed: installs
// base vtable 0x0066ee18 (via the inlined TUnitOrderState base ctor) then the derived
// vtable 0x0066eea8, with a real CString member at +0x24 (default-constructed, then
// assigned the empty string). The non-trivial ~CString on the member is what makes
// MSVC emit the EH unwind frame + uStack partial-construction state markers.
// VTABLE: IMPERIALISM 0x0066eea8
class TMilitaryUnitOrderState : public TUnitOrderState {
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

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void* operator new(unsigned int size, void* ptr) {
    (void)size;
    return ptr;
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  // --- TObject/TUnitOrderState overrides ---
  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void VTableSlot10(int pOwnerContext) override;
  void DetachUnitOrderFromOwnerAndReset() override;

  // --- TMilitaryUnitOrderState virtual functions ---
  virtual void CopyUnitCurrentTileIntoOrderTargets();
};
