#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/TIndexAndRankList.h"

class TStream;

#include "game/TObject.h"

// Minister base — fork-class construction (ConstructTMinister writes skillIndexC + vptr only).
// VTABLE: IMPERIALISM 0x00659c00
class TMinister : public TObject {
public:
  TMinister();
  void InitializeBaseOrderArray(undefined4 ownerContext);

  virtual CRuntimeClass* GetRuntimeClass() const override; // 0
  // slot 1 — scalar deleting destructor @ 0x0052eba0 (SYNTHETIC)
  void WriteTo(TStream* stream) override;                     // 5 (0x14)
  void ReadFrom(TStream* stream) override;                     // 6 (0x18)
  void SerializeTMinisterBaseOrderArrayHeader(TStream* archive);         // non-virtual helper
  void Call18(int arg1 = 0);                                             // non-virtual helper
  void Free() override; // 7 (0x1c) DeleteForeignMinisterAndReleaseOrderArray
  void Call1C();                                                         // non-virtual helper
  virtual void MinisterSlot0A();             // 10 (0x28)
  virtual void MinisterSlot0B();             // 11 (0x2c)
  virtual void MinisterSlot0C();             // 12 (0x30)
  virtual void MinisterSlot0D();             // 13 (0x34)
  virtual void MinisterSlot0E();             // 14 (0x38)
  virtual void MinisterSlot0F();             // 15 (0x3c)
  virtual void MinisterSlot10();             // 16 (0x40)
  virtual void NotifySlot44(void* receiver); // 17 (0x44)
  virtual void MinisterSlot12();             // 18 (0x48)
  virtual void Call4C();                     // 19 (0x4c)
  virtual void MinisterSlot14();             // 20 (0x50)
  virtual void Call54();                     // 21 (0x54)
  // The orig TMinister vtable (0x659c00) ends at slot 21 (0x54); slots 0x18-0x54 are
  // NULL/abstract in the base and the next object's vtable begins at 0x659c58. Virtuals
  // beyond slot 21 are introduced per-derived-class (e.g. TForeignMinister slots 22-39,
  // TCityInteriorMinister slots 22-53), not on this base. See worklog 2026-06-15.

  int ownerContextAt04;       // +0x4 — great-power back-pointer from InitializeBaseOrderArray
  TIndexAndRankList* field_8; // +0x8 — minister order array (vtable 0x659c58)
  short skillIndexC;          // +0xC
  unsigned char pad0e[0x24 - 0x0E];
  short capabilityFlag24;
  short capabilityFlag26;
  short capabilityFlag28;
};
