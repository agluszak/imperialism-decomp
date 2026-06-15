#pragma once

#include "decomp_types.h"

#include "CObject.h"
#include "game/TIndexAndRankList.h"

class TStream;

// Minister base — fork-class construction (ConstructTMinister writes skillIndexC + vptr only).
// Vtable has 44 slots (indices 0x00–0x2b); slots 2–4 are turn-event fork thunks, not
// CObject::Serialize/AssertValid/Dump.
// VTABLE: IMPERIALISM 0x00659c00
class TMinister : public CObject {
public:
  TMinister();
  void InitializeBaseOrderArray(undefined4 ownerContext);

  virtual CRuntimeClass* GetRuntimeClass() override; // 0
  // slot 1 — scalar deleting destructor @ 0x0052eba0 (SYNTHETIC)
  virtual void Serialize(CArchive* ar) override;                         // 2 (0x08) turn-event fork
  virtual void AssertValidOrSlot0c() override;                           // 3 (0x0c)
  virtual void DumpOrSlot10(int unused = 0) override;                    // 4 (0x10)
  virtual void SerializeTMinisterBaseOrderArrayHeader(TStream* archive); // 5 (0x14)
  virtual void Call18(int arg1 = 0);         // 6 (0x18) DeserializeTMinisterBaseOrderArrayHeader
  virtual void Call1C();                     // 7 (0x1c) DeleteForeignMinisterAndReleaseOrderArray
  virtual void InvokeObjectSlot20();         // 8 (0x20)
  virtual void CopyPayloadSlot24();          // 9 (0x24)
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
