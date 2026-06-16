#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/TObject.h"
#include "game/TPtrList.h"

class TStream;

// Intermediate base between TObject and TGreatPower (Ghidra: TCountry). Owns the nation
// identity strings, the nation-slot metrics, the military-unit list and the owned-region
// list, and serializes that sub-object via WriteTo (0x004d6e60) / ReadFrom (0x004d6bf0).
// Its own vtable (0x00653868) is a 52-slot prefix of TGreatPower's 0x00653938; only the
// TObject stream-lifecycle overrides are modeled here, so the vtable is intentionally
// left unannotated (the 0x0a..0x29 nation virtuals are still declared on TGreatPower).
class TCountry : public TObject {
public:
  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d6e60
  void ReadFrom(TStream* stream) override; // body 0x004d6bf0
  void Free() override;                    // body 0x004d6ba0

  CString identitySharedString0;
  CString identitySharedString1;
  short nationSlot;
  short encodedNationSlot;
  int treasuryValue10;
  short needLevelByNation[0x17];
  short field42;
  // 0x44 — military unit list; entries carry a unit-type short at +4 indexing
  // g_Classify_Nation_Military_LookupTable_00695CD4 power weights.
  TPtrList* militaryUnitList44;
  // 0x48 — per-unit-type counter of names already issued (slot 0x0f increments the
  // type's entry after assigning "<ordinal> <type name>").
  short unitNameOrdinalByType[0x1e];
  short unitNameCounter84; // 0x84 — monotonically increasing name tag (stored at +0x1a)
  short pad_86;
  short ownerNationSlot;
  short pad_8a;
  // 0x8c — serialized as a 4-byte block by slots 0x0a/0x0b together with the
  // 4 bytes at 0x88 (ownerNationSlot + pad).
  int serializedField8c;
  TPtrList* ownedRegionList;

  // Defined inline so MSVC inlines the two CString-member constructions (and the
  // resulting EH frame) into derived ctors, matching the original TGreatPower ctor
  // which inlines the TCountry base construction rather than calling 0x004d67d0.
  TCountry() {}
};

ASSERT_SIZE(TCountry, 0x94);
