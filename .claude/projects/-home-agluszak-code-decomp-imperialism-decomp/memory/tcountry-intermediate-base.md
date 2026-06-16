---
name: tcountry-intermediate-base
description: TCountry is the real extracted intermediate base of TGreatPower (TObject -> TCountry -> TGreatPower); ctor must stay inline
metadata:
  type: project
---

**TCountry** is the intermediate base between TObject and TGreatPower, now extracted
as a real C++ class (2026-06-16): `class TCountry : public TObject` in
`include/game/TCountry.h` + `src/game/TCountry.cpp`, and `TGreatPower : public TCountry`.
TCountry owns fields 0x4..0x90 (identity CStrings, nation-slot metrics,
needLevelByNation, militaryUnitList44, unitNameOrdinalByType, ownedRegionList) and the
TObject stream-lifecycle overrides: WriteTo **0x4d6e60**, ReadFrom **0x4d6bf0**, Free
**0x4d6ba0** (Free = 100%). TGreatPower::WriteTo/ReadFrom call `TCountry::WriteTo/ReadFrom`
directly. Vtable 0x00653868 (52-slot prefix of TGreatPower 0x00653938) is intentionally
**not** annotated — only the 3 stream virtuals are modeled; slots 0x0a..0x29 stay declared
on TGreatPower so TGreatPower's vtable stays matching.

**Critical: `TCountry::TCountry()` MUST stay defined inline in the header** (`TCountry() {}`).
The real TGreatPower ctor (0x4d89f0) *inlines* the base construction (inline CString
ctors + EH frame, sets RefCountedObjectBase vtable then TGreatPower vtable). An
out-of-line TCountry ctor makes MSVC emit a `call TCountry::TCountry` and drops the EH
frame -> TGreatPower ctor crashes from ~46% to ~19%. Inline keeps it ~45%. Consequence:
standalone 0x4d67d0 is no longer emitted/owned (acceptable).

Remaining: WriteTo 0x4d6e60 = 34% and ReadFrom 0x4d6bf0/0x4d92e0 ~18% are
register-alloc/body matching, not structural. See [[next-tgreatpower-vtable-scope]].
