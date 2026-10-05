#pragma once

#include "compat.h"

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/map/TIndexAndRankList.h"

class TStream;
class TGreatPower;
class TCity;

#include "game/app/TObject.h"

// Minister base — fork-class construction (ConstructTMinister writes skillIndex + vptr only).
// VTABLE: IMPERIALISM 0x00659c00
class TMinister : public TObject {
public:
  TMinister();
  void IMinister(TGreatPower* ownerContext);
  // FUNCTION: IMPERIALISM 0x0052ebd0
  virtual ~TMinister() override {} // slot 1

  DECLARE_DYNCREATE(TMinister)
  // slot 1 — scalar deleting destructor @ 0x0052eba0 (SYNTHETIC)
  void WriteTo(TStream* stream) override;  // 5 (0x14)
  void ReadFrom(TStream* stream) override; // 6 (0x18)
  void Free() override;                    // 7 (0x1c)
  virtual short GetRankingCriterionForGP(short nationSlot); // 10 (0x28)
  virtual void FigureOutRanking();                          // 11 (0x2c)
  virtual short GetRankOf(short nationSlot);                // 12 (0x30)
  virtual short GetCountryInRank(short rank);               // 13 (0x34)
  virtual short GetCountryAt(short index);                  // 14 (0x38)
  virtual short GetRankOfCountryAt(short index);            // 15 (0x3c)
  virtual short GetInfoOfCountryAt(short index);            // 16 (0x40)
  virtual void MakeNewCity(TCity* city); // 17 (0x44)
  // Orig TMinister vtable (0x659c00) ends at slot 17 (0x44); slots 0x48-0x54 are NULL.
  // Slots 0x48+ are introduced per derived minister (e.g. TDefenseMinister, TInteriorMinister).

  TGreatPower* greatPower;    // +0x4
  TIndexAndRankList* ranking; // +0x8 — great powers ranked by GetRankingCriterionForGP
  short skillIndex;           // +0xC
  unsigned char pad0e[0x10 - 0x0E];
};
ASSERT_SIZE(TMinister, 0x10);
