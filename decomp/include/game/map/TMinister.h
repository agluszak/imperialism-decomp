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
  virtual ~TMinister() override {}

  DECLARE_DYNCREATE(TMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
  virtual short GetRankingCriterionForGP(short nationSlot);
  virtual void FigureOutRanking();
  virtual short GetRankOf(short nationSlot);
  virtual short GetCountryInRank(short rank);
  virtual short GetCountryAt(short index);
  virtual short GetRankOfCountryAt(short index);
  virtual short GetInfoOfCountryAt(short index);
  virtual void MakeNewCity(TCity* city);
  // LAYOUT: TMinister's own vtable ends at slot 17; later slots belong to derived ministers.

  TGreatPower* greatPower;
  TIndexAndRankList* ranking; // great powers ranked by GetRankingCriterionForGP
  short skillIndex;
  unsigned char pad0e[0x10 - 0x0E];
};
ASSERT_SIZE(TMinister, 0x10);
