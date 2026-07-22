#pragma once

#include "game/TForeignMinister.h"

// VTABLE: IMPERIALISM 0x0065a188
class TArmsForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TArmsForeignMinister)
  TArmsForeignMinister();
  void MakeNewCity(TCity* city) override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659d70
class TTedForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTedForeignMinister)
  TTedForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659e30
class TBillForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TBillForeignMinister)
  TBillForeignMinister();
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;

  // Original object size is 0x84 (CRuntimeClass m_nObjectSize); the source class ended at 0x80. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field80;
};

// VTABLE: IMPERIALISM 0x00659f48
class TDiplomatForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TDiplomatForeignMinister)
  TDiplomatForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a008
class TTextileForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTextileForeignMinister)
  TTextileForeignMinister();
  void MakeNewCity(TCity* city) override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a0c8
class TTraderForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTraderForeignMinister)
  TTraderForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short targetNation) override;
};
