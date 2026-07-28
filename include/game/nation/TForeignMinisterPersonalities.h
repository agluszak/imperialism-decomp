#pragma once

#include "compat.h"

#include "game/nation/TForeignMinister.h"

// VTABLE: IMPERIALISM 0x0065a188
class TArmsForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x005340b0
  ~TArmsForeignMinister() override {}
  DECLARE_DYNCREATE(TArmsForeignMinister)
  TArmsForeignMinister();
  void MakeNewCity(TCity* city) override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;
};
ASSERT_SIZE(TArmsForeignMinister, 0x80);

// VTABLE: IMPERIALISM 0x00659d70
class TTedForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x00531270
  ~TTedForeignMinister() override {}
  DECLARE_DYNCREATE(TTedForeignMinister)
  TTedForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;
};
ASSERT_SIZE(TTedForeignMinister, 0x80);

// VTABLE: IMPERIALISM 0x00659e30
class TBillForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x00531c80
  ~TBillForeignMinister() override {}
  DECLARE_DYNCREATE(TBillForeignMinister)
  TBillForeignMinister();
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;

  unsigned char orderFlag80;
  unsigned char pad81[3];
};

ASSERT_SIZE(TBillForeignMinister, 0x84);

// VTABLE: IMPERIALISM 0x00659f48
class TDiplomatForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x00532820
  ~TDiplomatForeignMinister() override {}
  DECLARE_DYNCREATE(TDiplomatForeignMinister)
  TDiplomatForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void DoSecondTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;
};
ASSERT_SIZE(TDiplomatForeignMinister, 0x80);

// VTABLE: IMPERIALISM 0x0065a008
class TTextileForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x005331b0
  ~TTextileForeignMinister() override {}
  DECLARE_DYNCREATE(TTextileForeignMinister)
  TTextileForeignMinister();
  void MakeNewCity(TCity* city) override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;
};
ASSERT_SIZE(TTextileForeignMinister, 0x80);

// VTABLE: IMPERIALISM 0x0065a0c8
class TTraderForeignMinister : public TForeignMinister {
public:
  // FUNCTION: IMPERIALISM 0x00533940
  ~TTraderForeignMinister() override {}
  DECLARE_DYNCREATE(TTraderForeignMinister)
  TTraderForeignMinister();
  void MakeNewCity(TCity* city) override;
  void DoFirstTurnDiplomacy() override;
  void SetBuyPriorities() override;
  void SetTradeBids() override;
  void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) override;
};
ASSERT_SIZE(TTraderForeignMinister, 0x80);
