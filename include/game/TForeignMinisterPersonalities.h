#pragma once

#include "game/TForeignMinister.h"

// VTABLE: IMPERIALISM 0x0065a188
class TArmsForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TArmsForeignMinister)
  TArmsForeignMinister();
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659d70
class TTedForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTedForeignMinister)
  TTedForeignMinister();
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659e30
class TBillForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TBillForeignMinister)
  TBillForeignMinister();
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659f48
class TDiplomatForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TDiplomatForeignMinister)
  TDiplomatForeignMinister();
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a008
class TTextileForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTextileForeignMinister)
  TTextileForeignMinister();
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a0c8
class TTraderForeignMinister : public TForeignMinister {
public:
  DECLARE_DYNCREATE(TTraderForeignMinister)
  TTraderForeignMinister();
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};
