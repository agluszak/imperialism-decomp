#pragma once

#include "game/TForeignMinister.h"

// VTABLE: IMPERIALISM 0x0065a188
class TArmsForeignMinister : public TForeignMinister {
public:
  TArmsForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659d70
class TTedForeignMinister : public TForeignMinister {
public:
  TTedForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659e30
class TBillForeignMinister : public TForeignMinister {
public:
  TBillForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x00659f48
class TDiplomatForeignMinister : public TForeignMinister {
public:
  TDiplomatForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot19() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a008
class TTextileForeignMinister : public TForeignMinister {
public:
  TTextileForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};

// VTABLE: IMPERIALISM 0x0065a0c8
class TTraderForeignMinister : public TForeignMinister {
public:
  TTraderForeignMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NotifySlot44(void* receiver) override;
  void MinisterSlot18() override;
  void MinisterSlot21() override;
  void Call90() override;
  void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) override;
};
