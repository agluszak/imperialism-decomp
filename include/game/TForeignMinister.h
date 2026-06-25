#pragma once

#include "game/TMinister.h"

class TGreatPower;
class TStream;

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters();

  CRuntimeClass* GetRuntimeClass() const override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short DispatchNationStateEventCode10(short nationSlot) override;
  virtual void MinisterSlot12();
  virtual void Call4C();
  virtual void MinisterSlot14();
  virtual void Call54();

  virtual void Call58();
  virtual void MinisterSlot17();
  virtual void MinisterSlot18();
  virtual void MinisterSlot19();
  virtual void MinisterSlot1A(short arg = 0);
  virtual void MinisterSlot1B();
  virtual void MinisterSlot1C();
  virtual void MinisterSlot1D();
  virtual void MinisterSlot1E();
  virtual void MinisterSlot1F(short queueIndex); // byte 0x7c: processes a queued proposal row
  virtual void Call80();
  virtual void MinisterSlot21();
  virtual char MinisterSlot22();
  virtual void Call8C();
  virtual void Call90();
  virtual void Call94();
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation);
  virtual void RecomputeOrderStateSlot9C();

  unsigned char foreignState48[0x80 - 0x48];
};
