#pragma once

#include "compat.h"

#include "game/military_ui/TDefenseMinister.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x00654a28
class TNapoleonMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ed540
  ~TNapoleonMinister() override {}
  TNapoleonMinister();
  void INapoleonMinister(TGreatPower* owner);
  DECLARE_DYNCREATE(TNapoleonMinister)
  void MakeNewCity(TCity* city) override;
  double GetStategicEscalationMultiplier(bool flag) override;
};
ASSERT_SIZE(TNapoleonMinister, 0x94);

// VTABLE: IMPERIALISM 0x00654aa0
class TBismarckMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ed870
  ~TBismarckMinister() override {}
  TBismarckMinister();
  void IBismarckMinister(TGreatPower* owner);
  DECLARE_DYNCREATE(TBismarckMinister)
  void MakeNewCity(TCity* city) override;
  double GetStategicEscalationMultiplier(bool flag) override;
};
ASSERT_SIZE(TBismarckMinister, 0x94);

// VTABLE: IMPERIALISM 0x00654b18
class TPirateMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004edb60
  ~TPirateMinister() override {}
  TPirateMinister();
  void IPirateMinister(TGreatPower* owner);
  DECLARE_DYNCREATE(TPirateMinister)
  void MakeNewCity(TCity* city) override;
  double GetStategicEscalationMultiplier(bool flag) override;
};
ASSERT_SIZE(TPirateMinister, 0x94);

// VTABLE: IMPERIALISM 0x00654b90
class TDefenderMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ede40
  ~TDefenderMinister() override {}
  TDefenderMinister();
  void IDefenderMinister(TGreatPower* owner);
  DECLARE_DYNCREATE(TDefenderMinister)
  void MakeNewCity(TCity* city) override;
  double GetStategicEscalationMultiplier(bool flag) override;
};
ASSERT_SIZE(TDefenderMinister, 0x94);

// VTABLE: IMPERIALISM 0x00654c08
class TBullyMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ee130
  ~TBullyMinister() override {}
  TBullyMinister();
  void IBullyMinister(TGreatPower* owner);
  DECLARE_DYNCREATE(TBullyMinister)
  void MakeNewCity(TCity* city) override;
  double GetStategicEscalationMultiplier(bool flag) override;
};
ASSERT_SIZE(TBullyMinister, 0x94);
