#pragma once

#include "game/military_ui/TDefenseMinister.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x00654a28
class TNapoleonMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ed540
  ~TNapoleonMinister() override {}
  TNapoleonMinister();
  DECLARE_DYNCREATE(TNapoleonMinister)
  void MakeNewCity(TCity* city) override;
  double GetPersonalityWeightByFlag(char flag) override;
};

// VTABLE: IMPERIALISM 0x00654aa0
class TBismarckMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ed870
  ~TBismarckMinister() override {}
  TBismarckMinister();
  DECLARE_DYNCREATE(TBismarckMinister)
  void MakeNewCity(TCity* city) override;
  double GetPersonalityWeightByFlag(char flag) override;
};

// VTABLE: IMPERIALISM 0x00654b18
class TPirateMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004edb60
  ~TPirateMinister() override {}
  TPirateMinister();
  DECLARE_DYNCREATE(TPirateMinister)
  void MakeNewCity(TCity* city) override;
  double GetPersonalityWeightByFlag(char flag) override;
};

// VTABLE: IMPERIALISM 0x00654b90
class TDefenderMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ede40
  ~TDefenderMinister() override {}
  TDefenderMinister();
  DECLARE_DYNCREATE(TDefenderMinister)
  void MakeNewCity(TCity* city) override;
  double GetPersonalityWeightByFlag(char flag) override;
};

// VTABLE: IMPERIALISM 0x00654c08
class TBullyMinister : public TDefenseMinister {
public:
  // FUNCTION: IMPERIALISM 0x004ee130
  ~TBullyMinister() override {}
  TBullyMinister();
  DECLARE_DYNCREATE(TBullyMinister)
  void MakeNewCity(TCity* city) override;
  double GetPersonalityWeightByFlag(char flag) override;
};
