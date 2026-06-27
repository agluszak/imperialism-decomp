#pragma once

#include "game/TDefenseMinister.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x00654a28
class TNapoleonMinister : public TDefenseMinister {
public:
  TNapoleonMinister();
  DECLARE_DYNCREATE(TNapoleonMinister)
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654aa0
class TBismarckMinister : public TDefenseMinister {
public:
  TBismarckMinister();
  DECLARE_DYNCREATE(TBismarckMinister)
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654b18
class TPirateMinister : public TDefenseMinister {
public:
  TPirateMinister();
  DECLARE_DYNCREATE(TPirateMinister)
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654b90
class TDefenderMinister : public TDefenseMinister {
public:
  TDefenderMinister();
  DECLARE_DYNCREATE(TDefenderMinister)
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654c08
class TBullyMinister : public TDefenseMinister {
public:
  TBullyMinister();
  DECLARE_DYNCREATE(TBullyMinister)
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};
