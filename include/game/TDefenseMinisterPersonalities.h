#pragma once

#include "game/TDefenseMinister.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x00654a28
class TNapoleonMinister : public TDefenseMinister {
public:
  TNapoleonMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654aa0
class TBismarckMinister : public TDefenseMinister {
public:
  TBismarckMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654b18
class TPirateMinister : public TDefenseMinister {
public:
  TPirateMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654b90
class TDefenderMinister : public TDefenseMinister {
public:
  TDefenderMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};

// VTABLE: IMPERIALISM 0x00654c08
class TBullyMinister : public TDefenseMinister {
public:
  TBullyMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void NoOpForeignMinisterUtilityStub(void* receiver) override;
  undefined CreateTDefenseMinisterInstance() override;
};
