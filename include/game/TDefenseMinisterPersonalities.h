#pragma once

#include "game/TDefenseMinister.h"

// VTABLE: IMPERIALISM 0x00654a28
class TNapoleonMinister : public TDefenseMinister {
public:
  TNapoleonMinister();
};

// VTABLE: IMPERIALISM 0x00654aa0
class TBismarckMinister : public TDefenseMinister {
public:
  TBismarckMinister();
};

// VTABLE: IMPERIALISM 0x00654b18
class TPirateMinister : public TDefenseMinister {
public:
  TPirateMinister();
};

// VTABLE: IMPERIALISM 0x00654b90
class TDefenderMinister : public TDefenseMinister {
public:
  TDefenderMinister();
};

// VTABLE: IMPERIALISM 0x00654c08
class TBullyMinister : public TDefenseMinister {
public:
  TBullyMinister();
};
