#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x668a60
struct CRuntimeClass;
class TSoundPlayer : public TControl {
public:
  TSoundPlayer();
  CRuntimeClass* GetRuntimeClass() override;
};
