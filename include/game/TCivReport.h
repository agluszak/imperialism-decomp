#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPictureResourceEntryBase {
public:
  TCivReport();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TCivReport is compiler-generated (implicit virtual dtor).
};

ASSERT_SIZE(TCivReport, 0x90);
