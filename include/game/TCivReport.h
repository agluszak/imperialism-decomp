#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPictureResourceEntryBase {
public:
  TCivReport();
  CRuntimeClass* GetRuntimeClass() const override;
  // ~TCivReport is compiler-generated (implicit virtual dtor).
  bool IsSelected(short value = -1, bool refreshNow = true) override;
};

ASSERT_SIZE(TCivReport, 0x90);
