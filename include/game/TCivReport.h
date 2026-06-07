#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPictureResourceEntryBase {
public:
  TCivReport();
  virtual ~TCivReport();
};

ASSERT_SIZE(TCivReport, 0x90);
