#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;
class TCivUnit;
// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPicture {
public:
  virtual ~TCivReport() override;
  TCivReport();
  DECLARE_DYNCREATE(TCivReport)
  virtual void StuffValues(TCivUnit* civilianOrderEntry);
};

ASSERT_SIZE(TCivReport, 0x90);
