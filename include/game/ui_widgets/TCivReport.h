#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPicture {
public:
  virtual ~TCivReport() override; // slot 0x01 (scalar deleting destructor)
  TCivReport();
  DECLARE_DYNCREATE(TCivReport)
  virtual bool IsSelected(void* reportRecord);
};

ASSERT_SIZE(TCivReport, 0x90);
