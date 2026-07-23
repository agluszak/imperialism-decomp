#pragma once

#include "compat.h"
#include "game/TPicture.h"

struct CRuntimeClass;
class TCivUnit;
// VTABLE: IMPERIALISM 0x668128
class TCivReport : public TPicture {
public:
  virtual ~TCivReport() override; // slot 0x01 (scalar deleting destructor)
  TCivReport();
  DECLARE_DYNCREATE(TCivReport)
  // Slot 0x73 (byte 0x1cc), 0x590cb0, RET 0x4. This is the 'DLOG' pict of MapView.rsrc
  // view 3012 "Civilian info" (Mac resource oracle) and TViewMgr::ShowCivilianReport-
  // DialogAndReturnConfirm is its only caller, which passes the civilian order entry.
  // The previous `IsSelected(void*)` name/signature was a guess.
  virtual void PopulateCivilianReportContent(TCivUnit* civilianOrderEntry);
};

ASSERT_SIZE(TCivReport, 0x90);
