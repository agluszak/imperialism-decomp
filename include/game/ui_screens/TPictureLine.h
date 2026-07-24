#pragma once

#include "compat.h"

#include "game/ui_screens/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e480
class TPictureLine : public TLineData {
public:
  DECLARE_DYNCREATE(TPictureLine)
  virtual ~TPictureLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x570130

  // NOOP: verified empty in original 0x00570032 (no standalone TPictureLine::TPictureLine body exists: construction is fully inlined into CreateObject 0x00570030; that address is its operator-new call site)
  TPictureLine() {}

  // Original object size is 0x14 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  short pictureResourceId10;
  short reserved12;
};
ASSERT_SIZE(TPictureLine, 0x14);
