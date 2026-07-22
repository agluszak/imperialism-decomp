#pragma once

#include "game/TLineData.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065e480
class TPictureLine : public TLineData {
public:
  DECLARE_DYNCREATE(TPictureLine)
  virtual ~TPictureLine() override; // slot 0x01 (scalar deleting destructor)
  virtual void InstallViews(TView* panel, int* offsetLayout) override; // slot 0x0a 0x570130

  TPictureLine();

  // Original object size is 0x14 (CRuntimeClass m_nObjectSize); the source class ended at 0x10. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  short pictureResourceId10;
  short reserved12;
};
