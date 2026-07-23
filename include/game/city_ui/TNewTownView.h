#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TTown;

// VTABLE: IMPERIALISM 0x00650270
class TNewTownView : public TView {
public:
  DECLARE_DYNCREATE(TNewTownView)
  virtual ~TNewTownView() override;      // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;         // slot 0x28 0x4bdc10
  virtual void StuffValues(TTown* town); // slot 0x68 0x4bd880

  TNewTownView();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  TTown* town60;
};
