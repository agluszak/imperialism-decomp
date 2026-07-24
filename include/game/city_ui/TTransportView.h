#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TGreatPower;

// VTABLE: IMPERIALISM 0x00650078
class TTransportView : public TView {
public:
  DECLARE_DYNCREATE(TTransportView)
  virtual ~TTransportView() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;                 // slot 0x28 0x4bd690
  virtual void StuffValues(TGreatPower* nation); // slot 0x68 0x4bd3e0

  TTransportView();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  TGreatPower* nation60;
};
ASSERT_SIZE(TTransportView, 0x64);
