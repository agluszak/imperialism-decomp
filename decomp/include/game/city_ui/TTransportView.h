#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TGreatPower;

// VTABLE: IMPERIALISM 0x00650078
class TTransportView : public TView {
public:
  DECLARE_DYNCREATE(TTransportView)
  virtual ~TTransportView() override;
  virtual void Close() override;
  virtual void StuffValues(TGreatPower* nation);

  // NOOP: verified empty in original 0x004bd333
  TTransportView() {}

  TGreatPower* nation;
};
ASSERT_SIZE(TTransportView, 0x64);
