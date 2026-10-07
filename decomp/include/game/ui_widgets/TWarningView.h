#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x6687b8
class TWarningView : public TPicture {
public:
  virtual ~TWarningView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  char pad_90_to_93[4];

  TWarningView();
  DECLARE_DYNCREATE(TWarningView)
  void DoPostCreate(int arg) override;
};

ASSERT_SIZE(TWarningView, 0x94);
