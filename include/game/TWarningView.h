#pragma once

#include "compat.h"
#include "game/TPicture.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x6687b8
class TWarningView : public TPicture {
public:
  virtual ~TWarningView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00592980
  char pad_90_to_93[0x04];

  TWarningView();
  DECLARE_DYNCREATE(TWarningView)
  void DoPostCreate(int arg) override;
};

ASSERT_SIZE(TWarningView, 0x94);
