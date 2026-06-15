#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x6687b8
class TWarningView : public TPictureResourceEntryBase {
public:
  char pad_90_to_93[0x04];

  TWarningView();
  CRuntimeClass* GetRuntimeClass() override;

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void NoOpUiLifecycleHook(int arg) override;
};

ASSERT_SIZE(TWarningView, 0x94);
