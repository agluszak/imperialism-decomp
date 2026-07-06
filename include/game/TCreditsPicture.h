#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642d58
class TCreditsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TCreditsPicture)
  virtual ~TCreditsPicture();

  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void NoOpUiLifecycleHook(int arg) override;
  virtual void ApplyRectSlot110(RECT* rectBuffer) override;
  virtual undefined OrphanRetStub_0043d9f0();

  TCreditsPicture();
};

