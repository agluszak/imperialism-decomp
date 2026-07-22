#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642d58
class TCreditsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TCreditsPicture)
  virtual ~TCreditsPicture() override;

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite();

  TCreditsPicture();
};
