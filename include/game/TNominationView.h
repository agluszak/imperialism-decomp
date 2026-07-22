#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063ed78
class TNominationView : public TPicture {
public:
  DECLARE_DYNCREATE(TNominationView)
  virtual ~TNominationView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004fb990
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4fb780
  virtual void Hilite();                        // slot 0x73 0x4305c0; Mac symbol oracle

  TNominationView();
};
