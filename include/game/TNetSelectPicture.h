#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006440d8
class TNetSelectPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TNetSelectPicture)
  virtual ~TNetSelectPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005769c0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5769a0

  // NOOP: verified empty in original 0x004544c4 (trivial inline ctor: the builder
  // expansion site emits only the base ctor call + vtbl install)
  TNetSelectPicture() {}
};
