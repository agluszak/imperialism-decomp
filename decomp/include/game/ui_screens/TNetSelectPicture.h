#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006440d8
class TNetSelectPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TNetSelectPicture)
  virtual ~TNetSelectPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x004544c4
  TNetSelectPicture() {}
};
ASSERT_SIZE(TNetSelectPicture, 0x94);
