#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/multiplayer_session_tags.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006433b8
class TLoungeDialog : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TLoungeDialog)
  virtual ~TLoungeDialog() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual bool DoIdle(int action) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x0054d686
  TLoungeDialog() {}

  void YouHaveNewGameData();

  void NationalClick(int nationSlot);

  int selectedNationSlot; // initialized to -1 after the lounge controls are bound
};
ASSERT_SIZE(TLoungeDialog, 0x98);
