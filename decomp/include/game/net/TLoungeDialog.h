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
  virtual ~TLoungeDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;      // slot 0x07 0x54d6f0
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0054e1f0
  virtual char DoIdle(int action) override;     // slot 0x13 0x54db40
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x54d730

  // NOOP: verified empty in original 0x0054d686 (no standalone TLoungeDialog::TLoungeDialog body exists: CreateObject 0x0054d650 inlines this default ctor, calling the TNoHilitePicture base ctor directly at that site)
  TLoungeDialog() {}

  // 0x54e4c0: refresh the lounge's 'map '/'mess'/'okay' controls for the current
  // scenario/session context (turn-event 0xE receive tail; the original tolerates a
  // null `this`).
  void RefreshMapAndMessageControlsForCurrentContext();

  // Offer to replace a remote human nation with an AI. Without Ctrl this queues the
  // normal pose message; Ctrl+host opens the immediate replacement confirmation.
  void TryReplaceRemoteNationSlot(int nationSlot); // 0x54dfc0

  int selectedNationSlot; // 0x94, initialized to -1 after the lounge controls are bound
};
ASSERT_SIZE(TLoungeDialog, 0x98);
