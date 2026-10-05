#pragma once

#include "compat.h"
#include "game/TEvent.h"

class TUiEvent : public TEvent {
public:
  TUiEvent();
  ~TUiEvent() override;
};

ASSERT_SIZE(TUiEvent, 0x14);

struct TToolboxEvent {
  TUiEvent event;             // 0x00 TEvent-derived header (installs vtable 0x648590)
  int mouseX;                 // 0x14 mouse-event client X
  int mouseY;                 // 0x18 mouse-event client Y
  short commandCode;          // 0x1c virtual key code (0x68 for VK_F1)
  short keyFlags;             // 0x1e nFlags & 0xf
  short handledMarker;        // 0x20 repeat count / "already handled" marker
  unsigned short reserved22;  // 0x22
  int mouseButton;            // 0x24 mouse button selector read by TWorldView
  unsigned int modifierFlags; // 0x28 bit0 Ctrl, bit1 Shift, bit2 Alt, bit3 RWin
};

ASSERT_SIZE(TToolboxEvent, 0x2c);

enum UiKeyCode {
  kUiKeyEnter = 3,     // Mac Enter (ETX); VK_CANCEL on Windows, never produced here
  kUiKeyReturn = 0x0d, // VK_RETURN
  kUiKeyEscape = 0x1b, // VK_ESCAPE
  kUiKeySpace = 0x20,  // VK_SPACE
  kUiKeyPeriod = 0x2e, // Mac Command-period cancel; VK_DELETE on Windows
  kUiKeyHelpUpperCase = 'H',
  kUiKeyHelpLowerCase = 'h'
};
