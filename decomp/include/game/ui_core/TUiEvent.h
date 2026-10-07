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
  TUiEvent event;      // TEvent-derived header
  int mouseX;          // mouse-event client X
  int mouseY;          // mouse-event client Y
  short commandCode;   // virtual key code (0x68 for VK_F1)
  short keyFlags;      // nFlags & 0xf
  short handledMarker; // repeat count / "already handled" marker
  unsigned short reserved22;
  int mouseButton;            // mouse button selector read by TWorldView
  unsigned int modifierFlags; // bit0 Ctrl, bit1 Shift, bit2 Alt, bit3 RWin
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
