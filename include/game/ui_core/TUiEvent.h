#pragma once

#include "compat.h"
#include "game/TEvent.h"

// TEvent subclass with its own vtable (0x648590) and destructor but no RTTI/DYNCREATE
// registration and no additional virtuals or fixed fields of its own (GetRuntimeClass
// is inherited unchanged from TEvent). Every call site recycles the storage past the
// TEvent header for an unrelated purpose (a keyboard command code, mouse click
// coordinates, ...), so this base carries no trailing fields; see the per-call-site
// layouts that follow it (TKeyCommandEvent below; the mouse-click block local to
// CIncludeView.cpp).
class TUiEvent : public TEvent {
public:
  TUiEvent();
  ~TUiEvent() override;
};

ASSERT_SIZE(TUiEvent, 0x14);

// The shared keyboard/turn-order-navigation command event (persistent global object @
// 0x6a1780): a TUiEvent header followed by the command parameters written once per
// keystroke by CIncludeView::OnKeyDown (0x484260) and read by TGameWindow::DoKeyEvent
// (0x4ffd70). The not-yet-ported CMcWindow WM_CHAR handler (0x493ce0) shares the same
// global object and should use this type when it's ported.
struct TToolboxEvent {
  TUiEvent event;             // 0x00 TEvent-derived header (installs vtable 0x648590)
  int mouseX;                 // 0x14 mouse-event client X
  int mouseY;                 // 0x18 mouse-event client Y
  short commandCode;          // 0x1c virtual key code (0x68 for VK_F1)
  short keyFlags;             // 0x1e nFlags & 0xf
  short handledMarker;        // 0x20 repeat count / "already handled" marker
  unsigned short reserved22;  // 0x22
  int mouseButton24;          // 0x24 mouse button selector read by TWorldView
  unsigned int modifierFlags; // 0x28 bit0 Ctrl, bit1 Shift, bit2 Alt, bit3 RWin
};

ASSERT_SIZE(TToolboxEvent, 0x2c);

// Transitional source alias for the already-ported Windows keyboard handlers.
typedef TToolboxEvent TKeyCommandEvent;

// The key codes the dialog/window handlers test TToolboxEvent::commandCode against.
//
// This slot is filled by two producers: CIncludeView::OnKeyDown (0x00484260) forwards
// WM_KEYDOWN's virtual-key code, and the CMcWindow WM_CHAR handler (0x00493ce0)
// forwards a character code. The accept/cancel values are inherited verbatim from the
// Mac build, where the slot held the Toolbox event's ASCII character -- which is why
// the accept test still includes 3 (Mac Enter, a code no Windows key produces) beside
// carriage return, and why the help test accepts both letter cases.
enum UiKeyCode {
  kUiKeyEnter = 3,     // Mac Enter (ETX); VK_CANCEL on Windows, never produced here
  kUiKeyReturn = 0x0d, // VK_RETURN
  kUiKeyEscape = 0x1b, // VK_ESCAPE
  kUiKeySpace = 0x20,  // VK_SPACE
  kUiKeyPeriod = 0x2e, // Mac Command-period cancel; VK_DELETE on Windows
  kUiKeyHelpUpperCase = 'H',
  kUiKeyHelpLowerCase = 'h'
};
