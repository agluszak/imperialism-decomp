#pragma once

#ifndef IMPERIALISM_MODAL_SCREEN_H
#define IMPERIALISM_MODAL_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error ModalScreen is test-only and must not be included in the production build
#endif

#include "RuntimeActionResult.h"

// Declared `struct` to match RuntimeUiDriver.h: MSVC500 mangles struct and class differently
// (U vs V), so declaring it `class` here compiles but fails to link.
struct RuntimeControlSelector;
class TWindow;

// The modal dialog stack.
//
// Not a MainViewScreen: a modal's identity comes from its TDialogBehavior's defaultCommandCode
// rather than from a view class, and it sits on g_ModalViewStack rather than being the main
// view. Two scenarios grew near-identical copies of the same handler and diverged on which
// safety checks they kept -- one recorded the modal it handled and waited for the stack to
// unwind, the other did neither.
class ModalScreen {
public:
  ModalScreen();

  static bool AnyPresent();
  static int Depth();

  bool IsPresent() const;
  TWindow* Top() const;
  // The command the dialog fires on Enter, which is how the game itself identifies it.
  unsigned long DefaultCommand() const;
  // A turn alert: informational, confirmed with "okay". Seeing one means the turn will need
  // its Done re-submitted.
  bool IsTurnAlert() const;
  // An end-turn warning, confirmed through the picture button.
  bool IsEndTurnWarning() const;
  // Recognised means the default command is one of the two above and its control exists.
  bool IsRecognised() const;

  // Confirm the dialog through its own default command, and record which kind it was.
  RuntimeActionResult AcceptDefault();
  // Report an unrecognised modal into the run's unexpected-modal list, with its tree.
  CString Describe() const;

  // Queue a dismissal *before* entering a call that runs its own modal loop. The game's modal
  // loop does not return until the dialog closes, so an activation issued afterwards would
  // never run; this is the sanctioned way in and is used before PoseOffer and before the
  // engineer construction click.
  static RuntimeActionResult PreArmDismiss(const RuntimeControlSelector& selector);

private:
  TWindow* modal;
};

// Reads as Modal().AcceptDefault() in a script.
inline ModalScreen Modal() {
  return ModalScreen();
}

#endif
