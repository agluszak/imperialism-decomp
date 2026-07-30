#pragma once

#ifndef IMPERIALISM_ENGINEER_DIALOG_SCREEN_H
#define IMPERIALISM_ENGINEER_DIALOG_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error EngineerDialogScreen is test-only and must not be included in the production build
#endif

#include "RuntimeActionResult.h"

// The engineer's construction-options dialog.
//
// It is raised from inside the map click that orders the engineer, and it runs its own modal loop:
// the click does not return until the dialog is answered. So the answer has to be queued first,
// exactly like the diplomacy offer sheet -- ArmCancel() before the click, never after.
class EngineerDialogScreen {
public:
  // Queue the cancel that will close the dialog when the map click opens it.
  static RuntimeActionResult ArmCancel();
};

#endif
