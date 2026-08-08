#pragma once

#ifndef IMPERIALISM_LOAD_SAVE_SCREEN_H
#define IMPERIALISM_LOAD_SAVE_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error LoadSaveScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TLoadSavePicture;

// The save/load slot dialog.
//
// Selecting a slot puts it into a name-editing state -- the slot's label becomes a real edit
// control -- and only then does okay write through the document path. A scenario that activates
// okay without that state having appeared would be testing a save the game never committed, so
// SlotIsBeingNamed() is part of the screen rather than something a caller remembers to check.
class LoadSaveScreen : public MainViewScreen {
public:
  LoadSaveScreen();

  static bool IsCurrent();
  // The dialog is no longer up: neither its turn event nor its view. Deliberately not
  // !IsCurrent(), which is also true while a modal merely covers it -- the retail save flow moves
  // on from this screen by itself, and that is what a caller waits for.
  static bool IsDismissed();

  // Raise the dialog through the game's own turn-event dispatch: it is reached from a menu the
  // scenarios do not otherwise visit.
  static RuntimeActionResult OpenForNation(short nationSlot);

  TLoadSavePicture* View() const;

  RuntimeActionResult SelectSlot(short slot);
  short SelectedSlot() const;
  // The selected slot's label became an editable field, which is the retail rename state.
  bool SlotIsBeingNamed() const;
  RuntimeActionResult Accept();

private:
  TLoadSavePicture* loadSaveView;
};

inline LoadSaveScreen LoadSave() {
  return LoadSaveScreen();
}

#endif
