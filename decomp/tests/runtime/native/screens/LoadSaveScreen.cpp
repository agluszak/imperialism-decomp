#include "LoadSaveScreen.h"

#include "RuntimeObservations.h"

#include "game/globals/ui_core_globals.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TLoadSavePicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

LoadSaveScreen::LoadSaveScreen()
    : MainViewScreen(RUNTIME_CLASS(TLoadSavePicture), kTurnEventLoadSave, "the save dialog"),
      loadSaveView(0) {
  loadSaveView = static_cast<TLoadSavePicture*>(Root());
}

bool LoadSaveScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TLoadSavePicture), kTurnEventLoadSave);
}

bool LoadSaveScreen::IsDismissed() {
  if (g_pViewMgr != 0 &&
      g_pViewMgr->currentTurnEventCode == EncodeTurnEventCode(kTurnEventLoadSave)) {
    return false;
  }
  return !RuntimeIsViewKindOf(RuntimeMainView(), RUNTIME_CLASS(TLoadSavePicture));
}

RuntimeActionResult LoadSaveScreen::OpenForNation(short nationSlot) {
  if (g_pViewMgr == 0) {
    return RuntimeActionResult::Failure("cannot open the save dialog: no view manager");
  }
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventLoadSave), nationSlot);
  return RuntimeActionResult::Success();
}

TLoadSavePicture* LoadSaveScreen::View() const {
  return loadSaveView;
}

RuntimeActionResult LoadSaveScreen::SelectSlot(short slot) {
  // The slots are consecutive tags from the first, which is how the dialog resolves them too.
  return Activate(kControlTagSlt0 + slot, "select a save slot");
}

short LoadSaveScreen::SelectedSlot() const {
  return loadSaveView != 0 ? loadSaveView->selectedSlot92 : -1;
}

bool LoadSaveScreen::SlotIsBeingNamed() const {
  TView* editor = Find(kControlTagSlot);
  return editor != 0 && editor->IsKindOf(RUNTIME_CLASS(TEditText)) != 0;
}

RuntimeActionResult LoadSaveScreen::Accept() {
  return Activate(kControlTagOkay, "accept the selected save slot");
}
