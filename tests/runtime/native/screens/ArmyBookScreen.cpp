#include "ArmyBookScreen.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/military/TGarrisonView.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"

ArmyBookScreen::ArmyBookScreen() : book(0) {}

RuntimeActionResult ArmyBookScreen::Open() {
  if (book != 0) {
    return RuntimeActionResult::Success();
  }
  if (g_pAssetMgr == 0) {
    return RuntimeActionResult::Failure("cannot open the army book: no asset manager");
  }
  book = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
  if (book == 0) {
    return RuntimeActionResult::Failure(
        "cannot open the army book: the garrison turn event resolved no dialog node");
  }
  if (GarrisonPage() == 0) {
    return RuntimeActionResult::Failure(
        "the army book opened without building a TGarrisonView content page");
  }
  return RuntimeActionResult::Success();
}

bool ArmyBookScreen::IsOpen() const {
  return book != 0;
}

TGarrisonView* ArmyBookScreen::GarrisonPage() const {
  if (book == 0) {
    return 0;
  }
  TView* page = book->ResolveControlByTag(kControlTagPage);
  return page != 0 && page->IsKindOf(RUNTIME_CLASS(TGarrisonView)) != 0
             ? static_cast<TGarrisonView*>(page)
             : 0;
}

RuntimeActionResult ArmyBookScreen::ShowProvince(short province) {
  TGarrisonView* garrison = GarrisonPage();
  if (garrison == 0) {
    return RuntimeActionResult::Failure("cannot show a province: the army book has no page");
  }
  garrison->StuffValues(province);
  return RuntimeActionResult::Success();
}

bool ArmyBookScreen::HasUnitSpritePage() const {
  TGarrisonView* garrison = GarrisonPage();
  return garrison != 0 && garrison->primaryUnitAtlas84 != 0;
}

RuntimeActionResult ArmyBookScreen::Close() {
  if (book == 0) {
    return RuntimeActionResult::Failure("cannot close the army book: it is not open");
  }
  // Close then Free, matching the game's own teardown of a resolved dialog node.
  book->Close();
  book->Free();
  book = 0;
  return RuntimeActionResult::Success();
}
