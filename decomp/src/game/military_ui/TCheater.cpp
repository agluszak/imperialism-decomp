#include "game/military_ui/TCheater.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/TButton.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x004b1410
void TCheater::ApplyCheats() {}

// FUNCTION: IMPERIALISM 0x004b1460
TCheater::~TCheater() {}

IMPLEMENT_DYNCREATE(TCheater, TView)
// FUNCTION: IMPERIALISM 0x004b14a0
void TCheater::ConstructTCheaterBaseState(TView* panel, int unusedArg) {
  int frameOffset[2] = {0, 0};
  int frameSize[2] = {0x280, 0x1e0};
  int captionSize[2] = {0x80, 0x20};
  InitializeUiResourceEntryFrameAndParent(0, panel, frameOffset, frameSize, 5, 5, 0);

  TStaticText* caption = new TStaticText();
  caption->IStaticText(this, frameOffset, captionSize, 5, 5, 0x80, 1);

  TButton* doneButton = new TButton();
  CString doneLabel("Done");
  if (g_nMcAppUiAssertGate == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiHeaderPath, 0x5b7);
  }
  doneButton->eventNumber = 0x22;
  captionStringResourceGroup = 0x80;
}

// FUNCTION: IMPERIALISM 0x004b1670
void TCheater::ResizeWindow(const CPoint* size) {
  TWindow* window = GetWindow();
  CRect bounds;
  window->QueryBounds(&bounds);
  bounds.top = 0xf0 - size->y / 2;
  bounds.left = 0x140 - size->x / 2;
  bounds.bottom = bounds.top + size->y;
  bounds.right = bounds.left + size->x;
  window->ApplyBounds(&bounds, true);
}
