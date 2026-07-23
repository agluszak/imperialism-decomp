#include "game/military_ui/TSuperCivRoster.h"
#include "game/ui_tags_common.h"

#include "game/ui_core/CIterator.h"
#include "game/ui_screens/TBook.h"
#include "game/nation/TGreatPower.h"
#include "game/military_ui/TMiniCivLine.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x004ab400
// TSuperCivRoster::`scalar deleting destructor'
TSuperCivRoster::~TSuperCivRoster() {}
// SYNTHETIC: IMPERIALISM 0x004ab380
// TSuperCivRoster::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab450
// TSuperCivRoster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSuperCivRoster, TPageView)

// FUNCTION: IMPERIALISM 0x004ab470
void TSuperCivRoster::InitializeLedgerRosterPages(TView* pOwnerContext, int* pBoundsRect,
                                                  TView** pOutDialogView) {
  // sizeLayout is genuinely the caller's &runningDialog (a TView**) passed straight
  // through as the stack arg -- verified against the raw call site
  // (TViewMgr::ShowCivilianLedgerDialogAndSelectUnit passes &runningDialog as
  // pOutDialogView, which lands in EAX and is pushed unmodified as sizeLayout). A
  // codegen-neutral pointer reinterpret, not a guessed field.
  InitializeUiResourceEntryFrameAndParent(nullptr, pOwnerContext, pBoundsRect,
                                          reinterpret_cast<int*>(pOutDialogView), 5, 5, 0);
  controlTag = kControlTagPage; // 'page'
  // Explicit qualification forces a non-virtual call, matching the original's
  // devirtualized direct call (TSuperCivRoster doesn't override this slot).
  TPageView::DoPostCreate(0);

  short activeNationId = g_pSimMgr->GetActiveNationId();
  CIterator cursor(g_apNationStates[activeNationId]->trackedObjectList);
  void* current = cursor.Reset();
  while (cursor.More()) {
    TMiniCivLine* line = new TMiniCivLine();
    int lineBounds[2] = {0xec, 0x40};
    line->SetLineDataRowAndBounds(0, 0, lineBounds);
    line->civUnit10 = static_cast<TCivUnit*>(current);
    AddOrderedEntry(line);
    current = cursor.Advance();
  }

  visibleColumnCount = 2;
  BuildPageLayout();
  ShowPage(1);
  TBook* ownerBook = static_cast<TBook*>(ownerContext);
  ownerBook->AssertValid();
  ownerBook->ShowPage(currentPage);
}
