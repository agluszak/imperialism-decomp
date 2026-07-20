#include "game/TSuperCivRoster.h"

#include "game/CIterator.h"
#include "game/TBook.h"
#include "game/TGreatPower.h"
#include "game/TMiniCivLine.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x004ab400
// TSuperCivRoster::`scalar deleting destructor'
TSuperCivRoster::~TSuperCivRoster() {}
// SYNTHETIC: IMPERIALISM 0x004ab380
// TSuperCivRoster::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab450
// TSuperCivRoster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSuperCivRoster, TPageView)

// FUNCTION: IMPERIALISM 0x004ab470
undefined TSuperCivRoster::InitializeLedgerRosterPages(TView* pOwnerContext, int* pBoundsRect,
                                                       TView** pOutDialogView) {
  // sizeLayout is genuinely the caller's &runningDialog (a TView**) passed straight
  // through as the stack arg -- verified against the raw call site
  // (TViewMgr::ShowCivilianLedgerDialogAndSelectUnit passes &runningDialog as
  // pOutDialogView, which lands in EAX and is pushed unmodified as sizeLayout). A
  // codegen-neutral pointer reinterpret, not a guessed field.
  InitializeUiResourceEntryFrameAndParent(nullptr, pOwnerContext, pBoundsRect,
                                          reinterpret_cast<int*>(pOutDialogView), 5, 5, 0);
  controlTag = 0x70616765; // 'page'
  // Explicit qualification forces a non-virtual call, matching the original's
  // devirtualized direct call (TSuperCivRoster doesn't override this slot).
  TPageView::NoOpUiLifecycleHook(0);

  short activeNationId = g_pSimMgr->GetActiveNationId();
  CIterator cursor(g_apNationStates[activeNationId]->trackedObjectList);
  void* current = cursor.Reset();
  while (cursor.More()) {
    TMiniCivLine* line = new TMiniCivLine();
    int lineBounds[2] = {0xec, 0x40};
    line->SetLineDataRowAndBounds(0, 0, lineBounds);
    line->civUnit10 = static_cast<TCivUnit*>(current);
    OrphanCallChain_C1_I06_0056fbb0(line);
    current = cursor.Advance();
  }

  field_0x64 = 2;
  OrphanCallChain_C8_I82_0056fc80();
  OrphanCallChain_C8_I118_0056fdb0(1);
  ownerContext->AssertValid();
  static_cast<TBook*>(ownerContext)->UpdatePagedListNavigationButtonState(field_0x62);
  return 0;
}
