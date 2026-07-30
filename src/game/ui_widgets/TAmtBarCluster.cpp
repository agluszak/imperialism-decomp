#include "game/nation/TGreatPower.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;
const int kAssertLineMoveBarInitNil = 0x725;
const int kAssertLineMoveAdjustMove = 0x749;
const int kAssertLineMoveAdjustAvailable = 0x74d;
const int kAssertLineMoveAdjustMoveMinus = 0x759;

// SYNTHETIC: IMPERIALISM 0x00586c40
// TAmtBarCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00586cc0
// TAmtBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAmtBarCluster, TUberCluster)

// SYNTHETIC: IMPERIALISM 0x00586d10
// TAmtBarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586d40
TAmtBarCluster::~TAmtBarCluster() {}

// FUNCTION: IMPERIALISM 0x00586d60
void TAmtBarCluster::DoPostCreate(int styleSeed) {
  // 'move' is a TNumberText (UI factory: new TNumberText() for tag 'move'); slots
  // 0x6d/0x71 are TNumberText-hierarchy virtuals past TAmtBar's extent.
  TNumberText* moveControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagMove));
  TextStyle styleDescriptor = {0, 0, 0, 0};
  if (moveControl != 0) {
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    moveControl->InstallTextStyle(styleDescriptor, 0);
    moveControl->SetTextAlignmentAndMaybeRefresh(-2, 0);
  }

  TAmtBar* barControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineMoveBarInitNil);
  }
  barControl->DoPostCreate(styleSeed);
  TView::DoPostCreate(styleSeed);
}

// FUNCTION: IMPERIALISM 0x00586e70
void TAmtBarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int normalizedCommand = commandId - 100;
  if (normalizedCommand == 0) {
    TNumberText* moveControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMove);
    }
    short moveValue = static_cast<short>(moveControl->UpdateControlCachedIntFromWindowText());

    TNumberText* availableControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagAvai));
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustAvailable);
    }
    short availableValue =
        static_cast<short>(availableControl->UpdateControlCachedIntFromWindowText());
    if (moveValue < availableValue) {
      SetMoveAmount(static_cast<short>(moveValue + 1));
    }
  } else if (normalizedCommand == 1) {
    TNumberText* moveControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMoveMinus);
    }
    int moveValue = moveControl->UpdateControlCachedIntFromWindowText();
    if (static_cast<short>(moveValue) != 0) {
      SetMoveAmount(static_cast<short>(moveValue - 1));
    }
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00586ff0
void TAmtBarCluster::SetMoveAmount(short amount) {
  (void)amount;
}
