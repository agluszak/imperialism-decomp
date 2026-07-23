#include "game/TGreatPower.h"
#include "game/TAmtBar.h"
#include "game/TAmtBarCluster.h"
#include "game/GameAssert.h"
#include "game/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_control_tags.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"
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

// FUNCTION: IMPERIALISM 0x00586ce0
TAmtBarCluster::TAmtBarCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x00586d10
// TAmtBarCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00586d60
void TAmtBarCluster::DoPostCreate(int styleSeed) {
  TAmtBar* moveControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagMove));
  TextStyle styleDescriptor = {0, 0, 0, 0};
  if (moveControl != 0) {
    BuildUiTextStyleDescriptor(&styleDescriptor, 0, 0xa, 0x2b67);
    moveControl->ApplyStyleDescriptor(&styleDescriptor, 0);
    moveControl->SetStyleState(-2, 0);
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
    TAmtBar* moveControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMove);
    }
    short moveValue = moveControl->QueryValue();

    TAmtBar* availableControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagAvai));
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustAvailable);
    }
    short availableValue = availableControl->QueryValue();
    if (moveValue < availableValue) {
      SetMoveAmount(static_cast<short>(moveValue + 1));
    }
  } else if (normalizedCommand == 1) {
    TAmtBar* moveControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineMoveAdjustMoveMinus);
    }
    int moveValue = moveControl->QueryValue();
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

TAmtBarCluster::~TAmtBarCluster() {}
