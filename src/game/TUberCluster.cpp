#include "game/TAmtBar.h"
#include "game/TControl.h"
#include "game/TUberCluster.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

const int kAssertLineMoveBarInitNil = 0x725;

// SYNTHETIC: IMPERIALISM 0x005713c0
// TUberCluster::CreateObject
// SYNTHETIC: IMPERIALISM 0x00571440
// TUberCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUberCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00571460
TUberCluster::TUberCluster() : TCluster() {}

// The scalar deleting destructor is compiler-generated from the inherited virtual dtor.

// SYNTHETIC: IMPERIALISM 0x00571490
// TUberCluster::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005714e0
int TUberCluster::IsTradeControlAtMinimum() {
  return 1;
}

void TUberCluster::SetAmountValueOnConcreteCluster(int value) {
  // Concrete amount clusters append a compatible value setter at slot 0x74, but
  // TUberCluster itself ends at slot 0x73. Keep this unresolved boundary isolated
  // until the common source-level owner contract is recovered.
  void* slotFn = (*reinterpret_cast<void***>(this))[0x74];
  reinterpret_cast<void(__fastcall*)(TUberCluster*, int /*edx*/, int)>(slotFn)(this, 0, value);
}

void TUberCluster::InitializeTradeMoveAndBarControls(unsigned int styleSeed) {
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

void TUberCluster::HandleTradeMoveControlAdjustment(int commandId, void* eventArg, int eventExtra) {
  int normalizedCommand = commandId - 100;
  if (normalizedCommand == 0) {
    TAmtBar* moveControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0x749);
    }
    short moveValue = moveControl->QueryValue();

    TAmtBar* availableControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagAvai));
    if (availableControl == 0) {
      FailNilPointerInUSmallViews(0x74d);
    }
    short availableValue = availableControl->QueryValue();
    if (moveValue < availableValue) {
      SetAmountValueOnConcreteCluster(moveValue + 1);
    }
  } else if (normalizedCommand == 1) {
    TAmtBar* moveControl = static_cast<TAmtBar*>(ResolveControlByTag(kControlTagMove));
    if (moveControl == 0) {
      FailNilPointerInUSmallViews(0x759);
    }
    int moveValue = moveControl->QueryValue();
    if (static_cast<short>(moveValue) != 0) {
      SetAmountValueOnConcreteCluster(moveValue - 1);
    }
  }
  TCluster::DoEvent(commandId, static_cast<TEventHandler*>(eventArg),
                    reinterpret_cast<TEvent*>(eventExtra));
}

TUberCluster::~TUberCluster() {}
