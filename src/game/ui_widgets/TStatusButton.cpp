#include "game/ui_widgets/TStatusButton.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/mfc.h"
// SYNTHETIC: IMPERIALISM 0x00586280
// TStatusButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x00586310
// TStatusButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TStatusButton, TButton)

// FUNCTION: IMPERIALISM 0x00586330
TStatusButton::TStatusButton() : TButton() {}

// Destructor is compiler-generated (implicit) from real TButton inheritance.
// SYNTHETIC: IMPERIALISM 0x005863b0
// TStatusButton::`scalar deleting destructor'

const int kControlTagBack = 0x6261636b; // 'back'
const int kControlTagArms = 0x41726d73; // 'arms'
const int kControlTagClos = 0x436c6f73; // 'Clos'

// FUNCTION: IMPERIALISM 0x00586400
void TStatusButton::DoEvent(int selectedIndex, TEventHandler* sourceHandler, TEvent* event) {
  // Two CString scratch locals the original constructs on entry and destroys on exit;
  // unused in the body but required to reproduce the prologue/epilogue.
  CString scratchA;
  CString scratchB;

  if (selectedIndex == GetEventNumber() && IsEnabled() != '\0') {
    if (LogUnhandledDialogMethodAndReturnFalse() != '\0') {
      return;
    }

    if (g_pActiveCityDialogLegendSelectionOwner != nullptr) {
      static_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->Close();
      g_pActiveCityDialogLegendSelectionOwner = nullptr;
      g_bCityDialogLegendSelectionInitialized = 0;
    }

    TControl* backControl =
        static_cast<TControl*>(ownerContext->ResolveControlByTag(kControlTagBack));
    if (backControl != nullptr) {
      backControl->Free();
      ownerContext->RefreshControl();
    }

    if (controlTag != kControlTagArms && controlTag == kControlTagClos) {
      if (g_pActiveCityDialogLegendSelectionOwner != nullptr) {
        static_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->Close();
        g_pActiveCityDialogLegendSelectionOwner = nullptr;
      }
      g_bCityDialogLegendSelectionInitialized = 0;
      GetWindow()->Close();
    }

    TControl::DoEvent(selectedIndex, this, event);
    return;
  }

  TControl::DoEvent(selectedIndex, sourceHandler, event);
}
