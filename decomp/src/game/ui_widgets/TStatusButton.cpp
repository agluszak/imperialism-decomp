#include "game/ui_widgets/TStatusButton.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TStatusButton, TButton)

// FUNCTION: IMPERIALISM 0x00586330
TStatusButton::TStatusButton() : TButton() {}

// FUNCTION: IMPERIALISM 0x00586400
void TStatusButton::DoEvent(int selectedIndex, TEventHandler* sourceHandler, TEvent* event) {
  CString scratchA;
  CString scratchB;

  if (selectedIndex == GetEventNumber() && IsEnabled() != '\0') {
    if (LogUnhandledDialogMethodAndReturnFalse() != '\0') {
      return;
    }

    if (g_pActiveCityDialogLegendSelectionOwner != NULL) {
      static_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->Close();
      g_pActiveCityDialogLegendSelectionOwner = NULL;
      g_bCityDialogLegendSelectionInitialized = 0;
    }

    TControl* backControl =
        static_cast<TControl*>(ownerContext->ResolveControlByTag(kControlTagBack));
    if (backControl != NULL) {
      backControl->Free();
      ownerContext->RefreshControl();
    }

    if (controlTag != kControlTagArms && controlTag == kControlTagClos) {
      if (g_pActiveCityDialogLegendSelectionOwner != NULL) {
        static_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->Close();
        g_pActiveCityDialogLegendSelectionOwner = NULL;
      }
      g_bCityDialogLegendSelectionInitialized = 0;
      GetWindow()->Close();
    }

    TControl::DoEvent(selectedIndex, this, event);
    return;
  }

  TControl::DoEvent(selectedIndex, sourceHandler, event);
}
