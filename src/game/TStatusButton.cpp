#include "game/TStatusButton.h"
#include "game/ui_widget_thunks.h"
#include "game/TAmtBar.h"

int g_pClassDescTStatusButton;

// FUNCTION: IMPERIALISM 0x00586330
TStatusButton::TStatusButton() : TButton() {}

int TStatusButton::ControlTag() const {
  return *reinterpret_cast<const int*>(reinterpret_cast<const char*>(this) + 0x1c);
}

void* TStatusButton::OwnerPanel() const {
  return *reinterpret_cast<void* const*>(reinterpret_cast<const char*>(this) + 0x20);
}

// FUNCTION: IMPERIALISM 0x00586280
TStatusButton* __cdecl CreateTStatusButtonInstance(void) {
  return new TStatusButton();
}

// FUNCTION: IMPERIALISM 0x00586310
void* __cdecl GetTStatusButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTStatusButton);
}

// Destructor is compiler-generated (implicit) from real TButton inheritance.
// SYNTHETIC: IMPERIALISM 0x005863b0
// TStatusButton::`scalar deleting destructor'

extern "C" void* g_pActiveCityDialogLegendSelectionOwner;
extern unsigned char g_bCityDialogLegendSelectionInitialized;

const int kControlTagBack = 0x6261636b;
const int kControlTagArms = 0x41726d73;
const int kControlTagClos = 0x436c6f73;

// FUNCTION: IMPERIALISM 0x00586400
void TStatusButton::HandleCityDialogSelectionAndBackControlReset(int selectedIndex) {
  if (selectedIndex == QuerySelectedIndexSlotBC() && GetBoolSlot28() != '\0') {
    if (GetBoolSlot1BC() == '\0') {
      if (g_pActiveCityDialogLegendSelectionOwner != 0) {
        reinterpret_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->CallVoidSlotA0();
        g_pActiveCityDialogLegendSelectionOwner = 0;
        g_bCityDialogLegendSelectionInitialized = 0;
      }

      TAmtBar* backControl = reinterpret_cast<TAmtBar*>(
          reinterpret_cast<TView*>(OwnerPanel())->ResolveControlByTag(kControlTagBack));
      if (backControl != 0) {
        reinterpret_cast<TView*>(backControl)->CallVoidSlot1C();
        reinterpret_cast<TView*>(OwnerPanel())->RefreshControl();
      }

      if (ControlTag() != kControlTagArms && ControlTag() == kControlTagClos) {
        if (g_pActiveCityDialogLegendSelectionOwner != 0) {
          reinterpret_cast<TView*>(g_pActiveCityDialogLegendSelectionOwner)->CallVoidSlotA0();
          g_pActiveCityDialogLegendSelectionOwner = 0;
        }
        g_bCityDialogLegendSelectionInitialized = 0;
        TView* ownerPanel = reinterpret_cast<TView*>(OwnerPanel());
        if (ownerPanel != 0) {
          ownerPanel->CallVoidSlotA0();
        }
      }
    }
  }

  thunk_HandleCityDialogToggleCommandOrForward();
}
