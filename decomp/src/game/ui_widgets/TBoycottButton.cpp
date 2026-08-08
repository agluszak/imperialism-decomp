#include "game/ui_widgets/TBoycottButton.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TCluster.h"
#include "game/GameAssert.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x005846e0
// TBoycottButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x00584760
// TBoycottButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBoycottButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584780
TBoycottButton::TBoycottButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005847b0
// TBoycottButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005847e0
TBoycottButton::~TBoycottButton() {}

// FUNCTION: IMPERIALISM 0x00584800
void TBoycottButton::Select(bool isPressed, bool notifyParent) {
  if (static_cast<char>(isPressed) != '\0') {
    // GetWindow() (slot 0x16) -> the 'clus' control via ResolveControlByTag (slot 0x25).
    TCluster* clusControl =
        static_cast<TCluster*>(this->GetWindow()->ResolveControlByTag(kControlTagClus));
    if (clusControl == nullptr) {
      GAME_FAIL_NIL_POINTER();
    }
    clusControl->SetSelectedChildTagAndRefresh(kControlTagSpSpSpSp);
  }
  TToggleButton::Select(isPressed, notifyParent);
}
