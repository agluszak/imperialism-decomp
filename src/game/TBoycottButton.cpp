#include "game/TBoycottButton.h"
#include "game/TCluster.h"
#include "game/GameAssert.h"
#include "game/mfc.h"


// FUNCTION: IMPERIALISM 0x005846e0
TBoycottButton* __cdecl CreateTBoycottButtonInstance(void) {
  return new TBoycottButton();
}
// SYNTHETIC: IMPERIALISM 0x00584760
// TBoycottButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBoycottButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00584780
TBoycottButton::TBoycottButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005847b0
// TBoycottButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00584800
void TBoycottButton::Select(bool isPressed, bool notifyParent) {
  if (static_cast<char>(isPressed) != '\0') {
    // OwnerPanel() (slot 0x16) -> the 'clus' control via ResolveControlByTag (slot 0x25).
    TCluster* clusControl =
        static_cast<TCluster*>(this->OwnerPanel()->ResolveControlByTag(0x636c7573 /* 'clus' */));
    if (clusControl == nullptr) {
      GAME_FAIL_NIL_POINTER();
    }
    clusControl->SetControlClassAndRefresh(0x20202020 /* '    ' */);
  }
  TToggleButton::Select(isPressed, notifyParent);
}

TBoycottButton::~TBoycottButton() {}
