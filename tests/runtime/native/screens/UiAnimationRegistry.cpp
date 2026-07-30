#include "UiAnimationRegistry.h"

// TList is a CList specialisation over TView*, so the element type has to be complete before
// afxtempl instantiates it.
#include "game/ui_core/TView.h"

#include "game/TList.h"
#include "game/app/TAnimator.h"
#include "game/globals/ui_core_globals.h"

bool UiAnimationRegistry::IsReady() {
  return g_pUiAnimator != 0 && g_pUiAnimator->registryList24 != 0;
}

int UiAnimationRegistry::Count() {
  return IsReady() ? g_pUiAnimator->registryList24->GetCount() : -1;
}

bool UiAnimationRegistry::Contains(int tag) {
  return IsReady() && g_pUiAnimator->FindRegisteredAnimationByTag(tag) != 0;
}
