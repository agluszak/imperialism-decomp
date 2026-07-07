#include "game/TMapUberUberPicture.h"

#include "game/TAmbitApplication.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x0045d2a0
undefined TMapUberUberPicture::AutoScrollByEdgeMask(short edgeMask) {
  (void)edgeMask;
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0045d2c0
// TMapUberUberPicture::`scalar deleting destructor'
TMapUberUberPicture::~TMapUberUberPicture() {}
// SYNTHETIC: IMPERIALISM 0x00596770
// TMapUberUberPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005967f0
// TMapUberUberPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapUberUberPicture, TOffLimitsPicture)

TMapUberUberPicture::TMapUberUberPicture() {}

// FUNCTION: IMPERIALISM 0x00596810
void TMapUberUberPicture::NoOpUiLifecycleHook(int arg) {}

// Detach from the app root's edge-scroll/active-content backrefs before the shared
// clip-region teardown in TOffLimitsPicture::Free (0x596840 tail-jumps to 0x573900).
// FUNCTION: IMPERIALISM 0x00596840
void TMapUberUberPicture::Free() {
  static_cast<TAmbitApplication*>(g_pGlobalUiRootController)->edgeScrollTarget48 = 0;
  g_pGlobalUiRootController->field28 = 0;
  TOffLimitsPicture::Free();
}
