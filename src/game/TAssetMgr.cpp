#include "game/TAssetMgr.h"

// FUNCTION: IMPERIALISM 0x005df260
CRuntimeClass* TAssetMgr::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
TAssetMgr::~TAssetMgr() {}

// Forwards to the runtime view registry (slot 0x0a of g_dat_006a1b24); body still a stub.
// FUNCTION: IMPERIALISM 0x005df3c0
TView* TAssetMgr::ResolveTurnEventDialogNodeByMessageContext(int messageContext) {
  (void)messageContext;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df3f0
undefined TAssetMgr::NoOpRuntimeUiCallback_005df3f0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df410
undefined TAssetMgr::NoOpRuntimeUiCallback_005df410() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005df780
undefined TAssetMgr::NoOpRuntimeUiCallback_005df780() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005dfc10
undefined TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup() {
  return 0;
}
