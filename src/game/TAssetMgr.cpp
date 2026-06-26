#include "game/TAssetMgr.h"

// FUNCTION: IMPERIALISM 0x005dff20
void EnsurePictWvDataGobLoadedBySlot(int languageTag) {
  (void)languageTag;
}

// FUNCTION: IMPERIALISM 0x005df280
TAssetMgr::TAssetMgr() : TObject() {}

// FUNCTION: IMPERIALISM 0x005df260
CRuntimeClass* TAssetMgr::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005df300
// TAssetMgr::`scalar deleting destructor'
TAssetMgr::~TAssetMgr() {}

// FUNCTION: IMPERIALISM 0x005df3a0
void ForwardEnsurePictWvDataGobLoadedBySlot(int languageTag) {
  EnsurePictWvDataGobLoadedBySlot(languageTag);
}

void TAssetMgr::EnsurePictWvDataGobLoadedForLanguageSlot(int languageTag) {
  EnsurePictWvDataGobLoadedBySlot(languageTag);
}

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
