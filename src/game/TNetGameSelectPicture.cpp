#include "game/TNetGameSelectPicture.h"

#include "game/TMultiplayerMgr.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00576b20
// TNetGameSelectPicture::`scalar deleting destructor'
TNetGameSelectPicture::~TNetGameSelectPicture() {}
// SYNTHETIC: IMPERIALISM 0x00576aa0
// TNetGameSelectPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576b70
// TNetGameSelectPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNetGameSelectPicture, TNoHilitePicture)

TNetGameSelectPicture::TNetGameSelectPicture() {}

// FUNCTION: IMPERIALISM 0x00576b90
void TNetGameSelectPicture::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  g_pGameFlowState->InitializeRuntimeSelectionCredentialsFromProviderAndConnect(this);
}

// FUNCTION: IMPERIALISM 0x00576bc0
void TNetGameSelectPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) { }
