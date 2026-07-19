#include "game/TAmbitApplication.h"
#include "game/THighScoresPicture.h"

#include "game/TApplication.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x0045ada0
void THighScoresPicture::NoOpUiVirtualSlot73() {}

// SYNTHETIC: IMPERIALISM 0x0045adc0
// THighScoresPicture::`scalar deleting destructor'
THighScoresPicture::~THighScoresPicture() {}
// SYNTHETIC: IMPERIALISM 0x00575280
// THighScoresPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00575300
// THighScoresPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(THighScoresPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00575320
void THighScoresPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x00575460
void THighScoresPicture::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00575770
void THighScoresPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)sourceHandler;
  (void)event;
  if (commandId == 0xa) {
    g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
    g_pSfxPlaybackSystem->ResetDualAudioCuePools();
    g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(0xb);
    g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
  }
}
