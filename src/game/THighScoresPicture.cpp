#include "game/TAmbitApplication.h"
#include "game/THighScoresPicture.h"

#include "game/TApplication.h"
#include "game/TAssetMgr.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"

#include <stdio.h>
#include <string.h>

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
void THighScoresPicture::DoPostCreate(int arg) {
  TNoHilitePicture::DoPostCreate(arg);

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(0xb);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  CString path;
  AssignScoresDatPathToSharedString(&path);
  FILE* file = fopen(path, "rb");
  if (file == 0) {
    memset(scoreValues94, 0, sizeof(scoreValues94));
  } else {
    for (int i = 0; i < 10; ++i) {
      if (fread(&scoreValues94[i], 4, 1, file) == 0) {
        scoreValues94[i] = 0;
      }
      fread(scoreRecordsBc[i], 0x20, 1, file);
    }
    fclose(file);
  }
}

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
