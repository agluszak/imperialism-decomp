#include "game/TSetupRandomMapPicture.h"

#include "game/TUiEvent.h"
// SYNTHETIC: IMPERIALISM 0x00576ca0
// TSetupRandomMapPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00576d60
// TSetupRandomMapPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSetupRandomMapPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00576d80
TSetupRandomMapPicture::TSetupRandomMapPicture()
    : TNoHilitePicture(), countryName94(), flag98(0), flagA4(0) {}

// SYNTHETIC: IMPERIALISM 0x00576e00
// TSetupRandomMapPicture::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x00576e30
// TSetupRandomMapPicture::~TSetupRandomMapPicture
TSetupRandomMapPicture::~TSetupRandomMapPicture() {}

// FUNCTION: IMPERIALISM 0x00577030
void TSetupRandomMapPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005779c0
void TSetupRandomMapPicture::HandleEvent(int commandId, TEventHandler* sourceHandler,
                                         TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00577e40
undefined TSetupRandomMapPicture::ApplyNationSelectionAndMaybePostTurnEvent5E4() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005781f0
undefined TSetupRandomMapPicture::PostTurnEvent5DCOrResetLocalUiState() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005782f0
void TSetupRandomMapPicture::ForwardParam(int param) {
  TKeyCommandEvent* commandEvent = reinterpret_cast<TKeyCommandEvent*>(param);
  int commandCode = commandEvent->commandCode;
  if (commandCode == 3 || commandCode == 0xd) {
    ApplyNationSelectionAndMaybePostTurnEvent5E4();
  } else if (commandCode == 0x1b) {
    PostTurnEvent5DCOrResetLocalUiState();
  }
}
