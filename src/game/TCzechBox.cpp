#include "game/TCzechBox.h"
// SYNTHETIC: IMPERIALISM 0x00571b60
// TCzechBox::CreateObject

// SYNTHETIC: IMPERIALISM 0x00571c00
// TCzechBox::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCzechBox, TUpDownPictureButton)

// FUNCTION: IMPERIALISM 0x00571c20
TCzechBox::TCzechBox() {}

// SYNTHETIC: IMPERIALISM 0x00571c60
// TCzechBox::`scalar deleting destructor'
TCzechBox::~TCzechBox() {}

// FUNCTION: IMPERIALISM 0x00571cb0
void TCzechBox::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x21) {
    Toggle(1);
  }
  TUpDownPictureButton::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00571cf0
void TCzechBox::DoPostCreate(int arg) {
  (void)arg;
  eventNumber60 = 4;
}

// FUNCTION: IMPERIALISM 0x00571d10
void TCzechBox::HiliteState(unsigned char fEnabledState, unsigned char fRefreshNow) {
  if (controlState64 != fEnabledState) {
    controlState64 = fEnabledState;
    CheckTheLook(fRefreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x00571d40
void TCzechBox::CheckTheLook(unsigned char refreshNow) {
  bool useOddPicture = isOn94 != 0 || controlState64 != 0;
  if (!useOddPicture && (glyphBase84 & 1) != 0) {
    SetPictureResourceIdAndRefresh(static_cast<short>(glyphBase84 & ~1), refreshNow);
    if (refreshNow) {
      DrawImmediate();
    }
  } else if (useOddPicture && (glyphBase84 & 1) == 0) {
    SetPictureResourceIdAndRefresh(static_cast<short>(glyphBase84 | 1), refreshNow);
    if (refreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00571de0
unsigned char TCzechBox::IsOn() {
  return isOn94;
}

// FUNCTION: IMPERIALISM 0x00571e00
void TCzechBox::SetState(unsigned char isOn, unsigned char refreshNow) {
  if (isOn94 != isOn) {
    isOn94 = isOn;
    CheckTheLook(refreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x00571e40
void TCzechBox::Toggle(unsigned char refreshNow) {
  SetState(static_cast<unsigned char>(IsOn() == 0), refreshNow);
}

// FUNCTION: IMPERIALISM 0x00571e80
void TCzechBox::ToggleIf(unsigned char expectedState, unsigned char refreshNow) {
  if (IsOn() == expectedState) {
    SetState(static_cast<unsigned char>(IsOn() == 0), refreshNow);
  }
}
