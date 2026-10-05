#include "game/ui_screens/TCzechBox.h"

IMPLEMENT_DYNCREATE(TCzechBox, TUpDownPictureButton)

// The original stores isOn94 before the vptr write (init-list placement); the
// timingWord92 store visible at 0x571c28 is the inlined TUpDownPictureButton ctor.
// FUNCTION: IMPERIALISM 0x00571c20
TCzechBox::TCzechBox() : isOn94(0) {}

// FUNCTION: IMPERIALISM 0x00571c90
TCzechBox::~TCzechBox() {}

// FUNCTION: IMPERIALISM 0x00571cb0
void TCzechBox::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == kControlCommandHiliteToggle) {
    Toggle(true);
  }
  TUpDownPictureButton::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x00571cf0
void TCzechBox::DoPostCreate(int arg) {
  (void)arg;
  eventNumber60 = 4;
}

// FUNCTION: IMPERIALISM 0x00571d10
void TCzechBox::HiliteState(unsigned char fEnabledState, bool fRefreshNow) {
  if (controlState64 != fEnabledState) {
    controlState64 = fEnabledState;
    CheckTheLook(fRefreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x00571d40
void TCzechBox::CheckTheLook(unsigned char refreshNow) {
  bool useOddPicture = isOn94 != 0 || controlState64 != 0;
  if (!useOddPicture && (glyphBase84 & 1) != 0) {
    SetPictureRsrcID(static_cast<short>(glyphBase84 & ~1), refreshNow);
    if (refreshNow) {
      DrawImmediate();
    }
  } else if (useOddPicture && (glyphBase84 & 1) == 0) {
    SetPictureRsrcID(static_cast<short>(glyphBase84 | 1), refreshNow);
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
void TCzechBox::Toggle(bool refreshNow) {
  SetState(static_cast<unsigned char>(IsOn() == 0), refreshNow);
}

// FUNCTION: IMPERIALISM 0x00571e80
void TCzechBox::ToggleIf(unsigned char expectedState, unsigned char refreshNow) {
  if (IsOn() == expectedState) {
    SetState(static_cast<unsigned char>(IsOn() == 0), refreshNow);
  }
}
