#include "game/TToggleButton.h"
#include "game/TControl.h"
#include "game/TCluster.h"
#include "game/mfc.h"


// SYNTHETIC: IMPERIALISM 0x00571050
// TToggleButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x005710d0
// TToggleButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TToggleButton, TPicture)

// FUNCTION: IMPERIALISM 0x005710f0
TToggleButton::TToggleButton() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00571120
// TToggleButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00571170
void TToggleButton::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != 0x20) {
    if (commandId == 0x1f) {
      return;
    }
    TControl::HandleEvent(commandId, sourceHandler, event);
    return;
  }

  if (this->IsSelected()) {
    unsigned int tag = this->controlTag;
    bool match = false;
    if (tag < 0x656d706a) {
      if (tag == 0x656d7069 || tag == 0x616c6c69) {
        match = true;
      }
    } else if (tag < 0x6e6f6e42) {
      if (tag == 0x6e6f6e41 || (tag >= 0x66475030 && tag <= 0x66475036)) {
        match = true;
      }
    } else {
      if (tag == 0x72656c61 || tag == 0x74706f6c || tag == 0x77617220) {
        match = true;
      }
    }
    if (match) {
      this->ownerContext->DispatchEvent(0x20, nullptr, nullptr);
    }
  }

  this->Select(0, 1);

  if (this->ownerContext != nullptr && this->ownerContext->controlTag == 0x75436c75) {
    unsigned int tag = this->controlTag;
    bool match2 = false;
    if (tag < 0x646f6e66) {
      if (tag == 0x646f6e65 || tag == 0x64666e64) {
        match2 = true;
      }
    } else if (tag < 0x6d6f7666) {
      if (tag == 0x6d6f7665 || tag == 0x6c617472) {
        match2 = true;
      }
    } else {
      if (tag >= 0x6f707431 && tag <= 0x6f707435) {
        match2 = true;
      }
    }
    if (match2) {
      this->SetEnabled(0, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005712a0
char TToggleButton::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  if (!this->GetBoolSlot28()) {
    return 0;
  }
  bool isFieldWithinLimit = this->IsSelected();
  bool isOwnerWithinLimit = false;
  if (this->ownerContext != nullptr) {
    isOwnerWithinLimit = static_cast<TToggleButton*>(this->ownerContext)->IsSelected();
  }
  if (!isFieldWithinLimit && !isOwnerWithinLimit) {
    return 1;
  }
  this->Select(!isFieldWithinLimit, 1);
  if (!isFieldWithinLimit) {
    this->ownerContext->DispatchEvent(0x68, this, nullptr);
  } else {
    this->ownerContext->DispatchEvent(0x67, this, nullptr);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00571330
bool TToggleButton::IsSelected() {
  return this->IsActionable();
}

TToggleButton::~TToggleButton() {}

// FUNCTION: IMPERIALISM 0x00571350
void TToggleButton::Select(bool isPressed, bool notifyParent) {
  this->SetEnabled(static_cast<char>(isPressed), static_cast<char>(notifyParent));
  if (static_cast<char>(isPressed) != '\0') {
    // The owner panel is a TCluster; notify it which child tag is now active (slot 0x72).
    static_cast<TCluster*>(this->ownerContext)->SetControlClassAndRefresh(this->controlTag);
  }
  this->Refresh();
  this->PaintOrInvalidateControl(0);
}
