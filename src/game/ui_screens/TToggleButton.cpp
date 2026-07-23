#include "game/ui_screens/TToggleButton.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TCluster.h"
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
void TToggleButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != kControlCommandHiliteOff) {
    if (commandId == kControlCommandHiliteOn) {
      return;
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }

  if (this->IsSelected()) {
    unsigned int tag = this->controlTag;
    bool match = false;
    if (tag < kControlTagEmpj) {
      if (tag == kControlTagEmpi || tag == kControlTagAlli) {
        match = true;
      }
    } else if (tag < kControlTagNonB) {
      if (tag == kControlTagNonA || (tag >= kControlTagFGP0 && tag <= kControlTagFGP6)) {
        match = true;
      }
    } else {
      if (tag == kControlTagRela || tag == kControlTagTpol || tag == kControlTagWarSp) {
        match = true;
      }
    }
    if (match) {
      this->ownerContext->HandleEvent(kControlCommandHiliteOff, nullptr, nullptr);
    }
  }

  this->Select(0, 1);

  if (this->ownerContext != nullptr && this->ownerContext->controlTag == kControlTagUClu) {
    unsigned int tag = this->controlTag;
    bool match2 = false;
    if (tag < kControlTagDonf) {
      if (tag == kControlTagDone || tag == kControlTagDfnd) {
        match2 = true;
      }
    } else if (tag < kControlTagMovf) {
      if (tag == kControlTagMove || tag == kControlTagLatr) {
        match2 = true;
      }
    } else {
      if (tag >= kControlTagOpt1 && tag <= kControlTagOpt5) {
        match2 = true;
      }
    }
    if (match2) {
      this->SetEnabled(0, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005712a0
char TToggleButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
  if (!this->IsEnabled()) {
    return 0;
  }
  bool isFieldWithinLimit = this->IsSelected();
  if (!isFieldWithinLimit && !static_cast<TToggleButton*>(this->ownerContext)->IsSelected()) {
    return 1;
  }
  this->Select(!isFieldWithinLimit, 1);
  if (isFieldWithinLimit) {
    this->ownerContext->HandleEvent(0x67, this, nullptr);
  } else {
    this->ownerContext->HandleEvent(0x68, this, nullptr);
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
    static_cast<TCluster*>(this->ownerContext)->SetSelectedChildTagAndRefresh(this->controlTag);
  }
  this->PrepareForDrawing();
  this->PaintOrInvalidateControl(0);
}
