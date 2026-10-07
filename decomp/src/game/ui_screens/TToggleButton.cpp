#include "game/ui_screens/TToggleButton.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TCluster.h"
#include "game/mfc.h"

IMPLEMENT_DYNCREATE(TToggleButton, TPicture)

// FUNCTION: IMPERIALISM 0x005710f0
TToggleButton::TToggleButton() : TPicture() {}

// FUNCTION: IMPERIALISM 0x00571150
TToggleButton::~TToggleButton() {}

// FUNCTION: IMPERIALISM 0x00571170
void TToggleButton::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId != kControlCommandHiliteOff) {
    if (commandId == kControlCommandHiliteOn) {
      return;
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }

  if (IsSelected()) {
    unsigned int tag = controlTag;
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
      ownerContext->HandleEvent(kControlCommandHiliteOff, NULL, NULL);
    }
  }

  Select(false, true);

  if (ownerContext != NULL && ownerContext->controlTag == kControlTagUClu) {
    unsigned int tag = controlTag;
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
      Show(0, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005712a0
bool TToggleButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (!IsEnabled()) {
    return false;
  }
  bool isFieldWithinLimit = IsSelected();
  if (!isFieldWithinLimit && !static_cast<TToggleButton*>(ownerContext)->IsSelected()) {
    return true;
  }
  Select(!isFieldWithinLimit, true);
  if (isFieldWithinLimit) {
    ownerContext->HandleEvent(0x67, this, NULL);
  } else {
    ownerContext->HandleEvent(0x68, this, NULL);
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00571330
bool TToggleButton::IsSelected() {
  return IsActionable();
}

// FUNCTION: IMPERIALISM 0x00571350
void TToggleButton::Select(bool isPressed, bool notifyParent) {
  Show(static_cast<char>(isPressed), static_cast<char>(notifyParent));
  if (static_cast<char>(isPressed) != '\0') {
    // The owner panel is a TCluster; notify it which child tag is now active (slot 0x72).
    static_cast<TCluster*>(ownerContext)->SetCurrentChoice(controlTag);
  }
  PrepareForDrawing();
  PaintOrInvalidateControl(0);
}
