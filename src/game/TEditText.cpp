#include "game/TEditText.h"
#include "game/CMcWindow.h"
#include "game/TObject.h"
// SYNTHETIC: IMPERIALISM 0x00490210
// TEditText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00490380
// TEditText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEditText, TStaticText)

// FUNCTION: IMPERIALISM 0x004903a0
TEditText::TEditText() : TStaticText() {
  this->frameStyle60 = 13;
  this->field_94 = nullptr;
  this->field_98 = nullptr;
  this->field_9c = 0xff;
  this->childHitTestFlag4d = 0;
}

// FUNCTION: IMPERIALISM 0x004904d0
TEditText::~TEditText() {
  if (this->field_94 != nullptr) {
    delete this->field_94;
    this->field_94 = nullptr;
  }
  if (this->field_98 != nullptr) {
    delete this->field_98;
    this->field_98 = nullptr;
  }
  // `text` is freed by the inherited TStaticText::~TStaticText() base
  // destructor (the original inlines that base cleanup into this same
  // function; our real-inheritance model calls it via chaining instead).
}

// Releases the live edit CWnd (field_94) and cached font/style resource
// (field_98) via virtual-dtor dispatch, in that order — shared by Free() below.
// FUNCTION: IMPERIALISM 0x00490650
void TEditText::CallVoidSlotA0() {
  if (field_94 != nullptr) {
    delete field_94;
    field_94 = nullptr;
    if (field_98 != nullptr) {
      delete field_98;
    }
    field_98 = nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x004906a0
void TEditText::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  // The retail body dispatches on DispatchSlot9CToLinkedChildren() to choose between the
  // live-edit-window path and TStaticText::ApplyRectSlot110(rectBuffer). The dialog-creation
  // dependency below is still unported, so this body remains incomplete.
}

// FUNCTION: IMPERIALISM 0x004906d0
char TEditText::GetBoolSlot28() {
  return static_cast<char>(field04);
}

// FUNCTION: IMPERIALISM 0x004906f0
void TEditText::SetControlValue(int value) {
  field04 = value;
  if (field_94 != nullptr) {
    field_94->EnableWindow(value);
    return;
  }
  TEditText::DispatchSlot9CToLinkedChildren();
}

// FUNCTION: IMPERIALISM 0x00490730
void TEditText::SetEnabled(int enabledState, int refreshFlag) {
  if (enabledState != field08) {
    field08 = enabledState;
    if (refreshFlag != 0) {
      RefreshControl();
    }
    if (field_94 != nullptr) {
      field_94->ShowWindow(field08 != 0 ? 5 : 0);
      return;
    }
    TEditText::DispatchSlot9CToLinkedChildren();
  }
}

// FUNCTION: IMPERIALISM 0x004907a0
void TEditText::DispatchSlot9CToLinkedChildren() {
  // The retail body constructs the live edit CWnd (field_94) on demand through a
  // modal-dialog-style CreateWindowEx path when nativeWindow50, field04, and controlTag/field50
  // preconditions hold. It remains unported pending the real CWnd/dialog-template machinery.
}

// FUNCTION: IMPERIALISM 0x00490a50
void TEditText::SetEditSelectionAndScrollCaret(short selStart, short selEnd, int unusedFlag) {
  (void)unusedFlag;
  if (field_94 != nullptr) {
    field_94->SendMessage(0xb1, selStart, selEnd);
    field_94->SendMessage(0xb7, 0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00490aa0
char TEditText::ActivateCityProductionViewIfAllowed() {
  if (field_94 != nullptr) {
    field_94->SetFocus();
  }
  return 1;
}

// Shared tail with CallVoidSlotA0 (field_94/field_98 release), then the
// generic TView::Free() body (child list drain, owner detach, active-view
// handoff, linkedResourceOwner release, delete this).
// FUNCTION: IMPERIALISM 0x00490ad0
void TEditText::Free() {
  if (field_94 != nullptr) {
    delete field_94;
    field_94 = nullptr;
    if (field_98 != nullptr) {
      delete field_98;
    }
    field_98 = nullptr;
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00490bc0
char TEditText::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  // The retail body forwards to the base TView mouse-move dispatch and, on success, fires a
  // command event through a receiver/slot that is not yet recovered. This fallback remains an
  // incomplete stub rather than guessing that dispatch.
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00490c10
void TEditText::HandleCityProductionNoOp() {
  if (field_94 != nullptr) {
    field_94->SetFocus();
  }
}

// FUNCTION: IMPERIALISM 0x00490c30
void TEditText::vmethod_0081(int param_1) {
  if (field_94 != nullptr) {
    field_94->SetFocus();
  }
  SetEditSelectionAndScrollCaret(0, 0x7fff, param_1);
}

// FUNCTION: IMPERIALISM 0x00490c70
void TEditText::GetCurrentText(CString* out) {
  if (field_94 != nullptr) {
    field_94->GetWindowText(*out);
    return;
  }
  *out = *text;
}

// FUNCTION: IMPERIALISM 0x00490cb0
void TEditText::SetTextThemeCodeAndMaybeRefresh(short themeCode, char refreshFlag) {
  field90 = themeCode;
  if (refreshFlag != 0) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x00490cf0
void TEditText::InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag) {
  // The retail body truncates *newText to field_9c, then either updates the live edit window or
  // compares against the cached text and refreshes on change. The live/cached branch depends on
  // DispatchSlot9CToLinkedChildren(), so this body remains incomplete.
  (void)newText;
  (void)refreshFlag;
}

// FUNCTION: IMPERIALISM 0x00490e50
void TEditText::RecomputeAbsolutePositionRecursive() {
  TView::DispatchSlot9CToLinkedChildren();
  if (field_94 != nullptr) {
    RECT clientRect;
    GetClientRect(field_94->m_hWnd, &clientRect);
    if (clientRect.left != absoluteX || clientRect.top != absoluteY) {
      field_94->SetWindowPos(0, absoluteX, absoluteY, 0, 0, 0x215);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00492f30
// TEditText::`scalar deleting destructor'
