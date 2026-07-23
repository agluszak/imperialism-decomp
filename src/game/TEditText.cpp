#include "game/TEditText.h"
#include <mbstring.h>
#include "game/CMcWindow.h"
#include "game/TObject.h"
// SYNTHETIC: IMPERIALISM 0x00490210
// TEditText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00490380
// TEditText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEditText, TStaticText)

// FUNCTION: IMPERIALISM 0x004903a0
TEditText::TEditText() : TStaticText() {
  this->eventNumber60 = 13;
  this->editWindow = nullptr;
  this->editFont = nullptr;
  this->maxCharacterCount = 0xff;
  this->childHitTestFlag4d = 0;
}

// FUNCTION: IMPERIALISM 0x004904d0
TEditText::~TEditText() {
  if (this->editWindow != nullptr) {
    delete this->editWindow;
    this->editWindow = nullptr;
  }
  if (this->editFont != nullptr) {
    delete this->editFont;
    this->editFont = nullptr;
  }
  // `text` is freed by the inherited TStaticText::~TStaticText() base
  // destructor (the original inlines that base cleanup into this same
  // function; our real-inheritance model calls it via chaining instead).
}

// Releases the live edit CWnd and cached font in that order — shared by Free() below.
// FUNCTION: IMPERIALISM 0x00490650
void TEditText::Close() {
  if (editWindow != nullptr) {
    delete editWindow;
    editWindow = nullptr;
    if (editFont != nullptr) {
      delete editFont;
    }
    editFont = nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x004906a0
void TEditText::Draw(RECT* rectBuffer) {
  // The retail body calls Open() (which lazily constructs the
  // live-edit CWnd into editWindow the first time this control paints) and falls back to
  // the static text draw only while that CWnd doesn't exist yet. Open
  // itself is still a stub (pending the real CWnd/dialog-template machinery), so editWindow
  // never gets constructed here -- this always takes the static-text fallback for now, which
  // is still strictly better than drawing nothing.
  if (Open() == nullptr) {
    TStaticText::Draw(rectBuffer);
  }
}

// FUNCTION: IMPERIALISM 0x004906d0
char TEditText::IsEnabled() {
  return static_cast<char>(field04);
}

// FUNCTION: IMPERIALISM 0x004906f0
void TEditText::SetEnable(unsigned char enabled) {
  field04 = enabled;
  if (editWindow != nullptr) {
    editWindow->EnableWindow(enabled);
    return;
  }
  TEditText::Open();
}

// FUNCTION: IMPERIALISM 0x00490730
void TEditText::SetEnabled(int enabledState, int refreshFlag) {
  if (enabledState != field08) {
    field08 = enabledState;
    if (refreshFlag != 0) {
      RefreshControl();
    }
    if (editWindow != nullptr) {
      editWindow->ShowWindow(field08 != 0 ? 5 : 0);
      return;
    }
    TEditText::Open();
  }
}

// FUNCTION: IMPERIALISM 0x004907a0
CMcWindow* TEditText::Open() {
  // The retail body constructs the live edit CWnd (editWindow) on demand through a
  // modal-dialog-style CreateWindowEx path when nativeWindow50, field04, and controlTag/field50
  // preconditions hold. It remains unported pending the real CWnd/dialog-template machinery.
  return editWindow;
}

// FUNCTION: IMPERIALISM 0x00490a50
void TEditText::SetEditSelectionAndScrollCaret(short selStart, short selEnd, int unusedFlag) {
  (void)unusedFlag;
  if (editWindow != nullptr) {
    editWindow->SendMessage(0xb1, selStart, selEnd);
    editWindow->SendMessage(0xb7, 0, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00490aa0
char TEditText::BecomeTarget() {
  if (editWindow != nullptr) {
    editWindow->SetFocus();
  }
  return 1;
}

// Shared tail with Close (editWindow/editFont release), then the
// generic TView::Free() body (child list drain, owner detach, active-view
// handoff, linkedResourceOwner release, delete this).
// FUNCTION: IMPERIALISM 0x00490ad0
void TEditText::Free() {
  if (editWindow != nullptr) {
    delete editWindow;
    editWindow = nullptr;
    if (editFont != nullptr) {
      delete editFont;
    }
    editFont = nullptr;
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00490bc0
char TEditText::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (TView::HandleMouseDown(point, event, origin) == 0) {
    return 0;
  }
  HandleEvent(eventNumber60, this, 0);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00490c10
void TEditText::TargetValidationSucceeded() {
  if (editWindow != nullptr) {
    editWindow->SetFocus();
  }
}

// FUNCTION: IMPERIALISM 0x00490c30
void TEditText::SelectOwner(unsigned char select) {
  if (editWindow != nullptr) {
    editWindow->SetFocus();
  }
  SetEditSelectionAndScrollCaret(0, 0x7fff, select);
}

// FUNCTION: IMPERIALISM 0x00490c70
void TEditText::GetCurrentText(CString* out) {
  if (editWindow != nullptr) {
    editWindow->GetWindowText(*out);
    return;
  }
  *out = *text;
}

// FUNCTION: IMPERIALISM 0x00490cb0
void TEditText::SetTextAlignmentAndMaybeRefresh(short alignmentCode, char refreshFlag) {
  textAlignmentCode = alignmentCode;
  if (refreshFlag != 0) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x00490cf0
void TEditText::InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag) {
  CString clampedText(*newText);
  if (clampedText.GetLength() > maxCharacterCount) {
    clampedText = clampedText.Left(maxCharacterCount);
  }
  if (Open() != 0) {
    editWindow->SetWindowText(clampedText);
    return;
  }
  if (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(*text)),
              reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(clampedText))) != 0) {
    *text = clampedText;
    if (static_cast<char>(refreshFlag) != 0) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00490e50
void TEditText::UpdateCoordinates() {
  TView::Open();
  if (editWindow != nullptr) {
    RECT clientRect;
    GetClientRect(editWindow->m_hWnd, &clientRect);
    if (clientRect.left != absoluteX || clientRect.top != absoluteY) {
      editWindow->SetWindowPos(0, absoluteX, absoluteY, 0, 0, 0x215);
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00492f30
// TEditText::`scalar deleting destructor'
