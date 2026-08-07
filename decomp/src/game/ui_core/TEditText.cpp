#include "game/ui_core/TEditText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include <mbstring.h>
#include "game/ui_core/CMcEditWindow.h"
#include "game/app/TObject.h"
#include "game/pointer_representation.h"
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

// FUNCTION: IMPERIALISM 0x004905e0
void TEditText::IEditText(TView* panel, int* offsetLayout, int* sizeLayout,
                          short maximumCharacterCount) {
  IStaticText(panel, offsetLayout, sizeLayout, 5, 5, -1, 0);
  maxCharacterCount = maximumCharacterCount;
  SetEnable(1);
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
  // Open() lazily creates the live edit control the first time this paints; the static
  // text draw is only the fallback for a control that cannot host one.
  // Explicitly qualified: 0x004906a3 is a direct CALL to TEditText::Open, not a dispatch
  // through slot 0x27 (byte 0x9c). An unqualified Open() here compiles to the virtual call.
  if (TEditText::Open() == nullptr) {
    TStaticText::Draw(rectBuffer);
  }
}

// FUNCTION: IMPERIALISM 0x004906d0
char TEditText::IsEnabled() {
  return static_cast<char>(enabled);
}

// FUNCTION: IMPERIALISM 0x004906f0
void TEditText::SetEnable(char enabled) {
  this->enabled = enabled;
  if (editWindow != nullptr) {
    editWindow->EnableWindow(enabled);
    return;
  }
  TEditText::Open();
}

// FUNCTION: IMPERIALISM 0x00490730
void TEditText::Show(int enabledState, int refreshFlag) {
  if (enabledState != viewEnabled) {
    viewEnabled = enabledState;
    if (refreshFlag != 0) {
      RefreshControl();
    }
    if (editWindow != nullptr) {
      editWindow->ShowWindow(viewEnabled != 0 ? 5 : 0);
      return;
    }
    TEditText::Open();
  }
}

// FUNCTION: IMPERIALISM 0x004907a0
CWnd* TEditText::Open() {
  if (editWindow == 0 && viewEnabled != 0 && enabled != 0 && nativeWindow50 != 0) {
    // The original allocates 0x3c bytes and stores the 0x0064afd8 vtable — the
    // dedicated edit-host class, not CMcWindow (0x0064b7c8) and not the plain
    // CWnd the base ctor writes.
    editWindow = new CMcEditWindow;
    if (editWindow == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(g_szMcAppUiSourcePath_006950B0, 0xdee);
    }

    // ES_LEFT / ES_CENTER / ES_RIGHT follow the static text's own alignment code.
    DWORD editStyle = 0x44010004;
    if (textAlignmentCode == -1) {
      editStyle = 0x44010006;
    } else if (textAlignmentCode == 1) {
      editStyle = 0x44010005;
    }
    editStyle |= WS_BORDER;
    if (IsActionable()) {
      editStyle |= WS_VISIBLE;
    }
    if (IsEnabled() == 0) {
      editStyle |= WS_DISABLED;
    }

    CRect editBounds;
    // Qualified: CEdit's 4-argument Create hides the generic CWnd surface, and
    // the original makes a direct (non-virtual) call here.
    editWindow->CWnd::Create("EDIT", 0, editStyle, *GetQDExtent(&editBounds), nativeWindow50,
                             static_cast<UINT>(controlTag));

    editFont = CreateFontFromPresetAndAttachRegionHandle(&textStyle78);
    ::SendMessageA(editWindow->m_hWnd, WM_SETFONT,
                   reinterpret_cast<DWORD>(editFont != 0 ? editFont->m_hObject : 0), 0);
    if (text != 0 && text->GetLength() != 0) {
      editWindow->SetWindowText(*text);
    }
    editWindow->ModifyStyleEx(0, WS_EX_CLIENTEDGE, 0);
    nativeWindow50->ModifyStyle(WS_CLIPCHILDREN, 0, 0);
    ::SetWindowLongA(editWindow->m_hWnd, GWL_USERDATA, PointerAddressLong32(this));
    ::SendMessageA(editWindow->m_hWnd, EM_LIMITTEXT, maxCharacterCount, 0);
  }
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
  if (text->Compare(clampedText) != 0) {
    *text = clampedText;
    if (static_cast<char>(refreshFlag) != 0) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00490e50
void TEditText::UpdateCoordinates() {
  TView::UpdateCoordinates();
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
