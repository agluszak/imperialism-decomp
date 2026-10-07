
#include "game/ui_core/TStaticText.h"

#include <mbstring.h>
#include "game/ui_tags_common.h"
#include "game/gfx/TResourceMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/mfc.h"
#include <new>

// FUNCTION: IMPERIALISM 0x004294d0
void TStaticText::CopyTextTo(CString* out) {
  *out = *text;
}

IMPLEMENT_DYNCREATE(TStaticText, TControl)

// FUNCTION: IMPERIALISM 0x00486290
void TStaticText::SetText(CString* text) {
  TStaticText::SetTextAndMaybeRefresh(text, false);
}

// FUNCTION: IMPERIALISM 0x0048f890
TStaticText::TStaticText()
    : text(new CString()), stringResourceGroupId(-1), stringResourceIndex(0), textAlignmentCode(0),
      textOptionFlags(0) {
  eventNumber = 13;
}

// FUNCTION: IMPERIALISM 0x0048f9d0
TStaticText::TStaticText(const TStaticText& source)
    : TControl(source), text(0), stringResourceGroupId(source.stringResourceGroupId),
      stringResourceIndex(source.stringResourceIndex), textAlignmentCode(source.textAlignmentCode) {
  text = new CString();
  *text = *source.text;
}

TStaticText::~TStaticText() {
  delete text;
}

// FUNCTION: IMPERIALISM 0x0048fb10
void TStaticText::CopyViewStateFromSource(TView* source) {
  TView::CopyViewStateFromSource(source);
  TStaticText* src = static_cast<TStaticText*>(source);
  eventNumber = src->eventNumber;
  controlState = src->controlState;
  contentInsets = src->contentInsets;
  textStyle = src->textStyle;
  text = new CString();
  *text = *src->text;
}

// FUNCTION: IMPERIALISM 0x0048fc00
TObject* TStaticText::ShallowClone() {
  TObject* cloned = ShallowFree();
  if (cloned != 0) {
    static_cast<TStaticText*>(cloned)->CopyViewStateFromSource(this);
  }
  return cloned;
}

// FUNCTION: IMPERIALISM 0x0048fd00
void TStaticText::IStaticText(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam6,
                              int layoutParam7, short stringResourceGroup,
                              short stringResourceIndex) {
  if (panel != 0) {
    nativeWindow = panel->nativeWindow;
  }
  controlTag = kControlTagSpSpSpSp;
  enabled = 1;
  viewEnabled = 1;
  nextHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth = sizeLayout[0];
  frameHeight = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  resourceContext = 0;
  InstallTextStyle(g_UiResourceEntryDefaultTextStyle, 0);
  stringResourceGroupId = stringResourceGroup;
  this->stringResourceIndex = stringResourceIndex;
  if (stringResourceGroup != -1) {
    SetTextWithStrListID(stringResourceGroup, stringResourceIndex, false);
  }
  DoSetCursor(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048fe60
void TStaticText::SetTextAndMaybeRefresh(CString* sharedString, bool refreshNow) {
  if (sharedString->Compare(*text) != 0) {
    *text = *sharedString;
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048fed0
void TStaticText::SetTextWithStrListID(short stringResourceGroup, short stringResourceIndex,
                                       bool refreshNow) {
  CString loadedString;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&loadedString, stringResourceGroup,
                                                      stringResourceIndex);
  SetTextAndMaybeRefresh(&loadedString, refreshNow);
}

// FUNCTION: IMPERIALISM 0x0048ff70
void TStaticText::SetJustification(short alignmentCode, bool refreshFlag) {
  textAlignmentCode = alignmentCode;
  if (refreshFlag) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048ffb0
void TStaticText::Draw(RECT* rectBuffer) {
  CDC* dc = GetActiveQuickDrawDc();
  dc->SetBkMode(TRANSPARENT);
  CRect bounds;
  GetQDExtent(&bounds);
  bounds.DeflateRect(&contentInsets);
  CFont* font = UpdateFontPreset(&textStyle);
  CFont* oldFont = dc->SelectObject(font);
  COLORREF textColor;
  if (stylePayload == 0) {
    textColor = textStyle.textColor;
  } else {
    textColor = stylePayload->styleWord;
  }
  dc->SetTextColor(textColor);
  UINT format = 0x910;
  if (textAlignmentCode != -2) {
    if (textAlignmentCode == -1) {
      format = 0x912;
    } else if (textAlignmentCode == 1) {
      format = 0x911;
    }
  }
  dc->DrawText(*text, text->GetLength(), &bounds, format);
  dc->SelectObject(oldFont);
}

// FUNCTION: IMPERIALISM 0x004900a0
void TStaticText::ImageText(const char* textChars, int textLength, RECT* rect,
                            short alignmentCode) {
  CDC* dc = GetActiveQuickDrawDc();
  dc->SetBkMode(TRANSPARENT);
  CFont* font = UpdateFontPreset(&textStyle);
  CFont* oldFont = dc->SelectObject(font);
  dc->SetTextColor(g_QuickDrawForegroundColor);
  UINT format = 0x910;
  if (alignmentCode != -2) {
    if (alignmentCode == -1) {
      format = 0x912;
    } else if (alignmentCode == 1) {
      format = 0x911;
    }
  }
  RECT drawRect;
  drawRect.left = rect->left;
  drawRect.top = rect->top;
  drawRect.right = rect->right;
  drawRect.bottom = rect->bottom;
  OffsetRect(&drawRect, absoluteX, absoluteY);
  CString textCopy(textChars);
  dc->DrawText((LPCSTR)textCopy, textCopy.GetLength(), &drawRect, format);
  dc->SelectObject(oldFont);
}
