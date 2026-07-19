// Manual decompilation file.

#include "game/TStaticText.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

#include "game/UiRuntimeContext.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_rendering.h"
#include "game/mfc.h"
#include <new>
// FUNCTION: IMPERIALISM 0x004294d0
void TStaticText::AssignSharedStringFromField84(CString* out) {
  *out = *text;
}

// MFC RTTI slot 0x00 override: return this class's CRuntimeClass descriptor (0x649678).
// 0x48f710 is the IMPLEMENT_DYNCREATE-generated CreateObject (was previously modeled as
// a banned free-function factory; retired in favor of the macro's real static).
// SYNTHETIC: IMPERIALISM 0x0048f710
// TStaticText::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048f870
// TStaticText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TStaticText, TControl)

// FUNCTION: IMPERIALISM 0x00486290
void TStaticText::UpdateTextEntrySharedStringIfChanged(CString* text) {
  TStaticText::AssignTextSharedRefIfChangedAndMaybeInvalidate(text, 0);
}

// FUNCTION: IMPERIALISM 0x0048F890
TStaticText::TStaticText()
    : TControl(), text(new CString()), field88((void*)0xffffffff), field8C(0), field90(0) {
  hasCommandTagResource = 13;
}

// Destructors are compiler-generated (implicit) from real inheritance; the
// `text` CString member's real destructor makes this non-trivial, so MSVC
// emits it as its own out-of-line complete-object destructor (0x48fc30, 146
// bytes) in addition to the vtable-slot scalar deleting destructor (0x48f9a0)
// — same pattern as heuristic #39 (TFuzzySet/TFuzzyVar dtor split). It was
// still being served by a dummy autogen stub before this claim.
// SYNTHETIC: IMPERIALISM 0x0048f9a0
// TStaticText::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x0048fc30
// TStaticText::~TStaticText

TStaticText::~TStaticText() {
  delete text;
}

// FUNCTION: IMPERIALISM 0x0048fb10
void TStaticText::CopyViewStateFromSource(TView* source) {
  TView::CopyViewStateFromSource(source);
  TStaticText* src = static_cast<TStaticText*>(source);
  this->hasCommandTagResource = src->hasCommandTagResource;
  this->commandTagResourceByte = src->commandTagResourceByte;
  this->field68 = src->field68;
  this->field6C = src->field6C;
  this->field70 = src->field70;
  this->field74 = src->field74;
  this->commandTagDefaultParam0 = src->commandTagDefaultParam0;
  this->commandTagDefaultParam1 = src->commandTagDefaultParam1;
  this->commandTagDefaultParam2 = src->commandTagDefaultParam2;
  this->text = new CString();
  *this->text = *src->text;
}

// FUNCTION: IMPERIALISM 0x0048fc00
TObject* TStaticText::ShallowClone() {
  TObject* cloned = this->ShallowFree();
  if (cloned != 0) {
    static_cast<TStaticText*>(cloned)->CopyViewStateFromSource(this);
  }
  return cloned;
}

// FUNCTION: IMPERIALISM 0x0048fd00
void TStaticText::InitializeTextEntryBaseAndOptionalStringResource(
    TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam6, int layoutParam7,
    short stringResourceGroup, short stringResourceIndex) {
  (void)layoutParam6;
  (void)layoutParam7;
  if (panel != 0) {
    nativeWindow50 = panel->nativeWindow50;
  }
  controlTag = 0x20202020;
  field04 = 1;
  field08 = 1;
  linkedChildHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth34 = sizeLayout[0];
  frameHeight38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  resourceTemplateId40 = 0;
  SetCityProductionDialogPictureRectAndMaybeRefresh(&g_UiResourceEntryDefaultTextStyle, 0);
  field88 = reinterpret_cast<void*>(static_cast<int>(stringResourceGroup));
  field8C = stringResourceIndex;
  if (stringResourceGroup != -1) {
    CString loadedString;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
        &loadedString, stringResourceGroup, stringResourceIndex);
    AssignTextSharedRefIfChangedAndMaybeInvalidate(&loadedString, 0);
  }
  HandleCursorHoverFallback(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048fe60
void TStaticText::AssignTextSharedRefIfChangedAndMaybeInvalidate(CString* sharedString,
                                                                 char refreshNow) {
  if (_mbscmp(reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(*sharedString)),
              reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(*text))) != 0) {
    *text = *sharedString;
    if (refreshNow != 0) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048fed0
void TStaticText::LoadUiStringAndDispatchViaVslot1C8(short stringResourceGroup,
                                                     short stringResourceIndex, char refreshNow) {
  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
      &loadedString, stringResourceGroup, stringResourceIndex);
  AssignTextSharedRefIfChangedAndMaybeInvalidate(&loadedString, refreshNow);
}

// FUNCTION: IMPERIALISM 0x0048ff70
void TStaticText::SetTextThemeCodeAndMaybeRefresh(short themeCode, char refreshFlag) {
  field90 = themeCode;
  if (refreshFlag != 0) {
    PaintOrInvalidateControl(0);
  }
}

// Paint the static text through the active QuickDraw CDC: aspect-filtered font
// mapping, cached CFont from the widget's packed text style, text color from the
// optional stylePayload48 payload (else the style's styleRef), and CDC::DrawText with the
// field90 alignment code (-2 left / 1 center / -1 right on DT_NOPREFIX|0x100|
// DT_WORDBREAK).
// FUNCTION: IMPERIALISM 0x0048ffb0
void TStaticText::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  CDC* dc = GetActiveQuickDrawDc();
  dc->SetBkMode(TRANSPARENT);
  RECT bounds;
  BuildRectFromSlot158(&bounds);
  // The original calls the CRect::DeflateRect(LPCRECT) COMDAT (0x61f342) on the
  // 0x68-0x74 inset region; the four ints are open-coded here because the insets are
  // modeled as separate fields.
  bounds.left += field68;
  bounds.top += field6C;
  bounds.right -= field70;
  bounds.bottom -= field74;
  CFont* font = UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(&textStyle78);
  CFont* oldFont = dc->SelectObject(font);
  COLORREF textColor;
  if (stylePayload48 == 0) {
    textColor = textStyle78.styleRef6;
  } else {
    textColor = stylePayload48->styleWord;
  }
  dc->SetTextColor(textColor);
  UINT format = 0x910;
  if (field90 != -2) {
    if (field90 == -1) {
      format = 0x912;
    } else if (field90 == 1) {
      format = 0x911;
    }
  }
  dc->DrawText(*text, text->GetLength(), &bounds, format);
  dc->SelectObject(oldFont);
}

// FUNCTION: IMPERIALISM 0x004900a0
void TStaticText::RenderControlStateTextBySelectionCode(const char* textChars, int textLength,
                                                        RECT* rect, short alignmentCode) {
  (void)textLength;
  CDC* dc = GetActiveQuickDrawDc();
  dc->SetBkMode(TRANSPARENT);
  CFont* font = UpdateGlobalFontPresetAndRebuildCachedFontIfDirty(&textStyle78);
  CFont* oldFont = dc->SelectObject(font);
  dc->SetTextColor(g_Quick_Draw_Color_State_006950FC);
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
