// Manual decompilation file.

#include "game/TStaticText.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
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
    TControl* panel, int* offsetLayout, int* sizeLayout, int layoutParam6, int layoutParam7,
    short stringResourceGroup, short stringResourceIndex) {
  (void)layoutParam6;
  (void)layoutParam7;
  if (panel != 0) {
    nativeWindow50 = panel->nativeWindow50;
  }
  controlTag = 0x20202020;
  field04 = 1;
  field08 = 1;
  field0c = reinterpret_cast<int>(panel);
  ownerOffsetX = offsetLayout[0];
  ownerOffsetY = offsetLayout[1];
  field34 = sizeLayout[0];
  field38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  resourceTemplateId40 = 0;
  SetCityProductionDialogPictureRectAndMaybeRefresh(
      reinterpret_cast<TControlPictureRectState*>(&g_nUiResourceEntryDefaultParam0), 0);
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
  if (CompareAnsiStringsWithMbcsAwareness(
          reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(*sharedString)),
          reinterpret_cast<unsigned char*>((char*)static_cast<LPCSTR>(*text))) != 0) {
    *text = *sharedString;
    if (refreshNow != 0) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048fed0
void TStaticText::LoadUiStringAndDispatchViaVslot1C8(short stringResourceGroup,
                                                     short stringResourceIndex) {
  CString loadedString;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&loadedString, stringResourceGroup,
                                                                  stringResourceIndex);
  AssignTextSharedRefIfChangedAndMaybeInvalidate(&loadedString, 0);
}

// FUNCTION: IMPERIALISM 0x0048ff70
void TStaticText::SetTextThemeCodeAndMaybeRefresh(short themeCode, char refreshFlag) {
  field90 = themeCode;
  if (refreshFlag != 0) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048ffb0
void TStaticText::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x004900a0
void TStaticText::RenderControlStateTextBySelectionCode(RECT* rect) {
  // TODO(manifest): real body (273 bytes) dispatches through the same
  // unidentified quickdraw-context object as ApplyRectSlot110 (slots +0x30
  // and +0x38, plus a draw call at +0x70 with a palette-index selected from
  // field90 — the same 0x910/0x911/0x912 switch seen in ApplyRectSlot110),
  // offsetting `rect` by (field2c, field30) before drawing. See
  // imperialism-decomp-855 (text-widget ApplyRectSlot110 paint family) for
  // the shared class-recovery blocker; left unimplemented rather than guessed.
  (void)rect;
}
