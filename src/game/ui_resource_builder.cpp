#include "game/ui_resource_builder.h"

#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TEditText.h"
#include "game/TNumberText.h"
#include "game/TPicture.h"
#include "game/TStaticText.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0041b210
void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag, TView* widget,
                                     int offsetX, int offsetY, int width, int height,
                                     int stateValue, int enabledState, unsigned int ownerTag,
                                     int field3cValue) {
  (void)nameTag;
  (void)ownerTag;

  TView* parent;
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    parent = g_UiWidgetBuildStack006a13e0.GetTail();
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  g_UiWidgetBuildStack006a13e0.AddTail(widget);

  int offsetLayout[2];
  int sizeLayout[2];
  offsetLayout[0] = offsetX;
  offsetLayout[1] = offsetY;
  sizeLayout[0] = width;
  sizeLayout[1] = height;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offsetLayout, sizeLayout, 0, 0, 1);
  widget->controlTag = static_cast<int>(controlTag);
  widget->controlValue3c = field3cValue;
  widget->SetEnabled(enabledState, 0);
  widget->SetState(stateValue, 0);
}

// FUNCTION: IMPERIALISM 0x0041b3a0
void __cdecl SetUiResourceStateFlags(bool inputGateFlag4c, bool childHitTestFlag4d) {
  TView* context = g_pUiResourceContext;
  context->inputGateFlag4c = inputGateFlag4c;
  context->childHitTestFlag4d = childHitTestFlag4d;
}

// FUNCTION: IMPERIALISM 0x0041b3d0
void __cdecl SetUiResourceContextPictureId(int nPictureId) {
  static_cast<TPicture*>(g_pUiResourceContext)
      ->SetPictureResourceIdAndRefresh(static_cast<short>(nPictureId), 0);
}

// FUNCTION: IMPERIALISM 0x0041b400
void __cdecl SetUiResourceContextStringCode(int nCode) {
  static_cast<TCluster*>(g_pUiResourceContext)->selectedChildTag = nCode;
}

// FUNCTION: IMPERIALISM 0x0041b420
TUiStyleBytes* TUiStyleBytes::Reset() {
  styleBytes[0] = 0;
  styleBytes[1] = 0;
  styleBytes[2] = 0;
  styleBytes[3] = 0;
  styleBytes[4] = 0;
  styleBytes[5] = 0;
  styleBytes[6] = 0;
  styleBytes[7] = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x0041b450
void __cdecl SetUiResourceEventNumberAndInsets(int eventNumber, int rectLeft, int rectTop,
                                               int rectRight, int rectBottom) {
  TControl* context = static_cast<TControl*>(g_pUiResourceContext);
  context->eventNumber60 = eventNumber;
  context->contentInsets68.left = rectLeft;
  context->contentInsets68.top = rectTop;
  context->contentInsets68.right = rectRight;
  context->contentInsets68.bottom = rectBottom;
}

// Bind a text + style onto the current g_pUiResourceContext text control: assign the
// shared string, then apply a packed style descriptor and the theme code. nGroupId and
// nVariant are present at every call site but unused by the body (signature fidelity,
// like RegisterUiResourceEntry's tags).
// FUNCTION: IMPERIALISM 0x0041b490
void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, const char* szText, short nMode,
                                        short nFlag, short nPointSize, TUiStyleRef styleRef,
                                        short nThemeCode) {
  (void)nGroupId;
  (void)nVariant;

  TStaticText* context = static_cast<TStaticText*>(g_pUiResourceContext);
  {
    CString text(szText);
    context->SetTextAndMaybeRefresh(&text, 0);
  }
  TextStyle style;
  style.fontFamily = nMode;
  style.fontStyleFlags = nFlag;
  style.fontSize = nPointSize;
  style.textColor = styleRef.value;
  context->InstallTextStyle(style, 0);
  context->SetTextAlignmentAndMaybeRefresh(nThemeCode, 0);
}

// Set the current context edit control's max-character-count word (+0x9c).
// FUNCTION: IMPERIALISM 0x0041b570
void __cdecl SetUiResourceContextMaxCharCount(short maxChars) {
  TEditText* context = static_cast<TEditText*>(g_pUiResourceContext);
  context->AssertValid();
  context->maxCharacterCount = maxChars;
}

// FUNCTION: IMPERIALISM 0x0041b5a0
void __cdecl SetUiResourceContextNumberValueAndRange(int value, int minValue, int maxValue) {
  TNumberText* context = static_cast<TNumberText*>(g_pUiResourceContext);
  context->AssertValid();
  context->maximumValue = maxValue;
  context->minimumValue = minValue;
  context->SetControlValue(value, 0);
}

// FUNCTION: IMPERIALISM 0x0041b5f0
void __cdecl ClearUiResourceContext() {
  g_pUiResourceContext = 0;
}

// FUNCTION: IMPERIALISM 0x0041b610
void __cdecl PopUiResourcePoolNode(unsigned int nameTag) {
  (void)nameTag;
  // CList::RemoveTail -> FreeNode already performs the on-empty RemoveAll teardown
  // (walk + CPlex::FreeDataChain + member zeroing) — do not repeat it here.
  g_UiWidgetBuildStack006a13e0.RemoveTail();
}

// 0x479a80 / 0x479b00 ("Pop/PushUiResourcePoolNode") are the out-of-line template COMDATs
// of CList<TView*,TView*>::RemoveTail / ::AddTail operating on g_UiWidgetBuildStack006a13e0
// - see global_data_tables.h. The builders call them directly
// (g_UiWidgetBuildStack006a13e0.RemoveTail()/.AddTail(node)); claimed here as templates.

// TEMPLATE: IMPERIALISM 0x00479a80
// ?RemoveTail@?$CList@PAVTView@@PAV1@@@QAEPAVTView@@XZ

// The builder TU emits two identical AddTail COMDATs. 0x426ec0 is reached by the
// early giant dialog builders; 0x479b00 is the later copy used by the shared stack helpers.
// TEMPLATE: IMPERIALISM 0x00426ec0
// TEMPLATE: IMPERIALISM 0x00479b00
// ?AddTail@?$CList@PAVTView@@PAV1@@@QAEPAU__POSITION@@PAVTView@@@Z

template TView* CList<TView*, TView*>::RemoveTail();
template POSITION CList<TView*, TView*>::AddTail(TView*);
