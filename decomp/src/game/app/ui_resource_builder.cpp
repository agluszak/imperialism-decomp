#include "game/ui_core/TWindow.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/app/ui_resource_builder.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0041b210
void __cdecl RegisterUiResourceEntry(unsigned int nameTag, unsigned int controlTag, TView* widget,
                                     int offsetX, int offsetY, int width, int height,
                                     int stateValue, int enabledState, unsigned int ownerTag,
                                     int field3cValue) {

  TView* parent;
  g_pUiResourceContext = widget;
  if (g_pUiResourceHead != 0) {
    const CList<TView*, TView*>& buildStack = g_UiWidgetBuildStack;
    parent = buildStack.GetTail();
  } else {
    g_pUiResourceHead = widget;
    parent = 0;
  }
  g_UiWidgetBuildStack.AddTail(widget);

  int offsetLayout[2];
  int sizeLayout[2];
  offsetLayout[0] = offsetX;
  offsetLayout[1] = offsetY;
  sizeLayout[0] = width;
  sizeLayout[1] = height;
  widget->InitializeUiResourceEntryFrameAndParent(0, parent, offsetLayout, sizeLayout, 0, 0, 1);
  widget->controlTag = static_cast<int>(controlTag);
  widget->controlValue = field3cValue;
  widget->Show(enabledState, 0);
  widget->ViewEnable(stateValue, 0);
}

// FUNCTION: IMPERIALISM 0x0041b3a0
void __cdecl SetUiResourceStateFlags(bool inputGateFlag, bool childHitTestFlag) {
  TView* context = g_pUiResourceContext;
  context->inputGateFlag = inputGateFlag;
  context->childHitTestFlag = childHitTestFlag;
}

// FUNCTION: IMPERIALISM 0x0041b3d0
void __cdecl SetUiResourceContextPictureId(int nPictureId) {
  static_cast<TPicture*>(g_pUiResourceContext)->SetPictureRsrcID(static_cast<short>(nPictureId), 0);
}

// FUNCTION: IMPERIALISM 0x0041b400
void __cdecl SetUiResourceContextStringCode(int nCode) {
  static_cast<TCluster*>(g_pUiResourceContext)->selectedChildTag = nCode;
}

// FUNCTION: IMPERIALISM 0x0041b420
TUiStyleBytes* TUiStyleBytes::Reset() {
  packedColor = 0;
  styleWord = 0;
  return this;
}

// FUNCTION: IMPERIALISM 0x0041b450
void __cdecl SetUiResourceEventNumberAndInsets(int eventNumber, int rectLeft, int rectTop,
                                               int rectRight, int rectBottom) {
  TControl* context = static_cast<TControl*>(g_pUiResourceContext);
  context->eventNumber = eventNumber;
  CRect contentInsets(rectLeft, rectTop, rectRight, rectBottom);
  context->contentInsets = contentInsets;
}

// FUNCTION: IMPERIALISM 0x0041b490
void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, const char* szText, short nMode,
                                        short nFlag, short nPointSize, TUiStyleRef styleRef,
                                        short nThemeCode) {

  TStaticText* context = static_cast<TStaticText*>(g_pUiResourceContext);
  {
    CString text(szText);
    context->SetTextAndMaybeRefresh(&text, false);
  }
  TextStyle style;
  style.fontFamily = nMode;
  style.fontStyleFlags = nFlag;
  style.fontSize = nPointSize;
  style.textColor = styleRef.value;
  context->InstallTextStyle(style, 0);
  context->SetJustification(nThemeCode, false);
}

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
  g_UiWidgetBuildStack.RemoveTail();
}

// FUNCTION: IMPERIALISM 0x00426f80
void __cdecl UiResourceBuildCallback() {}

// FUNCTION: IMPERIALISM 0x00426fa0
void __cdecl SetUiResourceContextFlagsAndMetrics(short nField9C, short nStyleType, bool f70,
                                                 bool f6f, bool f6e, bool f6d, bool f6c, bool f71) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->topmostFlag = f70;
  window->resourceFlag6f = f6f;
  window->resourceFlag6e = f6e;
  window->useCaptionedFrameFlag = f6d;
  window->resourceFlag6c = f6c;
  window->resourceFlag = f71;
  window->windowFlags = static_cast<unsigned short>(nField9C);
  window->windowStyleType = nStyleType;
}

// FUNCTION: IMPERIALISM 0x00427010
void __cdecl ApplyUiResourceColorTripletFromContext(bool nFlag0C, bool nTripletFlag, int colorA,
                                                    int colorB) {
  TWindow* window = static_cast<TWindow*>(g_pUiResourceContext);
  window->GetDialogBehavior()->SetEnabled(nFlag0C);
  window->GetDialogBehavior()->IDialogBehavior(nTripletFlag, colorA, colorB);
}

// FUNCTION: IMPERIALISM 0x00427060
void __cdecl ReplaceUiResourceContextPairBuffer(int styleWord, int packedColor) {
  TView* context = g_pUiResourceContext;
  delete context->stylePayload;
  context->stylePayload = new TUiStyleBytes();
  context->stylePayload->styleWord = styleWord;
  context->stylePayload->packedColor = packedColor;
}

// FUNCTION: IMPERIALISM 0x004270e0
TUiStyleRef::TUiStyleRef(int value) {
  this->value = value;
}

// FUNCTION: IMPERIALISM 0x00479e10
int __stdcall ClearUiResourceEntryDwords(int* destination, int count) {
  while (count != 0) {
    *destination = 0;
    ++destination;
    --count;
  }
  return 0;
}
