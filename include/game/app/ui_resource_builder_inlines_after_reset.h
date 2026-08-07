#pragma once

#include "game/app/ui_resource_builder.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/ui_core_globals.h"

// FUNCTION: IMPERIALISM 0x0041b450
inline void __cdecl SetUiResourceEventNumberAndInsets(int eventNumber, int rectLeft, int rectTop,
                                                      int rectRight, int rectBottom) {
  TControl* context = static_cast<TControl*>(g_pUiResourceContext);
  context->eventNumber60 = eventNumber;
  CRect contentInsets(rectLeft, rectTop, rectRight, rectBottom);
  context->contentInsets68 = contentInsets;
}

// FUNCTION: IMPERIALISM 0x0041b490
inline void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, const char* szText,
                                               short nMode, short nFlag, short nPointSize,
                                               TUiStyleRef styleRef, short nThemeCode) {
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

// FUNCTION: IMPERIALISM 0x0041b570
inline void __cdecl SetUiResourceContextMaxCharCount(short maxChars) {
  TEditText* context = static_cast<TEditText*>(g_pUiResourceContext);
  context->AssertValid();
  context->maxCharacterCount = maxChars;
}

// FUNCTION: IMPERIALISM 0x0041b5a0
inline void __cdecl SetUiResourceContextNumberValueAndRange(int value, int minValue, int maxValue) {
  TNumberText* context = static_cast<TNumberText*>(g_pUiResourceContext);
  context->AssertValid();
  context->maximumValue = maxValue;
  context->minimumValue = minValue;
  context->SetControlValue(value, 0);
}

// FUNCTION: IMPERIALISM 0x0041b5f0
inline void __cdecl ClearUiResourceContext() {
  g_pUiResourceContext = 0;
}

// FUNCTION: IMPERIALISM 0x0041b610
inline void __cdecl PopUiResourcePoolNode(unsigned int nameTag) {
  (void)nameTag;
  g_UiWidgetBuildStack006a13e0.RemoveTail();
}
