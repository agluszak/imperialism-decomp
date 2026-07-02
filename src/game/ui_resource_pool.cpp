#include "game/ui_resource_pool.h"

#include "game/TControl.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"

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
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
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
  widget->field3c = field3cValue;
  widget->SetEnabled(enabledState, 0);
  widget->SetState(stateValue, 0);
}

// FUNCTION: IMPERIALISM 0x0041b3a0
void __cdecl SetUiResourceStateFlags(unsigned char flag4c, unsigned char flag4d) {
  TView* context = g_pUiResourceContext;
  context->flag4c = flag4c;
  context->flag4d = flag4d;
}

// FUNCTION: IMPERIALISM 0x0041b420
unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer) {
  buffer[0] = 0;
  buffer[1] = 0;
  buffer[2] = 0;
  buffer[3] = 0;
  buffer[4] = 0;
  buffer[5] = 0;
  buffer[6] = 0;
  buffer[7] = 0;
  return buffer;
}

// FUNCTION: IMPERIALISM 0x0041b450
void __cdecl SetUiResourceLayoutValues(int frameStyle, int rectLeft, int rectTop, int rectRight,
                                       int rectBottom) {
  TControl* context = static_cast<TControl*>(g_pUiResourceContext);
  context->hasCommandTagResource = frameStyle;
  context->field68 = rectLeft;
  context->field6C = rectTop;
  context->field70 = rectRight;
  context->field74 = rectBottom;
}

// Bind a text + style onto the current g_pUiResourceContext text control: assign the
// shared string, then apply a packed style descriptor and the theme code. nGroupId and
// nVariant are present at every call site but unused by the body (signature fidelity,
// like RegisterUiResourceEntry's tags).
// FUNCTION: IMPERIALISM 0x0041b490
void __cdecl BindUiResourceTextAndStyle(int nGroupId, int nVariant, char* szText, short nMode,
                                        short nFlag, short nPointSize, int styleRef,
                                        short nThemeCode) {
  (void)nGroupId;
  (void)nVariant;

  TStaticText* context = static_cast<TStaticText*>(g_pUiResourceContext);
  {
    CString text(szText);
    context->AssignTextSharedRefIfChangedAndMaybeInvalidate(&text, 0);
  }
  TControlPictureRectState style;
  style.mode = nMode;
  style.flag2 = nFlag;
  style.pointSize = nPointSize;
  style.styleRef6 = styleRef;
  context->SetCityProductionDialogPictureRectAndMaybeRefresh(&style, 0);
  context->SetTextThemeCodeAndMaybeRefresh(nThemeCode, 0);
}

// 0x479a80 / 0x479b00 ("Pop/PushUiResourcePoolNode") are this TU's out-of-line twin copies
// of CList<void*,void*>::RemoveTail / ::AddTail operating on g_UiWidgetBuildStack006a13e0
// — see global_data_tables.h. They are template COMDATs, not game functions; their
// addresses stay with autogen stubs (template twin-copy reccmp gap).
