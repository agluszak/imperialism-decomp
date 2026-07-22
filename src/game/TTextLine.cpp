#include "game/TTextLine.h"

#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x005701d0
// TTextLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x00570270
// TTextLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTextLine, TLineData)

// FUNCTION: IMPERIALISM 0x00570290
TTextLine::TTextLine() : TLineData() {
  // Only styleRef6 is zero-initialized here; mode/flag2/pointSize stay garbage until
  // SetTextLineRowBoundsAndStyle's BuildUiTextStyleDescriptor call fills them in.
  styleDescriptor14.textColor = 0;
}

// SYNTHETIC: IMPERIALISM 0x00570310
// TTextLine::`scalar deleting destructor'
TTextLine::~TTextLine() {}

// FUNCTION: IMPERIALISM 0x00570390
void TTextLine::SetTextLineRowBoundsAndStyle(short rowArg, short colArg, int* bounds,
                                             short styleGroupCode, short styleIndex) {
  field04 = colArg;
  field08 = bounds[0];
  field0c = bounds[1];
  field06 = rowArg;
  if (styleGroupCode != -1) {
    g_pSimMgr->GetString(styleGroupCode, static_cast<short>(styleIndex - 1), &captionText10);
  }
  BuildUiTextStyleDescriptor(&styleDescriptor14, 0, 0xc, 0x2b67);
  field1e = -2;
}

// FUNCTION: IMPERIALISM 0x00570440
void TTextLine::SetTextLineStyleDescriptor(const TextStyle* descriptor) {
  styleDescriptor14 = *descriptor;
}

// FUNCTION: IMPERIALISM 0x005704e0
void TTextLine::SetField1E(short value) {
  field1e = value;
}

// FUNCTION: IMPERIALISM 0x00570500
void TTextLine::CreateLineItemView(TView* panel, int* offsetLayout) {
  (void)panel;
  (void)offsetLayout;
}
