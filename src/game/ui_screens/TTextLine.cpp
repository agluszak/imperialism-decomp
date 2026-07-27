#include "game/ui_screens/TTextLine.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
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
// FUNCTION: IMPERIALISM 0x00570340
TTextLine::~TTextLine() {}

// FUNCTION: IMPERIALISM 0x00570390
void TTextLine::SetTextLineRowBoundsAndStyle(short rowArg, short colArg, int* bounds,
                                             short styleGroupCode, short styleIndex) {
  column = colArg;
  layoutWidth = bounds[0];
  layoutHeight = bounds[1];
  row = rowArg;
  if (styleGroupCode != -1) {
    g_pSimMgr->GetString(styleGroupCode, static_cast<short>(styleIndex - 1), &captionText10);
  }
  BuildUiTextStyleDescriptor(&styleDescriptor14, 0, 0xc, 0x2b67);
  textAlignmentCode = -2;
}

// FUNCTION: IMPERIALISM 0x00570420
void TTextLine::SetCaptionText(CString* caption) {
  captionText10 = *caption;
}

// FUNCTION: IMPERIALISM 0x00570440
void TTextLine::SetTextLineStyleDescriptor(const TextStyle* descriptor) {
  styleDescriptor14 = *descriptor;
}

// FUNCTION: IMPERIALISM 0x005704e0
void TTextLine::SetTextAlignmentCode(short value) {
  textAlignmentCode = value;
}

// FUNCTION: IMPERIALISM 0x00570500
void TTextLine::InstallViews(TView* panel, int* offsetLayout) {
  TStaticText* text = new TStaticText();
  text->IStaticText(panel, offsetLayout, &layoutWidth, 5, 5, -1, 0);
  text->SetTextAndMaybeRefresh(&captionText10, 0);
  text->InstallTextStyle(styleDescriptor14, 0);
  text->SetTextAlignmentAndMaybeRefresh(textAlignmentCode, 0);
  text->RefreshControl();
}
