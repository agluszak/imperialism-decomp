#include "game/ui_widgets/TArmyInfoView.h"
#include "game/mfc.h"

#include "game/ui_screens/CString.h"
#include "game/ui_core/TControl.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00591500
// TArmyInfoView::CreateObject
// SYNTHETIC: IMPERIALISM 0x00591580
// TArmyInfoView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyInfoView, TPicture)

// FUNCTION: IMPERIALISM 0x005915a0
TArmyInfoView::TArmyInfoView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005915d0
// TArmyInfoView::`scalar deleting destructor'
TArmyInfoView::~TArmyInfoView() {}

// PARTIAL PORT of 0x591620 (1,506 bytes). Everything below is read off the listing:
// the five CString locals and the four text-style descriptors the label pass uses
// (0x591684-0x591729). Not yet transcribed: the 'titl'/'lab2'/'lab3' label writes
// (GetString(0x2744, 0xb..0xd) -> SetTextAndMaybeRefresh -> InstallTextStyle) and the
// 'whom'/'ords'/'gene' text assembly that formats categoryCounts through
// g_szDecimalFormat and the ", "/" " separators at 0x695760/0x695794.
// FUNCTION: IMPERIALISM 0x00591620
void TArmyInfoView::PopulateFriendlyArmyReportContent(short cityRecordIndex, int* categoryCounts) {
  (void)cityRecordIndex;
  (void)categoryCounts;
  CString whomText;
  CString ordersText;
  CString scratchText;
  CString labelText;
  CString generalText;

  TextStyle titleStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xe, 0x2b67, 1);
  TextStyle bodyStyle;
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 0xc, 0x2b67);
  TextStyle smallStyle;
  InitializeUiTextStyleDescriptor(&smallStyle, 0, 0xa, 0x2b67, 3);
  TextStyle smallBoldStyle;
  InitializeUiTextStyleDescriptor(&smallBoldStyle, 2, 0xa, 0x2b67, 3);
}
