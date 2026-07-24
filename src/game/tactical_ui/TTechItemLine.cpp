#include "game/tactical_ui/TTechItemLine.h"

#include "game/tactical_ui/TTechItemView.h"

// SYNTHETIC: IMPERIALISM 0x005b1040
// TTechItemLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005b1070
TTechItemLine::~TTechItemLine() {}
// SYNTHETIC: IMPERIALISM 0x005b1090
// TTechItemLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b1100
// TTechItemLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechItemLine, TLineData)

// Virtual line factory: builds this tech line's TTechItemView, sized by the inherited
// field08/field0c bound pair and parameterized by this line's nation slot and tech id.
// FUNCTION: IMPERIALISM 0x005b1160
void TTechItemLine::InstallViews(TView* panel, int* offsetLayout) {
  TTechItemView* view = new TTechItemView();
  view->ITechItemView(panel, offsetLayout, &field08, nationSlot10, techId14);
}
