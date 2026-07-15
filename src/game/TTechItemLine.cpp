#include "game/TTechItemLine.h"

#include "game/TTechItemView.h"

// SYNTHETIC: IMPERIALISM 0x005b1040
// TTechItemLine::`scalar deleting destructor'
TTechItemLine::~TTechItemLine() {}
// SYNTHETIC: IMPERIALISM 0x005b1090
// TTechItemLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b1100
// TTechItemLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechItemLine, TLineData)

TTechItemLine::TTechItemLine() {}

// Virtual line factory: builds this tech line's TTechItemView, sized by the inherited
// field08/field0c bound pair and parameterized by this line's nation slot and tech id.
// FUNCTION: IMPERIALISM 0x005b1160
void TTechItemLine::CreateLineItemView(TView* panel, int* offsetLayout) {
  TTechItemView* view = new TTechItemView();
  view->ConstructTTechItemViewBaseState(panel, offsetLayout, &field08, nationSlot10, techId14);
}
