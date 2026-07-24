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

// NOOP: verified empty in original 0x005b10c3 (no standalone TTechItemLine::TTechItemLine body exists: CreateObject 0x005b1090 inlines this default ctor, calling the TLineData base ctor directly at that site)
TTechItemLine::TTechItemLine() {}

// Virtual line factory: builds this tech line's TTechItemView, sized by the inherited
// field08/field0c bound pair and parameterized by this line's nation slot and tech id.
// FUNCTION: IMPERIALISM 0x005b1160
void TTechItemLine::InstallViews(TView* panel, int* offsetLayout) {
  TTechItemView* view = new TTechItemView();
  view->InitializeTechItem(panel, offsetLayout, &field08, nationSlot10, techId14);
}
