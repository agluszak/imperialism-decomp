#include "game/military_ui/TMiniCivLine.h"

#include "game/military_ui/TMiniCivView.h"

// SYNTHETIC: IMPERIALISM 0x004ab620
// TMiniCivLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004ab650
TMiniCivLine::~TMiniCivLine() {}
// SYNTHETIC: IMPERIALISM 0x004ab670
// TMiniCivLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab6e0
// TMiniCivLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniCivLine, TLineData)

// NOOP: verified empty in original 0x004ab6a3 (no standalone TMiniCivLine::TMiniCivLine body exists: CreateObject 0x004ab670 inlines this default ctor, calling the TLineData base ctor directly at that site)
TMiniCivLine::TMiniCivLine() {}

// FUNCTION: IMPERIALISM 0x004ab740
void TMiniCivLine::InstallViews(TView* panel, int* offsetLayout) {
  TMiniCivView* view = new TMiniCivView();
  view->InitializeForCivilianUnit(panel, offsetLayout, &field08, civUnit10);
}
