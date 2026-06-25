// TStratReportView wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TView.h"

#include <new>


namespace {

// GLOBAL: IMPERIALISM 0x6630e8
char g_pClassDescTStratReportView;

// VTABLE: IMPERIALISM 0x667d08
class TStratReportView : public TView {
public:
  char pad_60_to_63[0x04];

  TStratReportView();

};

} // namespace

// FUNCTION: IMPERIALISM 0x0058e330
TStratReportView* __cdecl CreateTStratReportViewInstance(void) {
  return new TStratReportView();
}

// FUNCTION: IMPERIALISM 0x0058e3a0
void* __cdecl GetTStratReportViewClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTStratReportView);
}

// FUNCTION: IMPERIALISM 0x0058e3c0
TStratReportView::TStratReportView() : TView() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058e3f0
// TStratReportView::`scalar deleting destructor'
