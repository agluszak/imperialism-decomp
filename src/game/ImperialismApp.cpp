#include "game/ImperialismApp.h"

// The global MFC application object (DAT_006a1210). Its CRT static-init bootstrap is
// 0x00412d40 (ctor) / 0x00412d70 (dtor).
ImperialismApp theApp;

// FUNCTION: IMPERIALISM 0x00412ac0
ImperialismApp::ImperialismApp()
    : CWinApp(), field_C0(0), field_C4(), field_C8(0), field_CC(), field_D0(),
      field_D4(), field_D8(), field_DC(), field_E0() {}

// Shape-stage placeholder. The real body (the window-open / asset-load path) is gated on
// a leaf-up cascade: the TModuleLibraryCacheTableStateB asset-loader class + its load
// methods, a TAmbitApplication subclass (vtable 0x0063e398), DAT_006a2158's class, and
// typed prototypes for the __cdecl startup helpers. See docs/reference/imperialism-decomp.md.
// FUNCTION: IMPERIALISM 0x00412dc0
BOOL ImperialismApp::InitInstance() {
  return TRUE;
}

// Shape-stage placeholder. Real body frees the global subsystems (module cache, strategic
// map, UI view manager, sound, UI root controller), restores the display mode, unloads the
// custom fonts, and chains to CWinApp::ExitInstance.
// FUNCTION: IMPERIALISM 0x00413780
int ImperialismApp::ExitInstance() {
  return 0;
}
