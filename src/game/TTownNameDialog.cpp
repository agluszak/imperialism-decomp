#include "game/TTownNameDialog.h"

#include "game/ui_control_tags.h"
// SYNTHETIC: IMPERIALISM 0x0051ba70
// TTownNameDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x0051baf0
// TTownNameDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTownNameDialog, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x0051bb10
TTownNameDialog::TTownNameDialog() : TNoHilitePicture() {}

// SYNTHETIC: IMPERIALISM 0x0051bb40
// TTownNameDialog::`scalar deleting destructor'
TTownNameDialog::~TTownNameDialog() {}

// FUNCTION: IMPERIALISM 0x0051bb90
void TTownNameDialog::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  TView* nameControl = ResolveControlByTag(kControlTagName);
  // The original then rolls a random suggested-name index (rand() % 8 + 1) and loads
  // string group 0x1c52 at that index into nameControl, enables it, and applies the
  // text via a handful of further calls on nameControl -- its concrete class beyond
  // TView (its vtable slots there don't match TStaticText's declared signatures at the
  // same byte offsets) is unresolved, so that suggested-name setup is left unmodeled.
  (void)nameControl;
}

// FUNCTION: IMPERIALISM 0x0051bcc0
void TTownNameDialog::ApplyRectSlot110(RECT* rectBuffer) {}
