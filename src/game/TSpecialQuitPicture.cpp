#include "game/TSpecialQuitPicture.h"

#include "game/ui_control_tags.h"

// FUNCTION: IMPERIALISM 0x0045acb0
undefined TSpecialQuitPicture::OrphanRetStub_0045acb0() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0045acd0
// TSpecialQuitPicture::`scalar deleting destructor'
TSpecialQuitPicture::~TSpecialQuitPicture() {}
// SYNTHETIC: IMPERIALISM 0x005b4760
// TSpecialQuitPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b47f0
// TSpecialQuitPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSpecialQuitPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005b4810
void TSpecialQuitPicture::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  TView* saleControl = ResolveControlByTag(kControlTagSale);
  saleControl->AssertValid();
  // The original then calls saleControl's own vtable slots 0x1dc/0x1e0/0x12c with
  // templated string/rect arguments, and resolves further 'quit'/'titl' controls with the
  // same pattern -- saleControl's concrete class introduces virtuals beyond TStaticText's
  // own declared extent (those slots are null in TStaticText's real vtable), so it is
  // unresolved; left unmodeled.
}

// FUNCTION: IMPERIALISM 0x005b4a10
void TSpecialQuitPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
