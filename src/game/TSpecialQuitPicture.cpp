#include "game/TSpecialQuitPicture.h"

#include "game/ImperialismApp.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
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
void TSpecialQuitPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagQuit) {
      PostWmCloseToMainThreadWindow();
    }
    if (sourceHandler->controlTag == kControlTagShow) {
      ResolveControlByTag(kControlTagQuit)->SetState(0, 1);
      ResolveControlByTag(kControlTagShow)->SetState(0, 1);
      ResolveControlByTag(kControlTagSale)->SetEnabled(0, 1);
      ResolveControlByTag(kControlTagRequ)->SetEnabled(0, 1);
      ResolveControlByTag(kControlTagShot)->SetEnabled(0, 1);
      ResolveControlByTag(kControlTagEqui)->SetEnabled(0, 1);
      TView* titlControl = ResolveControlByTag(kControlTagTitl);
      titlControl->AssertValid();
      titlControl->SetEnabled(1, 1);
      field90 = 1;
      SetPictureResourceIdAndRefresh(0x3e9, 1);
      // The original then loads a templated string (group 0x1770, index 0) and applies it
      // to titlControl via its own vtable slot 0x1f0 -- beyond TStaticText's declared
      // extent (a genuinely unrecovered sibling class, same as NoOpUiLifecycleHook's
      // saleControl), left unmodeled.
    } else if (field90 > 0) {
      ++field90;
      if (field90 < 10) {
        SetPictureResourceIdAndRefresh(static_cast<short>(field90 + 0x3e8), 1);
        TView* titlControl = ResolveControlByTag(kControlTagTitl);
        titlControl->AssertValid();
        // The original then loads a templated string (group 0x1770, index field90-1) and
        // applies it to titlControl via vtable slot 0x1f0 -- same unresolved-class gap as
        // above, left unmodeled.
      } else {
        field90 = 0;
        SetPictureResourceIdAndRefresh(0x4e20, 1);
        ResolveControlByTag(kControlTagQuit)->SetState(1, 1);
        ResolveControlByTag(kControlTagShow)->SetState(1, 1);
        ResolveControlByTag(kControlTagSale)->SetEnabled(1, 1);
        ResolveControlByTag(kControlTagRequ)->SetEnabled(1, 1);
        ResolveControlByTag(kControlTagShot)->SetEnabled(1, 1);
        ResolveControlByTag(kControlTagEqui)->SetEnabled(1, 1);
        ResolveControlByTag(kControlTagTitl)->SetEnabled(0, 1);
      }
    }
  }
  TPicture::HandleEvent(commandId, sourceHandler, event);
}
