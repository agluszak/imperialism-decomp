#include "game/ui_widgets/TSpecialQuitPicture.h"

#include "game/ImperialismApp.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0045acb0
void TSpecialQuitPicture::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x0045acd0
// TSpecialQuitPicture::`scalar deleting destructor'
TSpecialQuitPicture::~TSpecialQuitPicture() {}
// SYNTHETIC: IMPERIALISM 0x005b4760
// TSpecialQuitPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b47f0
// TSpecialQuitPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TSpecialQuitPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005b4810
void TSpecialQuitPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  // 'sale'/'shot'/'equi'/'titl' are TDeluxeText controls (verified via class-vtable-dump:
  // TDeluxeText is the class that introduces real virtuals at byte offsets 0x1d8-0x1f8,
  // beyond TStaticText's declared extent -- ApplyControlThemeStyleAndOptionalCaption's own
  // TStaticText* parameter accepts them via the real inheritance chain).
  TDeluxeText* saleControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagSale));
  saleControl->AssertValid();
  saleControl->SetTextFromUiStringResourceId(0x4e20);
  saleControl->SetTextStyle(0, 0x18, 0x2b6c);
  CRect saleBounds;
  saleControl->QueryBounds(&saleBounds);
  saleBounds.right = 0x28;
  saleBounds.bottom = 0x11;
  saleControl->ApplyBounds(&saleBounds, 1);

  TDeluxeText* shotControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagShot));
  shotControl->AssertValid();
  CString shotCaption;
  g_pSimMgr->GetString(0x274c, 0x18, &shotCaption);
  ApplyControlThemeStyleAndOptionalCaption(shotControl, 0, 0xc, 0x2b6c, 1,
                                           static_cast<const char*>(shotCaption));

  TDeluxeText* equiControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagEqui));
  equiControl->AssertValid();
  CString equiCaption;
  g_pSimMgr->GetString(0x2737, 9, &equiCaption);
  ApplyControlThemeStyleAndOptionalCaption(equiControl, 0, 0xc, 0x2b6c, 1,
                                           static_cast<const char*>(equiCaption));

  TDeluxeText* titlControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTitl));
  titlControl->AssertValid();
  titlControl->SetTextStyle(0, 0xe, 0x2b6c);
  titlControl->SetTextAlignmentAndMaybeRefresh(1, 1);
}

// FUNCTION: IMPERIALISM 0x005b4a10
void TSpecialQuitPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  CString titlText;
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
      TDeluxeText* titlControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTitl));
      titlControl->AssertValid();
      titlControl->SetEnabled(1, 1);
      quitAnimationFrame90 = 1;
      SetPictureResourceIdAndRefresh(0x3e9, 1);
      g_pSimMgr->GetString(0x1770, 0, &titlText);
      titlControl->UpdateTextEntrySharedString(&titlText);
    } else if (quitAnimationFrame90 > 0) {
      ++quitAnimationFrame90;
      if (quitAnimationFrame90 < 10) {
        SetPictureResourceIdAndRefresh(static_cast<short>(quitAnimationFrame90 + 0x3e8), 1);
        TDeluxeText* titlControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagTitl));
        titlControl->AssertValid();
        g_pSimMgr->GetString(0x1770, static_cast<short>(quitAnimationFrame90 - 1), &titlText);
        titlControl->UpdateTextEntrySharedString(&titlText);
      } else {
        quitAnimationFrame90 = 0;
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
  TPicture::DoEvent(commandId, sourceHandler, event);
}
