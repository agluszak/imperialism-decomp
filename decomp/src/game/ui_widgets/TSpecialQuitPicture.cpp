#include "game/ui_widgets/TSpecialQuitPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0045acb0
void TSpecialQuitPicture::Hilite() {}

// FUNCTION: IMPERIALISM 0x0045ad00
TSpecialQuitPicture::~TSpecialQuitPicture() {}

IMPLEMENT_DYNCREATE(TSpecialQuitPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005b4810
void TSpecialQuitPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  TDeluxeText* saleControl = static_cast<TDeluxeText*>(FindSubView(kControlTagSale));
  saleControl->AssertValid();
  saleControl->LoadTextResource(0x4e20);
  saleControl->SetTextStyle(0, 0x18, 0x2b6c);
  CRect saleBounds;
  saleControl->GetFrame(&saleBounds);
  saleBounds.right = 0x28;
  saleBounds.bottom = 0x11;
  saleControl->SetFrame(&saleBounds, true);

  TDeluxeText* shotControl = static_cast<TDeluxeText*>(FindSubView(kControlTagTsho));
  shotControl->AssertValid();
  CString shotCaption;
  g_pSimMgr->GetString(0x274c, 0x18, &shotCaption);
  ApplyControlTheme(shotControl, 0, 0xc, 0x2b6c, 1, static_cast<const char*>(shotCaption));

  TDeluxeText* equiControl = static_cast<TDeluxeText*>(FindSubView(kControlTagTqui));
  equiControl->AssertValid();
  CString equiCaption;
  g_pSimMgr->GetString(0x2737, 9, &equiCaption);
  ApplyControlTheme(equiControl, 0, 0xc, 0x2b6c, 1, static_cast<const char*>(equiCaption));

  TDeluxeText* titlControl = static_cast<TDeluxeText*>(FindSubView(kControlTagTitl));
  titlControl->AssertValid();
  titlControl->SetTextStyle(0, 0xe, 0x2b6c);
  titlControl->SetJustification(1, true);
}

// FUNCTION: IMPERIALISM 0x005b4a10
void TSpecialQuitPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  CString titlText;
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagQuit) {
      g_pAmbitApplication->PostWmCloseToMainThreadWindow();
    }
    if (sourceHandler->controlTag == kControlTagShow) {
      FindSubView(kControlTagQuit)->ViewEnable(0, 1);
      FindSubView(kControlTagShow)->ViewEnable(0, 1);
      FindSubView(kControlTagSale)->Show(0, 1);
      FindSubView(kControlTagRequ)->Show(0, 1);
      FindSubView(kControlTagTsho)->Show(0, 1);
      FindSubView(kControlTagTqui)->Show(0, 1);
      TDeluxeText* titlControl = static_cast<TDeluxeText*>(FindSubView(kControlTagTitl));
      titlControl->AssertValid();
      titlControl->Show(1, 1);
      quitAnimationFrame = 1;
      SetPictureRsrcID(0x3e9, 1);
      g_pSimMgr->GetString(0x1770, 0, &titlText);
      titlControl->UpdateTextEntrySharedString(&titlText);
    } else if (quitAnimationFrame > 0) {
      ++quitAnimationFrame;
      if (quitAnimationFrame < 10) {
        SetPictureRsrcID(static_cast<short>(quitAnimationFrame + 0x3e8), 1);
        TDeluxeText* titlControl = static_cast<TDeluxeText*>(FindSubView(kControlTagTitl));
        titlControl->AssertValid();
        g_pSimMgr->GetString(0x1770, static_cast<short>(quitAnimationFrame - 1), &titlText);
        titlControl->UpdateTextEntrySharedString(&titlText);
      } else {
        quitAnimationFrame = 0;
        SetPictureRsrcID(0x4e20, 1);
        FindSubView(kControlTagQuit)->ViewEnable(1, 1);
        FindSubView(kControlTagShow)->ViewEnable(1, 1);
        FindSubView(kControlTagSale)->Show(1, 1);
        FindSubView(kControlTagRequ)->Show(1, 1);
        FindSubView(kControlTagTsho)->Show(1, 1);
        FindSubView(kControlTagTqui)->Show(1, 1);
        FindSubView(kControlTagTitl)->Show(0, 1);
      }
    }
  }
  TPicture::DoEvent(commandId, sourceHandler, event);
}
