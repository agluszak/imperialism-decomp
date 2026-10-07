#include "game/ui_screens/TCreditsPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/gfx_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0043d9c0
TCreditsPicture::TCreditsPicture() {}

// FUNCTION: IMPERIALISM 0x0043d9f0
void TCreditsPicture::Hilite() {}

// FUNCTION: IMPERIALISM 0x0043db80
TCreditsPicture::~TCreditsPicture() {}

IMPLEMENT_DYNCREATE(TCreditsPicture, TPicture)

// FUNCTION: IMPERIALISM 0x0056ee50
void TCreditsPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  g_pSfxPlaybackSystem->ResetPlayList();
  g_pSfxPlaybackSystem->AddToPlayList(0xc);
  g_pSfxPlaybackSystem->PlayRandomTrack();

  TDeluxeText* line1 = static_cast<TDeluxeText*>(FindSubView(kControlTagCred));
  line1->AssertValid();
  TextStyle style;
  InitializeUiTextStyleDescriptor(&style, 0, 0xc, 0x2b68, 3);
  COLORREF cursorTheme;
  ResolveUiThemeColor(0x2b6b, &cursorTheme);
  line1->LoadTextResource(0xfb0);
  line1->SetTextStyle(style, true);
  line1->shadowTextColor = cursorTheme;
  line1->dropShadowEnabled = false;

  TDeluxeText* line2 = static_cast<TDeluxeText*>(FindSubView(kControlTagCre2));
  line2->AssertValid();
  line2->LoadTextResource(0xfb1);
  line2->SetTextStyle(style, true);
  line2->shadowTextColor = cursorTheme;
  line2->dropShadowEnabled = false;
}

// FUNCTION: IMPERIALISM 0x0056efc0
void TCreditsPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler == this) {
    if (g_creditsPlaybackActive != 0) {
      g_pSimMgr->StartNextPhase();
      g_creditsPlaybackActive = 0;
      g_pSfxPlaybackSystem->ResetPlayList();
      g_pSfxPlaybackSystem->AddToPlayList(2);
      g_pSfxPlaybackSystem->AddToPlayList(3);
      g_pSfxPlaybackSystem->PlayRandomTrack();
    } else {
      g_creditsPlaybackActive = 1;

      COLORREF cursorTheme;
      ResolveUiThemeColor(0x2b6b, &cursorTheme);
      TextStyle style;
      InitializeUiTextStyleDescriptor(&style, 0, 0xc, 0x2b68, 3);

      TDeluxeText* line1 = static_cast<TDeluxeText*>(FindSubView(kControlTagCred));
      line1->AssertValid();
      line1->LoadTextResource(0xfb2);
      line1->SetTextStyle(style, true);
      line1->shadowTextColor = cursorTheme;
      line1->dropShadowEnabled = true;

      TDeluxeText* line2 = static_cast<TDeluxeText*>(FindSubView(kControlTagCre2));
      line2->AssertValid();
      line2->LoadTextResource(0xfb3);
      line2->SetTextStyle(style, true);
      line2->shadowTextColor = cursorTheme;
      line2->dropShadowEnabled = true;
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0056f190
void TCreditsPicture::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x0056f1d0
void __fastcall ReleaseDibOrientationGuard(int* engagedFlag) {
  if (*engagedFlag != 0) {
    --g_nDibOrientationFlag;
    *engagedFlag = 0;
  }
}
