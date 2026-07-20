#include "game/TCreditsPicture.h"

#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0043d9f0
undefined TCreditsPicture::OrphanRetStub_0043d9f0() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0043dad0
// TCreditsPicture::`scalar deleting destructor'
TCreditsPicture::~TCreditsPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056edb0
// TCreditsPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056ee30
// TCreditsPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCreditsPicture, TPicture)

TCreditsPicture::TCreditsPicture() {}

// FUNCTION: IMPERIALISM 0x0056ee50
void TCreditsPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  g_pSfxPlaybackSystem->ResetDualAudioCuePools();
  g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(0xc);
  g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();

  TDeluxeText* line1 = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagCred));
  line1->QueryStepValue();
  TUiTextStyleDescriptor style;
  InitializeUiTextStyleDescriptor(&style, 0, 0xc, 0x2b68, 3);
  int cursorTheme;
  MapUiThemeCodeToStyleFlags(0x2b6b, &cursorTheme);
  line1->SetTextFromUiStringResourceId(0xfb0);
  line1->ApplyTextStyleDescriptorAndMaybeRefresh(&style, 1);
  line1->shadowTextColor9C = cursorTheme;
  line1->dropShadowEnabledA0 = false;

  TDeluxeText* line2 = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagCre2));
  line2->QueryStepValue();
  line2->SetTextFromUiStringResourceId(0xfb1);
  line2->ApplyTextStyleDescriptorAndMaybeRefresh(&style, 1);
  line2->shadowTextColor9C = cursorTheme;
  line2->dropShadowEnabledA0 = false;
}

// FUNCTION: IMPERIALISM 0x0056efc0
void TCreditsPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler == this) {
    if (g_creditsPlaybackActive_006a4084 != 0) {
      g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
      g_creditsPlaybackActive_006a4084 = 0;
      g_pSfxPlaybackSystem->ResetDualAudioCuePools();
      g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(2);
      g_pSfxPlaybackSystem->PushCueToDualAudioCuePools(3);
      g_pSfxPlaybackSystem->SelectAndScheduleRandomAudioCue();
    } else {
      g_creditsPlaybackActive_006a4084 = 1;

      int cursorTheme;
      MapUiThemeCodeToStyleFlags(0x2b6b, &cursorTheme);
      TUiTextStyleDescriptor style;
      InitializeUiTextStyleDescriptor(&style, 0, 0xc, 0x2b68, 3);

      TDeluxeText* line1 = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagCred));
      line1->QueryStepValue();
      line1->SetTextFromUiStringResourceId(0xfb2);
      line1->ApplyTextStyleDescriptorAndMaybeRefresh(&style, 1);
      line1->shadowTextColor9C = cursorTheme;
      line1->dropShadowEnabledA0 = true;

      TDeluxeText* line2 = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagCre2));
      line2->QueryStepValue();
      line2->SetTextFromUiStringResourceId(0xfb3);
      line2->ApplyTextStyleDescriptorAndMaybeRefresh(&style, 1);
      line2->shadowTextColor9C = cursorTheme;
      line2->dropShadowEnabledA0 = true;
    }
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0056f190
void TCreditsPicture::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
}
