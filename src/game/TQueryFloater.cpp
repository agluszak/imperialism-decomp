#include "game/TQueryFloater.h"

#include "game/TStaticText.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043d6a0
// TQueryFloater::`scalar deleting destructor'
TQueryFloater::~TQueryFloater() {}
// SYNTHETIC: IMPERIALISM 0x0056e840
// TQueryFloater::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056e8c0
// TQueryFloater::GetRuntimeClass

IMPLEMENT_DYNCREATE(TQueryFloater, TPicture)

TQueryFloater::TQueryFloater() {}

// FUNCTION: IMPERIALISM 0x0056e8e0
void TQueryFloater::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  TUiTextStyleDescriptor style;

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->QueryStepValue();
  titleControl->LoadUiStringAndDispatchViaVslot1C8(0x2757, 1, 1);
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);
  titleControl->SetTextStyleAndMaybeRefresh(&style, 0);
  titleControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6c);
  for (int i = 0; i < 7; ++i) {
    TStaticText* lineControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTex0 + i));
    lineControl->QueryStepValue();
    lineControl->LoadUiStringAndDispatchViaVslot1C8(0x2757, static_cast<short>(i + 2), 1);
    lineControl->SetTextStyleAndMaybeRefresh(&style, 0);
    if (i == 6) {
      lineControl->SetTextThemeCodeAndMaybeRefresh(1, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0056ea20
void TQueryFloater::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) { }
