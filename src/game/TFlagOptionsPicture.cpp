#include "game/TFlagOptionsPicture.h"

#include "game/TDropShadowText.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0043da10
// TFlagOptionsPicture::`scalar deleting destructor'
TFlagOptionsPicture::~TFlagOptionsPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056b210
// TFlagOptionsPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056b290
// TFlagOptionsPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFlagOptionsPicture, TPicture)

TFlagOptionsPicture::TFlagOptionsPicture() {}

// FUNCTION: IMPERIALISM 0x0056b2b0
void TFlagOptionsPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) { }

// FUNCTION: IMPERIALISM 0x0056b640
void TFlagOptionsPicture::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  CString text;
  for (int i = 0; i < 8; ++i) {
    g_pSimMgr->GetString(0x2743, static_cast<short>(i), &text);
    TDropShadowText* control = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTxt0 + i));
    control->QueryStepValue();
    if (i == 0) {
      ApplyUiTextStyleAndThemeFlags(control, 0, 0xc, 0x2b6c, 0x2b6a);
    } else {
      ApplyUiTextStyleAndThemeFlags(control, 0, 0xe, 0x2b6b, 0x2b6c);
    }
    control->SetTextThemeCodeAndMaybeRefresh(i > 1 ? -2 : 1, 0);
    control->AssignTextSharedRefIfChangedAndMaybeInvalidate(&text, 0);
  }
}
