#include "game/TTacticalAdiosPicture.h"

#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0045d430
// TTacticalAdiosPicture::`scalar deleting destructor'
TTacticalAdiosPicture::~TTacticalAdiosPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad430
// TTacticalAdiosPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad4b0
// TTacticalAdiosPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalAdiosPicture, TPicture)

TTacticalAdiosPicture::TTacticalAdiosPicture() {}

// FUNCTION: IMPERIALISM 0x005ad4d0
void TTacticalAdiosPicture::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  TUiTextStyleDescriptor titleStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xe, 0x2b6b, 1);
  titleControl->SetTextStyleAndMaybeRefresh(&titleStyle, 0);
  titleControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

  TStaticText* locationControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
  locationControl->AssertValid();
  TUiTextStyleDescriptor locationStyle;
  InitializeUiTextStyleDescriptor(&locationStyle, 2, 0xc, 0x2b6b, 1);
  locationControl->SetTextStyleAndMaybeRefresh(&locationStyle, 0);
  locationControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

  TDeluxeText* infoControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagInfo));
  infoControl->AssertValid();
  infoControl->BuildAndApplyTextStyleDescriptor(0, 0xa, 0x2b6b);
  infoControl->SetTextThemeCodeAndMaybeRefresh(1, 0);

  TView* owner = OwnerPanel();
  POINT placement;
  g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(owner, &placement);

  TView* owner2 = OwnerPanel();
  owner2->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
}

// FUNCTION: IMPERIALISM 0x005ad650
void TTacticalAdiosPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    static_cast<TControl*>(OwnerPanel())
        ->SetTextStyleAndMaybeRefresh(
            reinterpret_cast<const TUiTextStyleDescriptor*>(sourceHandler->controlTag), 1);
  }
  TControl::HandleEvent(commandId, sourceHandler, event);
}
