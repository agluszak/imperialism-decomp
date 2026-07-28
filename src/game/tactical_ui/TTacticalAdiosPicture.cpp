#include "game/tactical_ui/TTacticalAdiosPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x0045d430
// TTacticalAdiosPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0045d460
TTacticalAdiosPicture::~TTacticalAdiosPicture() {}
// SYNTHETIC: IMPERIALISM 0x005ad430
// TTacticalAdiosPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad4b0
// TTacticalAdiosPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalAdiosPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005ad4d0
void TTacticalAdiosPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TStaticText* titleControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  TextStyle titleStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xe, 0x2b6b, 1);
  titleControl->InstallTextStyle(titleStyle, 0);
  titleControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TStaticText* locationControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLoca));
  locationControl->AssertValid();
  TextStyle locationStyle;
  InitializeUiTextStyleDescriptor(&locationStyle, 2, 0xc, 0x2b6b, 1);
  locationControl->InstallTextStyle(locationStyle, 0);
  locationControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TDeluxeText* infoControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagInfo));
  infoControl->AssertValid();
  infoControl->SetTextStyle(0, 0xa, 0x2b6b);
  infoControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TView* owner = GetWindow();
  CPoint placement;
  g_pViewMgr->ComputeTurnEventDialogPlacementByCode(owner, &placement);

  TView* owner2 = GetWindow();
  owner2->Locate(placement, 0);
}

// FUNCTION: IMPERIALISM 0x005ad650
void TTacticalAdiosPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagOkay) {
    GetWindow()->Dismiss(sourceHandler->controlTag, 1);
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
