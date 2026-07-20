#include "game/TOffersPanelView.h"

#include "game/TDeluxeText.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004f8ec0
// TOffersPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f8f50
// TOffersPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOffersPanelView, TPanelView)

// FUNCTION: IMPERIALISM 0x004f8f70
TOffersPanelView::TOffersPanelView() : TPanelView(), acceptText(0), rejectText(0) {}

// SYNTHETIC: IMPERIALISM 0x004f8fa0
// TOffersPanelView::`scalar deleting destructor'
TOffersPanelView::~TOffersPanelView() {}

// FUNCTION: IMPERIALISM 0x004f8ff0
void TOffersPanelView::DoPostCreate(int arg) {
  TPanelView::DoPostCreate(arg);

  m_panelData = ownerContext;
  acceptText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagAcce));
  acceptText->AssertValid();
  rejectText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagReje));
  rejectText->AssertValid();
  acceptText->textOptionFlags = 0x1388;
  rejectText->textOptionFlags = 0x1388;

  TUiTextStyleDescriptor sharedStyle;
  BuildUiTextStyleDescriptor(&sharedStyle, 0, 0, 0x2b68);

  // 'prop'/'text' are TDeluxeText controls (see the TDeluxeText class-recovery note in
  // TSpecialQuitPicture.cpp): their vtable slots 0x1e4/0x1c4 match
  // ApplyTextStyleDescriptorAndMaybeRefresh/SetTextAlignmentAndMaybeRefresh exactly.
  TDeluxeText* propControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagProp));
  propControl->AssertValid();
  propControl->ApplyTextStyleDescriptorAndMaybeRefresh(&sharedStyle, 0);
  propControl->cursorThemeCode9c = sharedStyle.textColor;
  propControl->fieldA0 = 1;
  propControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  TDeluxeText* textControl = static_cast<TDeluxeText*>(ResolveControlByTag(kControlTagText));
  textControl->AssertValid();
  textControl->ApplyTextStyleDescriptorAndMaybeRefresh(&sharedStyle, 0);
  textControl->cursorThemeCode9c = sharedStyle.textColor;
  textControl->fieldA0 = 1;
  textControl->SetTextAlignmentAndMaybeRefresh(1, 0);

  CString acceHint;
  g_pSimMgr->GetString(0x274a, 6, &acceHint);
  SetControlHoverHelpText(acceHint, acceptText);
  CString rejeHint;
  g_pSimMgr->GetString(0x274a, 7, &rejeHint);
  SetControlHoverHelpText(rejeHint, rejectText);

  // Blanks the panel's own hover-help text (SetControlHoverHelpText's callee target
  // decodes to the real ported SetControlHoverHelpText/TView::SetHoverHelpText, not the
  // stale "ApplySharedStringToControlState" symbols.csv name).
  SetControlHoverHelpText(CString(), this);
}

// FUNCTION: IMPERIALISM 0x004f9300
void TOffersPanelView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId == 5 || (commandId == 0xa && (tag == kControlTagAcce || tag == kControlTagReje))) {
    lastNegotiationResponseTag64 = tag;
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004f9350
void TOffersPanelView::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x004f9420
char TOffersPanelView::DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                                 int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f9450
undefined TOffersPanelView::RunDiplomacyNegotiationPopupAndAwaitResponse() {
  return 0;
}
