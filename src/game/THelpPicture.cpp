#include "game/THelpPicture.h"

#include "game/THelpMgr.h"
#include "game/TDeluxeText.h"
#include "game/TDisplayMgr.h"
#include "game/TScrollView.h"
#include "game/TSimMgr.h"
#include "game/TSortedPtrList.h"
#include "game/TSoundPlayer.h"
#include "game/TStaticText.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/ui_text_label_helpers_decls.h"

namespace {

HelpSetRecord* FindHelpSetById(short helpSetId) {
  TSortedPtrList* list = g_pHelpMgr->indexList;
  for (int index = 1; index <= list->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(list->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpResourceBaseId == helpSetId) {
      return record;
    }
  }
  return 0;
}

} // namespace
// SYNTHETIC: IMPERIALISM 0x00503bd0
// THelpPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00503c70
// THelpPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(THelpPicture, TPicture)

THelpPicture::THelpPicture() : TPicture(), currentHelpSet90(0), topicListText94(0) {}

// SYNTHETIC: IMPERIALISM 0x00503cc0
// THelpPicture::`scalar deleting destructor'
THelpPicture::~THelpPicture() {}

// FUNCTION: IMPERIALISM 0x00503d10
void THelpPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TextStyle textStyle;
  InitializeUiTextStyleDescriptor(&textStyle, 0, 12, 0x2b67, 3);

  // Mac Linger.rsrc:3000 identifies 'swin' as the help dialog's TScrollView.
  TScrollView* scrollView = static_cast<TScrollView*>(ResolveControlByTag(0x7377696e)); // 'swin'
  scrollView->AssertValid();

  TDeluxeText* topicText = new TDeluxeText();
  int textOffset[2] = {0, 0};
  int textSize[2] = {scrollView->frameWidth34 - 0x1c, scrollView->frameHeight38};
  RECT textInsets = {0, 0, 0, 0};
  topicText->InitializeDeluxeText(scrollView, textOffset, textSize, &textInsets, &textStyle, -2);

  topicListText94 = topicText;
  scrollView->contentView60 = topicText;
  scrollView->SyncBoundedValueAndToggleControlStates();
}

// FUNCTION: IMPERIALISM 0x00503ed0
void THelpPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::DoEvent(commandId, sourceHandler, event);
  if (commandId != 0xd) {
    return;
  }

  switch (sourceHandler->controlTag) {
  case 0x6d6f7265: // 'more'
    PlayDefaultMessageBeep(1);
    return;
  case 0x6e616d31: // 'nam1'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(1);
    return;
  case 0x6e616d32: // 'nam2'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(2);
    return;
  case 0x6e616d33: // 'nam3'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(3);
    return;
  case 0x6e616d34: // 'nam4'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(4);
    return;
  case 0x6e616d35: // 'nam5'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(5);
    return;
  case 0x6e657874: // 'next'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowNextHelpSet();
    return;
  case 0x70726576: // 'prev'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowPreviousHelpSet();
    return;
  case 0x746f676c: // 'togl'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopicList();
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00504120
void THelpPicture::ShowNextHelpSet() {
  HelpSetRecord* next = FindHelpSetById(currentHelpSet90->nextHelpResourceBaseId);
  if (next != 0) {
    currentHelpSet90 = next;
  }
  ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x005041a0
void THelpPicture::ShowPreviousHelpSet() {
  HelpSetRecord* previous = FindHelpSetById(currentHelpSet90->previousHelpResourceBaseId);
  if (previous != 0) {
    currentHelpSet90 = previous;
  }
  ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x00504220
void THelpPicture::ShowTopic(short topic) {
  TView* helpDialog = g_pHelpMgr->pendingDialogView8;
  TextStyle normalStyle;
  TextStyle highlightStyle;
  TextStyle captionStyle;
  normalStyle.textColor = 0;
  highlightStyle.textColor = 0;
  captionStyle.textColor = 0;
  CString navigationText;

  InitializeUiTextStyleDescriptor(&normalStyle, 4, 12, 0x2b6d, 3);
  InitializeUiTextStyleDescriptor(&highlightStyle, 4, 12, 0x2b69, 3);
  InitializeUiTextStyleDescriptor(&captionStyle, 0, 12, 0x2b67, 1);

  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(0x7375626a)); // 'subj'
  subject->SetTextFromStringResource(currentHelpSet90->helpResourceBaseId,
                                     static_cast<short>(topic + 1), 1);
  subject->SetEnabled(1, 1);
  subject->SetState(0, 1);
  subject->SetTextAlignmentAndMaybeRefresh(1, 0);
  subject->InstallTextStyle(captionStyle, 0);

  TStaticText* toggle = static_cast<TStaticText*>(ResolveControlByTag(0x746f676c)); // 'togl'
  toggle->SetEnabled(1, 1);
  toggle->SetState(1, 1);
  toggle->SetTextAlignmentAndMaybeRefresh(1, 0);
  toggle->InstallTextStyle(normalStyle, 0);

  for (int index = 0; index < 5; ++index) {
    TView* topicName = ResolveControlByTag(0x6e616d31 + index); // 'nam1'..'nam5'
    topicName->SetEnabled(0, 1);
    topicName->SetState(0, 1);
  }

  TStaticText* previous = static_cast<TStaticText*>(ResolveControlByTag(0x70726576)); // 'prev'
  g_pSimMgr->GetString(0x2749, 0xd, &navigationText);
  previous->SetTextAndMaybeRefresh(&navigationText, 1);
  previous->SetEnabled(0, 1);
  previous->SetState(0, 1);
  previous->SetTextAlignmentAndMaybeRefresh(-1, 0);
  previous->InstallTextStyle(normalStyle, 0);

  TStaticText* next = static_cast<TStaticText*>(ResolveControlByTag(0x6e657874)); // 'next'
  g_pSimMgr->GetString(0x2749, 0xe, &navigationText);
  next->SetTextAndMaybeRefresh(&navigationText, 1);
  next->SetEnabled(0, 1);
  next->SetState(0, 1);
  next->SetTextAlignmentAndMaybeRefresh(-1, 0);
  next->InstallTextStyle(normalStyle, 0);

  topicListText94->SetEnabled(1, 0);

  // Mac Strings.rsrc TEXT entries and the Windows GOB crosswalk both use
  // helpResourceBaseId + topic for the selected long-form help body.
  TScrollView* scrollView = static_cast<TScrollView*>(ResolveControlByTag(0x7377696e)); // 'swin'
  scrollView->AssertValid();
  scrollView->SetEnabled(1, 0);
  topicListText94->SetTextFromUiStringResourceId(
      static_cast<short>(currentHelpSet90->helpResourceBaseId + topic));

  int textHeight = topicListText94->MeasureCurrentTextHeightInLayoutRect() + 8;

  CRect scrollBounds;
  scrollView->QueryBounds(&scrollBounds);
  scrollBounds.top = 0x92;
  scrollBounds.bottom = 0x135;
  scrollView->ApplyBounds(&scrollBounds, 1);

  CRect textBounds;
  if (textHeight < 0xa3) {
    scrollView->QueryBounds(&textBounds);
    textBounds.top += 10;
    scrollView->ApplyBounds(&textBounds, 0);
  }

  topicListText94->QueryBounds(&textBounds);
  textBounds.top = 0;
  textBounds.bottom = textHeight;
  topicListText94->ApplyBounds(&textBounds, 0);
  scrollView->SyncBoundedValueAndToggleControlStates();
  RefreshControl();
  helpDialog->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005046c0
void THelpPicture::ShowTopicList() {
  TView* helpDialog = g_pHelpMgr->pendingDialogView8;
  TextStyle normalStyle;
  TextStyle highlightStyle;
  TextStyle captionStyle;
  normalStyle.textColor = 0;
  highlightStyle.textColor = 0;
  captionStyle.textColor = 0;
  CString navigationText;

  InitializeUiTextStyleDescriptor(&normalStyle, 4, 12, 0x2b6d, 3);
  InitializeUiTextStyleDescriptor(&highlightStyle, 4, 12, 0x2b69, 3);
  InitializeUiTextStyleDescriptor(&captionStyle, 0, 12, 0x2b67, 1);

  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(0x7375626a)); // 'subj'
  subject->SetTextFromStringResource(currentHelpSet90->helpResourceBaseId, 1, 1);
  subject->SetEnabled(1, 1);
  subject->SetState(0, 1);
  subject->SetTextAlignmentAndMaybeRefresh(1, 0);
  subject->InstallTextStyle(captionStyle, 0);

  TStaticText* toggle = static_cast<TStaticText*>(ResolveControlByTag(0x746f676c)); // 'togl'
  toggle->SetEnabled(0, 1);
  toggle->SetState(0, 1);
  toggle->SetTextFromStringResource(0x2749, 9, 1);

  int topicIndex;
  for (topicIndex = 0; topicIndex < currentHelpSet90->topicCount; ++topicIndex) {
    TStaticText* topicName =
        static_cast<TStaticText*>(ResolveControlByTag(0x6e616d31 + topicIndex)); // 'nam1'..
    topicName->SetTextFromStringResource(currentHelpSet90->helpResourceBaseId,
                                         static_cast<short>(topicIndex + 2), 1);
    topicName->SetEnabled(1, 1);
    topicName->SetState(1, 1);
    topicName->SetTextAlignmentAndMaybeRefresh(-2, 0);
    topicName->InstallTextStyle(normalStyle, 0);
  }

  for (int unusedTopicTag = currentHelpSet90->topicCount + 0x6e616d31; unusedTopicTag < 0x6e616d36;
       ++unusedTopicTag) { // 'nam1'..'nam5'
    TView* topicName = ResolveControlByTag(unusedTopicTag);
    topicName->SetEnabled(0, 1);
    topicName->SetState(0, 1);
  }

  char navigationAvailable = currentHelpSet90->previousHelpResourceBaseId != 0;
  TStaticText* previous = static_cast<TStaticText*>(ResolveControlByTag(0x70726576)); // 'prev'
  g_pSimMgr->GetString(0x2749, 0xd, &navigationText);
  previous->SetTextAndMaybeRefresh(&navigationText, 1);
  previous->SetEnabled(navigationAvailable, 1);
  previous->SetState(navigationAvailable, 1);
  previous->SetTextAlignmentAndMaybeRefresh(-1, 0);
  previous->InstallTextStyle(normalStyle, 0);

  navigationAvailable = currentHelpSet90->nextHelpResourceBaseId != 0;
  TStaticText* next = static_cast<TStaticText*>(ResolveControlByTag(0x6e657874)); // 'next'
  g_pSimMgr->GetString(0x2749, 0xe, &navigationText);
  next->SetTextAndMaybeRefresh(&navigationText, 1);
  next->SetEnabled(navigationAvailable, 1);
  next->SetState(navigationAvailable, 1);
  next->SetTextAlignmentAndMaybeRefresh(-1, 0);
  next->InstallTextStyle(normalStyle, 0);

  topicListText94->SetEnabled(0, 1);

  TScrollView* scrollView = static_cast<TScrollView*>(ResolveControlByTag(0x7377696e)); // 'swin'
  scrollView->AssertValid();
  scrollView->SetEnabled(0, 1);
  RefreshControl();
  helpDialog->ForceRedraw();
}
