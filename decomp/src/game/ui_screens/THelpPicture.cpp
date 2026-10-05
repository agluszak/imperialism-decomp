#include "game/ui_screens/THelpPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"

#include "game/ui_core/THelpMgr.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_screens/TScrollView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(THelpPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00503c90
THelpPicture::THelpPicture() : TPicture(), currentHelpSet(0), topicListText(0) {}

// FUNCTION: IMPERIALISM 0x00503cf0
THelpPicture::~THelpPicture() {}

// FUNCTION: IMPERIALISM 0x00503d10
void THelpPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TextStyle textStyle;
  InitializeUiTextStyleDescriptor(&textStyle, 0, 12, 0x2b67, 3);

  // Mac Linger.rsrc:3000 identifies 'swin' as the help dialog's TScrollView.
  TScrollView* scrollView =
      static_cast<TScrollView*>(ResolveControlByTag(kControlTagSwin)); // 'swin'
  scrollView->AssertValid();

  TDeluxeText* topicText = new TDeluxeText();
  int textOffset[2] = {0, 0};
  int textSize[2] = {scrollView->frameWidth - 0x1c, scrollView->frameHeight};
  RECT textInsets = {0, 0, 0, 0};
  topicText->IDeluxeText(scrollView, textOffset, textSize, &textInsets, &textStyle, -2);

  topicListText = topicText;
  scrollView->contentView = topicText;
  scrollView->Reset();
}

// FUNCTION: IMPERIALISM 0x00503ed0
void THelpPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::DoEvent(commandId, sourceHandler, event);
  if (commandId != 0xd) {
    return;
  }

  switch (sourceHandler->controlTag) {
  case kControlTagMore: // 'more'
    PlayDefaultMessageBeep(1);
    return;
  case kControlTagNam1: // 'nam1'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(1);
    return;
  case kControlTagNam2: // 'nam2'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(2);
    return;
  case kControlTagNam3: // 'nam3'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(3);
    return;
  case kControlTagNam4: // 'nam4'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(4);
    return;
  case kControlTagNam5: // 'nam5'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopic(5);
    return;
  case kControlTagNext: // 'next'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowNextHelpSet();
    return;
  case kControlTagPrev: // 'prev'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowPreviousHelpSet();
    return;
  case kControlTagTogl: // 'togl'
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
    ShowTopicList();
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00504120
void THelpPicture::ShowNextHelpSet() {
  HelpSetRecord* next = 0;
  TPtrList* list = g_pHelpMgr->indexList;
  for (int index = 1; index <= list->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(list->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpResourceBaseId == currentHelpSet->nextHelpResourceBaseId) {
      next = record;
      break;
    }
  }
  if (next != 0) {
    currentHelpSet = next;
  }
  ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x005041a0
void THelpPicture::ShowPreviousHelpSet() {
  HelpSetRecord* previous = 0;
  TPtrList* list = g_pHelpMgr->indexList;
  for (int index = 1; index <= list->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(list->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpResourceBaseId == currentHelpSet->previousHelpResourceBaseId) {
      previous = record;
      break;
    }
  }
  if (previous != 0) {
    currentHelpSet = previous;
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

  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(kControlTagSubj)); // 'subj'
  subject->SetTextWithStrListID(currentHelpSet->helpResourceBaseId,
                                     static_cast<short>(topic + 1), true);
  subject->Show(1, 1);
  subject->ViewEnable(0, 1);
  subject->SetJustification(1, false);
  subject->InstallTextStyle(captionStyle, 0);

  TStaticText* toggle = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTogl)); // 'togl'
  toggle->Show(1, 1);
  toggle->ViewEnable(1, 1);
  toggle->SetJustification(1, false);
  toggle->InstallTextStyle(normalStyle, 0);

  for (int index = 0; index < 5; ++index) {
    TView* topicName = ResolveControlByTag(kControlTagNam1 + index); // 'nam1'..'nam5'
    topicName->Show(0, 1);
    topicName->ViewEnable(0, 1);
  }

  TStaticText* previous = static_cast<TStaticText*>(ResolveControlByTag(kControlTagPrev)); // 'prev'
  g_pSimMgr->GetString(0x2749, 0xd, &navigationText);
  previous->SetTextAndMaybeRefresh(&navigationText, true);
  previous->Show(0, 1);
  previous->ViewEnable(0, 1);
  previous->SetJustification(-1, false);
  previous->InstallTextStyle(normalStyle, 0);

  TStaticText* next = static_cast<TStaticText*>(ResolveControlByTag(kControlTagNext)); // 'next'
  g_pSimMgr->GetString(0x2749, 0xe, &navigationText);
  next->SetTextAndMaybeRefresh(&navigationText, true);
  next->Show(0, 1);
  next->ViewEnable(0, 1);
  next->SetJustification(-1, false);
  next->InstallTextStyle(normalStyle, 0);

  topicListText->Show(1, 0);

  TScrollView* scrollView =
      static_cast<TScrollView*>(ResolveControlByTag(kControlTagSwin)); // 'swin'
  scrollView->AssertValid();
  scrollView->Show(1, 0);
  topicListText->LoadTextResource(
      static_cast<short>(currentHelpSet->helpResourceBaseId + topic));

  int textHeight = topicListText->MeasureCurrentTextHeightInLayoutRect() + 8;

  CRect scrollBounds;
  scrollView->QueryBounds(&scrollBounds);
  scrollBounds.top = 0x92;
  scrollBounds.bottom = 0x135;
  scrollView->ApplyBounds(&scrollBounds, true);

  CRect textBounds;
  if (textHeight < 0xa3) {
    scrollView->QueryBounds(&textBounds);
    textBounds.top += 10;
    scrollView->ApplyBounds(&textBounds, false);
  }

  topicListText->QueryBounds(&textBounds);
  textBounds.top = 0;
  textBounds.bottom = textHeight;
  topicListText->ApplyBounds(&textBounds, false);
  scrollView->Reset();
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

  TStaticText* subject = static_cast<TStaticText*>(ResolveControlByTag(kControlTagSubj)); // 'subj'
  subject->SetTextWithStrListID(currentHelpSet->helpResourceBaseId, 1, true);
  subject->Show(1, 1);
  subject->ViewEnable(0, 1);
  subject->SetJustification(1, false);
  subject->InstallTextStyle(captionStyle, 0);

  TStaticText* toggle = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTogl)); // 'togl'
  toggle->Show(0, 1);
  toggle->ViewEnable(0, 1);
  toggle->SetTextWithStrListID(0x2749, 9, true);

  int topicIndex;
  for (topicIndex = 0; topicIndex < currentHelpSet->topicCount; ++topicIndex) {
    TStaticText* topicName =
        static_cast<TStaticText*>(ResolveControlByTag(kControlTagNam1 + topicIndex)); // 'nam1'..
    topicName->SetTextWithStrListID(currentHelpSet->helpResourceBaseId,
                                         static_cast<short>(topicIndex + 2), true);
    topicName->Show(1, 1);
    topicName->ViewEnable(1, 1);
    topicName->SetJustification(-2, false);
    topicName->InstallTextStyle(normalStyle, 0);
  }

  for (int unusedTopicTag = currentHelpSet->topicCount + kControlTagNam1;
       unusedTopicTag < kControlTagNam6; ++unusedTopicTag) { // 'nam1'..'nam5'
    TView* topicName = ResolveControlByTag(unusedTopicTag);
    topicName->Show(0, 1);
    topicName->ViewEnable(0, 1);
  }

  bool navigationAvailable = currentHelpSet->previousHelpResourceBaseId != 0;
  TStaticText* previous = static_cast<TStaticText*>(ResolveControlByTag(kControlTagPrev)); // 'prev'
  g_pSimMgr->GetString(0x2749, 0xd, &navigationText);
  previous->SetTextAndMaybeRefresh(&navigationText, true);
  previous->Show(navigationAvailable, 1);
  previous->ViewEnable(navigationAvailable, 1);
  previous->SetJustification(-1, false);
  previous->InstallTextStyle(normalStyle, 0);

  navigationAvailable = currentHelpSet->nextHelpResourceBaseId != 0;
  TStaticText* next = static_cast<TStaticText*>(ResolveControlByTag(kControlTagNext)); // 'next'
  g_pSimMgr->GetString(0x2749, 0xe, &navigationText);
  next->SetTextAndMaybeRefresh(&navigationText, true);
  next->Show(navigationAvailable, 1);
  next->ViewEnable(navigationAvailable, 1);
  next->SetJustification(-1, false);
  next->InstallTextStyle(normalStyle, 0);

  topicListText->Show(0, 1);

  TScrollView* scrollView =
      static_cast<TScrollView*>(ResolveControlByTag(kControlTagSwin)); // 'swin'
  scrollView->AssertValid();
  scrollView->Show(0, 1);
  RefreshControl();
  helpDialog->ForceRedraw();
}
