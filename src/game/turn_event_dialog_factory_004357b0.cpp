#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TDropShadowNumberText.h"
#include "game/TDropShadowText.h"
#include "game/TDlgWindow.h"
#include "game/TEditText.h"
#include "game/TGWorldPartView.h"
#include "game/TMapPreviewView.h"
#include "game/TRadioText.h"
#include "game/TRadioTextCluster.h"
#include "game/TSetupRandomMapPicture.h"
#include "game/TGameSetupPicture.h"
#include "game/TMyNumberText.h"
#include "game/TNoHilitePicture.h"
#include "game/TPageView.h"
#include "game/TScrollView.h"
#include "game/TSidewaysArrow.h"
#include "game/TSliderPicture.h"
#include "game/TTechHistoryView.h"
#include "game/TTechStorePage.h"
#include "game/TGameWindow.h"
#include "game/TInfoBarText.h"
#include "game/TPicture.h"
#include "game/TPictureButton.h"
#include "game/TStaticText.h"
#include "game/TToolBarCluster.h"
#include "game/TTradeCluster.h"
#include "game/TTradeOrderPicture.h"
#include "game/TTradeScreenPicture.h"
#include "game/TTraderAmtBar.h"
#include "game/TMovieView.h"
#include "game/TUpDownPictureButton.h"
#include "game/TView.h"
#include "game/TWindow.h"
#include "game/TFloatWindow.h"
#include "game/TUniversityView.h"
#include "game/TArmyInfoView.h"
#include "game/TArmyPlacard.h"
#include "game/TArmyToolbar.h"
#include "game/TCivDescription.h"
#include "game/TCivReport.h"
#include "game/TCivToolbar.h"
#include "game/TColorKeyPicture.h"
#include "game/TCombatReportView.h"
#include "game/TCzechBox.h"
#include "game/TGamePreferencesPicture.h"
#include "game/TLoadSavePicture.h"
#include "game/TMadnessButton.h"
#include "game/TNoHiliteText.h"
#include "game/TTwoPicSlider.h"
#include "game/TEngineerDialog.h"
#include "game/TGarrisonView.h"
#include "game/TMapDialog.h"
#include "game/TMapUberPicture.h"
#include "game/TNavyRoster.h"
#include "game/TNavyToolbarCluster.h"
#include "game/TNumberText.h"
#include "game/TNumberedArrowButton.h"
#include "game/TOceanDialog.h"
#include "game/TPageCorner.h"
#include "game/TRadioPictureButton.h"
#include "game/TShipFractionCluster.h"
#include "game/TShipPlacard.h"
#include "game/TCitySiteView.h"
#include "game/TClickZone.h"
#include "game/TGameScorePicture.h"
#include "game/TGameSetupMultiplayerPicture.h"
#include "game/THighScoresPicture.h"
#include "game/TMyStaticText.h"
#include "game/TNetSelectPicture.h"
#include "game/TPlaceCityDialog.h"
#include "game/TScenarioChooser.h"
#include "game/TSpecialQuitPicture.h"
#include "game/TTEView.h"
#include "game/TTextList.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_resource_builder.h"

#include "game/turn_event_dialog_builder_detail.h"

// Screen-builder helpers used only by BuildTurnEventDialogUiByCode's switch
// (0x11f8/0x3a98/0x7d1/0x7d2 cases). static __inline: /Ob1 folds them in.
static __inline TView* BuildTurnOrderNavigationWindow(int offsetX, int offsetY, int width,
                                                      int height, unsigned short layoutModeWord) {
  TGameWindow* window = new TGameWindow();
  if (window == 0) {
    return 0;
  }

  if (g_pUiResourceHead == 0) {
    g_pUiResourceHead = window;
  }
  g_pUiResourceContext = window;

  PushUiWidgetBuildStackNode(window);

  int offsetLayout[2] = {offsetX, offsetY};
  int sizeLayout[2] = {width, height};
  window->InitializeUiResourceEntryFrameAndParent(0, 0, offsetLayout, sizeLayout, 0, 0, 1);

  window->controlTag = static_cast<int>(kControlTagWind);
  window->controlValue3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(width, 0);
  window->inputGateFlag4c = 1;
  window->childHitTestFlag4d = 1;

  if (window->stylePayload48 != 0) {
    delete window->stylePayload48;
    window->stylePayload48 = 0;
  }
  window->EnsureField48Buffer();
  if (window->stylePayload48 != 0) {
    window->stylePayload48->Reset();
    window->stylePayload48->styleWord = 0;
    window->stylePayload48->packedColor = 0xffffff;
  }

  window->useCaptionedFrameFlag6d = 0;
  window->flag6e = 1;
  window->flag6f = 1;
  window->flag71 = 1;
  window->windowStyleType = static_cast<short>(layoutModeWord);
  window->field9c = 8;

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

// Startup intro screen (event code 0x11f8): a root TView container ('base' tag, a
// large logical 2000x2000 layout area) holding a full-screen 640x480 TPicture ('main'
// tag) that loads bitmap resource 0x11f7. Verified against the retail disassembly at
// 0x0043b1cb (inside BuildTurnEventDialogUiByCode's body — Ghidra reports that whole
// function as 25768 bytes; this is one of its many event-code cases, not a separate
// function).
//
// Hosting mechanism (bd 1uj.10): this tree deliberately propagates a null native
// window here, exactly like the other factories. The real host hookup happens after
// the factory returns: the tree is attached under the TIncludeView packet (which
// inherited the main view's nativeWindow50), and the packet's NoOpUiLifecycleHook tail
// sends message 0x4ef (wParam 1) to that window — CIncludeView::OnDialogTreeHostMsg4EF
// then re-propagates the CIncludeView itself as every node's native window and
// re-resolves 'main'. Painting flows through CIncludeView::OnDraw's slot-0x43
// recursion over the hosted tree.
static __inline TView* BuildStartupIntroBackground() {
  TView* parent;

  TView* container = new TView();
  if (container == 0) {
    return 0;
  }

  g_pUiResourceContext = container;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = container;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(container);

  int containerOffset[2] = {0, 0};
  int containerSize[2] = {0x7d0, 0x7d0};
  container->InitializeUiResourceEntryFrameAndParent(0, parent, containerOffset, containerSize, 0,
                                                     0, 1);
  container->controlTag = static_cast<int>(kControlTagBase);
  container->controlValue3c = 0;
  container->SetEnabled(1, 0);
  container->SetState(containerSize[0], 0);

  TPicture* background = new TPicture();
  if (background != 0) {
    g_pUiResourceContext = background;
    if (g_pUiResourceHead != 0) {
      parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
    } else {
      g_pUiResourceHead = background;
      parent = 0;
    }
    PushUiWidgetBuildStackNode(background);

    int pictureOffset[2] = {0, 0};
    int pictureSize[2] = {0x280, 0x1e0};
    background->InitializeUiResourceEntryFrameAndParent(0, parent, pictureOffset, pictureSize, 0, 0,
                                                        1);
    background->controlTag = static_cast<int>(kControlTagMain);
    background->controlValue3c = 0;
    background->SetEnabled(1, 0);
    background->SetState(pictureSize[0], 0);

    background->EnsureField48Buffer();
    if (background->stylePayload48 != 0) {
      background->stylePayload48->styleWord = 0;
      background->stylePayload48->packedColor = 0xffffff;
    }

    background->frameStyle60 = 0xa;
    background->contentInsets68.left = 0;
    background->contentInsets68.top = 0;
    background->contentInsets68.right = 0;

    background->SetPictureResourceIdAndRefresh(0x11f7, 0);

    TMovieView* movie = new TMovieView();
    if (movie != 0) {
      g_pUiResourceContext = movie;
      if (g_pUiResourceHead != 0) {
        parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
      } else {
        g_pUiResourceHead = movie;
        parent = 0;
      }
      PushUiWidgetBuildStackNode(movie);

      int movieOffset[2] = {0xc8, 0x64};
      int movieSize[2] = {0x11c, 0xe8};
      movie->InitializeUiResourceEntryFrameAndParent(0, parent, movieOffset, movieSize, 0, 0, 1);
      movie->controlTag = static_cast<int>(kControlTagMovi);
      movie->controlValue3c = 0;
      movie->SetEnabled(1, 0);
      movie->SetState(1, 0);

      movie->EnsureField48Buffer();
      if (movie->stylePayload48 != 0) {
        movie->stylePayload48->styleWord = 0;
        movie->stylePayload48->packedColor = 0xffffff;
      }

      movie->frameStyle60 = 0xa;
      movie->contentInsets68.left = 0;
      movie->contentInsets68.top = 0;
      movie->contentInsets68.right = 0;

      movie->SetPictureResourceIdAndRefresh(0x11f7, 0);
      PopUiWidgetBuildStackNode();
    }
    PopUiWidgetBuildStackNode();
  }

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

// Event 0x3a98 (keystone case at 0x0043b099): a single bare 200x200 'WIND' window at
// (0x9c,0x38) with the gold dialog behavior. Unlike the sibling cases, the original
// case body uses the expanded (non-helper) idiom: field writes re-read
// g_pUiResourceContext per statement group, and the pop is a direct RemoveTail.
static __inline TView* BuildBareGoldEventWindow3A98() {
  TView* parent;

  TWindow* window = new TWindow();
  g_pUiResourceContext = window;
  if (g_pUiResourceHead != 0) {
    parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());
  } else {
    g_pUiResourceHead = window;
    parent = 0;
  }
  PushUiWidgetBuildStackNode(window);

  int offset[2];
  int size[2];
  offset[0] = 0x9c;
  offset[1] = 0x38;
  size[0] = 0xc8;
  size[1] = 0xc8;
  window->InitializeUiResourceEntryFrameAndParent(0, parent, offset, size, 0, 0, 1);
  window->controlTag = static_cast<int>(kControlTagWind);
  window->controlValue3c = 0;
  window->SetEnabled(1, 0);
  window->SetState(1, 0);

  g_pUiResourceContext->inputGateFlag4c = 1;
  g_pUiResourceContext->childHitTestFlag4d = 1;

  TWindow* context = static_cast<TWindow*>(g_pUiResourceContext);
  context->topmostFlag70 = 0;
  context->flag6f = 1;
  context->flag6e = 1;
  context->useCaptionedFrameFlag6d = 0;
  context->flag6c = 1;
  context->flag71 = 1;
  context->field9c = 8;
  context->windowStyleType = 2;

  TWindow* behaviorOwner = static_cast<TWindow*>(g_pUiResourceContext);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetFlag0C(1);
  behaviorOwner->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet(1, 0x20202020,
                                                                              0x20202020);

  g_pUiResourceContext = 0;
  PopUiWidgetBuildStackNode();

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(0);
  }
  return g_pUiResourceHead;
}

// FUNCTION: IMPERIALISM 0x004357b0
TView* __cdecl BuildTurnEventDialogUiByCode(CWnd* pHostWindow, int nEventCode) {
  g_pUiResourceHead = 0;

  switch (static_cast<short>(nEventCode)) {
  case 0x3b6: {
    TDlgWindow* window = new TDlgWindow();
    RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, window, 0x28, 0x28, 0x226,
                            0x15e, 1, 1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceContextFlagsAndMetrics(8, 3, 0, 0, 0, 0, 0, 1);
    ApplyUiResourceColorTripletFromContext(1, 0, 0x20202020, 0x20202020);
    ClearUiResourceContext();

    TNoHilitePicture* backdrop = new TNoHilitePicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, backdrop, 0, 0, 0x226, 0x15e, 1, 1,
                            kControlTagWind, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x3b6);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagOkay);
  } break;

  case 0x3ba: {
    TWindow* window = new TWindow();
    RegisterUiResourceEntry(0x77696e64 /* 'wind' */, kControlTagWind, window, 0xa0, 0x8a, 0xfc,
                            0xb1, 1, 1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);
    ApplyUiResourceColorTripletFromContext(1, 1, 0x20202020, 0x20202020);
    ClearUiResourceContext();

    TPicture* backdrop = new TPicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagGold, backdrop, 0, 0, 0xfc, 0xb1, 0, 1,
                            kControlTagWind, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11b7);
    ClearUiResourceContext();

    TRadioTextCluster* choiceCluster = new TRadioTextCluster();
    RegisterUiResourceEntry(kControlTagClus, 0x316f7232 /* '1or2' */, choiceCluster, 0x27, 0x6e,
                            0xaf, 0x14, 0, 0, kControlTagGold, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    TRadioText* firstChoice = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, 0x6f6e6531 /* 'one1' */, firstChoice, 2, 2, 0x55, 0x10,
                            1, 1, 0x316f7232, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6f6e6531 /* 'one1' */);

    TRadioText* secondChoice = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, 0x74776f32 /* 'two2' */, secondChoice, 0x58, 2, 0x55,
                            0x10, 1, 1, 0x316f7232, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74776f32 /* 'two2' */);
    PopUiResourcePoolNode(0x316f7232 /* '1or2' */);

    TStaticText* instruction = new TStaticText();
    RegisterUiResourceEntry(kControlTagStat, 0x696e7374 /* 'inst' */, instruction, 0x25, 0x16, 0xb6,
                            0x37, 0, 1, kControlTagGold, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, 3, g_szUiPickAPlanet_00694530, 3, 1, 0xc, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x696e7374 /* 'inst' */);

    TEditText* planetName = new TEditText();
    RegisterUiResourceEntry(kControlTagEdit, 0x706c616e /* 'plan' */, planetName, 0x28, 0x4f, 0xaf,
                            0x17, 1, 1, kControlTagGold, 0);
    SetUiResourceStateFlags(1, 0);
    SetUiResourceLayoutValues(6, 3, 3, 3, 3);
    BindUiResourceTextAndStyle(0x3b9, 1, g_szUiDefaultPlanetName_00694528, 3, 0, 0, 0, 1);
    SetUiResourceContextMaxCharCount(0x20);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x706c616e /* 'plan' */);

    TUpDownPictureButton* okay = new TUpDownPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okay, 0x9e, 0x8a, 0x3d, 0x18, 1, 1,
                            kControlTagGold, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24c2);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagOkay);

    TUpDownPictureButton* cancel = new TUpDownPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagCanc, cancel, 0x21, 0x8a, 0x3d, 0x18, 0, 0,
                            kControlTagGold, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x22, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24c4);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCanc);
    PopUiResourcePoolNode(kControlTagGold);
  } break;

  case 0x5de: {
    // Load/Save-game screen (posted by TGameSetupPicture::HandleEvent when the 'load'
    // menu button is clicked; g_nSaveFormatVersion is set to -2 first). A 640x480
    // 'view'/'base' TView holds the 'pict'/'main' TLoadSavePicture backdrop, on which
    // sit eight save-slot labels ('slt0'-'slt7' TNoHiliteText, two columns of four),
    // a cancel click zone ('cncl' TClickZone), a 'plat' TPicture plate parenting the
    // OK button ('okay' TUpDownPictureButton), the map preview ('map ' TMapPreviewView)
    // and an info label ('info' TStaticText), an 'otto' TControl and the cursor info
    // text ('curs' TInfoBarText). Shares the 0x1036 teardown/return tail (0x43bc09):
    // pop 'curs'/'main'/'base' and return g_pUiResourceHead. Slots are emitted in the
    // original's body order (slt0,1,3,2,7,6,5,4), not numeric order.
    TView* base = new TView();
    RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBase, base, 0, 0, 0x280, 0x1e0, 0,
                            1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    TLoadSavePicture* backdrop = new TLoadSavePicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagMain, backdrop, 0, 0, 0x280, 0x1e0, 0, 1,
                            kControlTagBase, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11a8);
    ClearUiResourceContext();

    TNoHiliteText* slot0 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7430 /* 'slt0' */, slot0, 0x48, 0x122, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7430 /* 'slt0' */);

    TNoHiliteText* slot1 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7431 /* 'slt1' */, slot1, 0x48, 0x146, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7431 /* 'slt1' */);

    TNoHiliteText* slot3 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7433 /* 'slt3' */, slot3, 0x49, 0x18a, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7433 /* 'slt3' */);

    TNoHiliteText* slot2 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7432 /* 'slt2' */, slot2, 0x49, 0x168, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7432 /* 'slt2' */);

    TNoHiliteText* slot7 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7437 /* 'slt7' */, slot7, 0x15a, 0x18a, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7437 /* 'slt7' */);

    TNoHiliteText* slot6 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7436 /* 'slt6' */, slot6, 0x15a, 0x168, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7436 /* 'slt6' */);

    TNoHiliteText* slot5 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7435 /* 'slt5' */, slot5, 0x159, 0x146, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7435 /* 'slt5' */);

    TNoHiliteText* slot4 = new TNoHiliteText();
    RegisterUiResourceEntry(kControlTagStat, 0x736c7434 /* 'slt4' */, slot4, 0x159, 0x122, 0xe1,
                            0x15, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736c7434 /* 'slt4' */);

    TClickZone* cancelZone = new TClickZone();
    RegisterUiResourceEntry(kControlTagCntl, 0x636e636c /* 'cncl' */, cancelZone, 2, 0xdd, 0x43,
                            0xfc, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x636e636c /* 'cncl' */);

    TPicture* plate = new TPicture();
    RegisterUiResourceEntry(kControlTagPict, 0x706c6174 /* 'plat' */, plate, 0x122, 1, 0x15e, 0xff,
                            0, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11a9);
    ClearUiResourceContext();

    TUpDownPictureButton* okayButton = new TUpDownPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okayButton, 0xe9, 0xcd, 0x60, 0x1e, 1,
                            1, 0x706c6174 /* 'plat' */, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x11aa);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagOkay);

    TMapPreviewView* mapPreview = new TMapPreviewView();
    RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagMapP, mapPreview, 0xc, 0xd, 0x144,
                            0xb4, 0, 1, 0x706c6174 /* 'plat' */, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagMapP);

    TStaticText* infoText = new TStaticText();
    RegisterUiResourceEntry(kControlTagStat, kControlTagInfo, infoText, 0x14, 0xc5, 0xcd, 0x2b, 0,
                            1, 0x706c6174 /* 'plat' */, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x3e9, 0x10, g_szUiPlaceholderStaticText_00694354, 0, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagInfo);
    PopUiResourcePoolNode(0x706c6174 /* 'plat' */);

    TControl* ottoControl = new TControl();
    RegisterUiResourceEntry(kControlTagCntl, 0x6f74746f /* 'otto' */, ottoControl, 0x47, 0x50, 0xbc,
                            0x31, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6f74746f /* 'otto' */);

    TInfoBarText* cursorText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorText, 0x31, 0x13, 0xc9, 0x1e, 0,
                            1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCurs);
    PopUiResourcePoolNode(kControlTagMain);
    PopUiResourcePoolNode(kControlTagBase);
    if (g_pUiResourceHead != 0) {
      g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
    }
    return g_pUiResourceHead;
  }

  case 0x1036: {
    // Preferences screen (posted by TGameSetupPicture::HandleEvent when the 'pref'
    // menu button is clicked). A 640x480 'view'/'base' TView holds the 'pict'/'main'
    // TGamePreferencesPicture backdrop, on which sit: two AI/watch check boxes
    // ('optc'/'optd' TCzechBox), the flag-madness toggle ('opte' TMadnessButton),
    // the sound/music volume sliders ('soun'/'musi' TTwoPicSlider), a help
    // question-mark button ('quer' TPictureButton in the 'tbr2' TToolBarCluster),
    // five caption labels ('txta'-'txte' TDeluxeText), an auto-save yes/no radio
    // pair ('yess'/'nooo' TRadioText in the 'opca' TRadioTextCluster) with its
    // caption ('tpca' TDeluxeText), the OK button ('okay' TPictureButton in the
    // 'tool' TToolBarCluster) and a cursor-tracking info text ('curs' TInfoBarText).
    // Unlike the 'wind'-rooted cases this one has its own teardown/return tail
    // (original 0x43bc09): it pops 'curs'/'main'/'base' and returns g_pUiResourceHead.
    TView* base = new TView();
    RegisterUiResourceEntry(0x76696577 /* 'view' */, kControlTagBase, base, 0, 0, 0x280, 0x1e0, 0,
                            1, 0, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    TGamePreferencesPicture* backdrop = new TGamePreferencesPicture();
    RegisterUiResourceEntry(kControlTagPict, kControlTagMain, backdrop, 0, 0, 0x280, 0x1e0, 0, 1,
                            kControlTagBase, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1035);
    ClearUiResourceContext();

    TCzechBox* watchAiCheck = new TCzechBox();
    RegisterUiResourceEntry(kControlTagPict, 0x6f707463 /* 'optc' */, watchAiCheck, 0x36, 0x127,
                            0x66, 0x5b, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x103a);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6f707463 /* 'optc' */);

    TCzechBox* autoResolveCheck = new TCzechBox();
    RegisterUiResourceEntry(kControlTagPict, 0x6f707464 /* 'optd' */, autoResolveCheck, 0xc2, 0x127,
                            0x66, 0x5b, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x103c);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6f707464 /* 'optd' */);

    TMadnessButton* madnessToggle = new TMadnessButton();
    RegisterUiResourceEntry(kControlTagPict, 0x6f707465 /* 'opte' */, madnessToggle, 0x186, 0x9c,
                            0xa0, 0xa0, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x103e);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6f707465 /* 'opte' */);

    TTwoPicSlider* soundSlider = new TTwoPicSlider();
    RegisterUiResourceEntry(kControlTagCntl, 0x736f756e /* 'soun' */, soundSlider, 0x36, 0x5c, 0x66,
                            0x5b, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x736f756e /* 'soun' */);

    TTwoPicSlider* musicSlider = new TTwoPicSlider();
    RegisterUiResourceEntry(kControlTagCntl, 0x6d757369 /* 'musi' */, musicSlider, 0xc2, 0x5c, 0x66,
                            0x5b, 1, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6d757369 /* 'musi' */);

    TToolBarCluster* helpToolbar = new TToolBarCluster();
    RegisterUiResourceEntry(kControlTagClus, 0x74627232 /* 'tbr2' */, helpToolbar, 0x25a, 0x24,
                            0x28, 0x2e, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    TPictureButton* helpButton = new TPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagQuer, helpButton, 6, 3, 0x16, 0x26, 1, 0,
                            0x74627232 /* 'tbr2' */, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1031);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagQuer);
    PopUiResourcePoolNode(0x74627232 /* 'tbr2' */);

    TDeluxeText* labelB = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74787462 /* 'txtb' */, labelB, 0xc5, 0xc1, 0x60,
                            0x2f, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74787462 /* 'txtb' */);

    TDeluxeText* labelA = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74787461 /* 'txta' */, labelA, 0x39, 0xc1, 0x60,
                            0x2f, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74787461 /* 'txta' */);

    TDeluxeText* labelC = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74787463 /* 'txtc' */, labelC, 0x39, 0x18c, 0x60,
                            0x2f, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74787463 /* 'txtc' */);

    TDeluxeText* labelD = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74787464 /* 'txtd' */, labelD, 0xc5, 0x18c, 0x60,
                            0x2f, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74787464 /* 'txtd' */);

    TDeluxeText* labelE = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74787465 /* 'txte' */, labelE, 0x1a7, 0x142, 0x60,
                            0x2f, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74787465 /* 'txte' */);

    TRadioTextCluster* autoSaveCluster = new TRadioTextCluster();
    RegisterUiResourceEntry(kControlTagClus, 0x6f706361 /* 'opca' */, autoSaveCluster, 0x172, 0x1ad,
                            0xc3, 0x14, 0, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    TRadioText* autoSaveYes = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, 0x79657373 /* 'yess' */, autoSaveYes, 2, 2, 0x5f, 0x10,
                            1, 1, 0x6f706361 /* 'opca' */, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0xffffff, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x79657373 /* 'yess' */);

    TRadioText* autoSaveNo = new TRadioText();
    RegisterUiResourceEntry(kControlTagStat, 0x6e6f6f6f /* 'nooo' */, autoSaveNo, 0x62, 2, 0x5f,
                            0x10, 1, 1, 0x6f706361 /* 'opca' */, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0x514, -1, g_szEmptyString, 0, 0, 0, 0xffffff, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x6e6f6f6f /* 'nooo' */);
    PopUiResourcePoolNode(0x6f706361 /* 'opca' */);

    TDeluxeText* autoSaveCaption = new TDeluxeText();
    RegisterUiResourceEntry(kControlTagTevw, 0x74706361 /* 'tpca' */, autoSaveCaption, 0x172, 0x17c,
                            0xc3, 0x2f, 0, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x74706361 /* 'tpca' */);

    TToolBarCluster* okayToolbar = new TToolBarCluster();
    RegisterUiResourceEntry(kControlTagClus, kControlTagTool, okayToolbar, 3, 6, 0x40, 0x5b, 0, 1,
                            kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    TPictureButton* okayButton = new TPictureButton();
    RegisterUiResourceEntry(kControlTagPict, kControlTagOkay, okayButton, 5, 0x20, 0x1f, 0x33, 1, 0,
                            kControlTagTool, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1032);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagOkay);
    PopUiResourcePoolNode(kControlTagTool);

    TInfoBarText* cursorText = new TInfoBarText();
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, cursorText, 0x182, 5, 0xc9, 0x1e, 0,
                            1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCurs);
    PopUiResourcePoolNode(kControlTagMain);
    PopUiResourcePoolNode(kControlTagBase);
    if (g_pUiResourceHead != 0) {
      g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
    }
    return g_pUiResourceHead;
  }

  case 0x7d2:
    return BuildTurnOrderNavigationWindow(0, 0x28, 0x280, 0x1e0, 4);
  case 0x7d1:
    return BuildTurnOrderNavigationWindow(5, 0x32, 0x258, 400, 2);
  case 0x3a98:
    return BuildBareGoldEventWindow3A98();
  case 0x11f8:
    return BuildStartupIntroBackground();
  default:
    return 0;
  }

  PopUiResourcePoolNode(kControlTagWind);
  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
