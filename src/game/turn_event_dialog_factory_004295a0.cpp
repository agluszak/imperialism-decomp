#include "game/turn_event_dialog_factory.h"

#include "game/TBook.h"
#include "game/TCluster.h"
#include "game/TControl.h"
#include "game/TDeluxeText.h"
#include "game/TCouncilPanelView.h"
#include "game/TDiplomacyMapView.h"
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
#include "game/TGrantsView.h"
#include "game/TInfoBarText.h"
#include "game/TInfoPanelView.h"
#include "game/TMapKey.h"
#include "game/TOffersPanelView.h"
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
#include "game/TTradePanelView.h"
#include "game/TTreatiesView.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_resource_builder.h"

#include "game/turn_event_dialog_builder_detail.h"

namespace {
// Screen-local control tags for the 0x7d8 (diplomacy map) resource tree; only used by
// this builder, so kept local rather than in the shared ui_control_tags.h.
const unsigned int kTagNameView = 0x76696577u; // 'view' -- nameTag, unused by the callee
const unsigned int kTagMkey = 0x6d6b6579u;     // 'mkey' -- map-key legend picture
const unsigned int kTagOvr0 = 0x6f767230u;
const unsigned int kTagOvr1 = 0x6f767231u;
const unsigned int kTagOvr2 = 0x6f767232u;
const unsigned int kTagOvr4 = 0x6f767234u;
const unsigned int kTagDocs = 0x646f6373u;
const unsigned int kTagDoc0 = 0x646f6330u;
const unsigned int kTagDoc1 = 0x646f6331u;
const unsigned int kTagDoc2 = 0x646f6332u;
const unsigned int kTagDoc3 = 0x646f6333u;
const unsigned int kTagDoc4 = 0x646f6334u;
const unsigned int kTagDoc5 = 0x646f6335u;
const unsigned int kTagDoc6 = 0x646f6336u;
const unsigned int kTagDoc7 = 0x646f6337u;
const unsigned int kTagScro = 0x7363726fu;
const unsigned int kTagScr0 = 0x73637230u;
const unsigned int kTagScr1 = 0x73637231u;
const unsigned int kTagScr2 = 0x73637232u;
const unsigned int kTagScr3 = 0x73637233u;
const unsigned int kTagScr4 = 0x73637234u;
const unsigned int kTagScr5 = 0x73637235u;
const unsigned int kTagScr6 = 0x73637236u;
const unsigned int kTagTraA = 0x74726161u;
const unsigned int kTagTraB = 0x74726162u;
const unsigned int kTagTraC = 0x74726163u;
const unsigned int kTagTraD = 0x74726164u; // 'trad' icon tag; kControlTagTrad names this FourCC
                                           // for the sibling trade-panel view tag
const unsigned int kTagTraE = 0x74726165u;
const unsigned int kTagTraF = 0x74726166u;
const unsigned int kTagTraG = 0x74726167u;
const unsigned int kTagLink = 0x6c696e6bu;
const unsigned int kTagShee = 0x73686565u;
const unsigned int kTagWait = 0x77616974u;
const unsigned int kTagToo2 = 0x746f6f32u;
const unsigned int kTagToo3 = 0x746f6f33u;
} // namespace

// Event 0x7d8 (diplomacy map): a 'base' TView container (2000x2000) holding a 640x480
// 'main' TDiplomacyMapView (bitmap 0x1388), which parents: the six minister action-topic
// panels (TInfoPanelView/TTreatiesView/TGrantsView/TTradePanelView/TOffersPanelView/
// TCouncilPanelView, tags info/trty/gran/trad/coun/offr) each with its own picture/cluster
// content; the 'ltab'/'rtab' TPicture selection brackets; five 'cntl' TClickZone hover-text
// zones (inft/cout/trtt/grat/trat); a 'too2' toolbar hosting a 'quer' TPictureButton; a
// 'too3' toolbar hosting an 'end ' TPictureButton; a 'topB' toolbar of four
// TUpDownPictureButtons (tran/city/trad/dipl); a 'curs' TInfoBarText; and a 'tool' toolbar
// hosting 'seas'/'trea' TDropShadowText labels.
// FUNCTION: IMPERIALISM 0x004295a0
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(CWnd* pHostWindow, int nEventCode) {
  g_pUiResourceHead = 0;
  switch (static_cast<short>(nEventCode)) {
  case 0x7d8: {
    RegisterUiResourceEntry(kTagNameView, kControlTagBase, new TView(), 0, 0, 0x7d0, 0x7d0, 0, 1, 0,
                            0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kControlTagMain, new TDiplomacyMapView(), 0, 0, 0x280,
                            0x1e0, 1, 1, kControlTagBase, 0);
    SetUiResourceStateFlags(1, 1);
    ReplaceUiResourceContextPairBuffer(0, 0xffffff);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1388);
    ClearUiResourceContext();

    // --- info panel (TInfoPanelView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagInfo, new TInfoPanelView(), 0x39, 0x162, 0x206,
                            0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kTagMkey, new TMapKey(), 0x10c, 0x3, 0xf1, 0x75, 0, 1,
                            kControlTagInfo, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1393);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagMkey);

    RegisterUiResourceEntry(kControlTagClus, kControlTagClus, new TCluster(), 0xee, 0x4, 0x24, 0x75,
                            0, 1, kControlTagInfo, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kTagOvr2, new TRadioPictureButton(), 0x6, 0x5e, 0x19,
                            0x19, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13f2);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagOvr2);

    RegisterUiResourceEntry(kControlTagPict, kTagOvr0, new TRadioPictureButton(), 0x6, -1, 0x19,
                            0x2d, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13ec);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagOvr0);

    RegisterUiResourceEntry(kControlTagPict, kTagOvr4, new TRadioPictureButton(), 0x6, 0x2c, 0x19,
                            0x19, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13ee);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagOvr4);

    RegisterUiResourceEntry(kControlTagPict, kTagOvr1, new TRadioPictureButton(), 0x6, 0x45, 0x19,
                            0x19, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13f0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagOvr1);
    PopUiResourcePoolNode(kControlTagClus);
    PopUiResourcePoolNode(kControlTagInfo);

    // --- grants panel (TGrantsView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagGran, new TGrantsView(), 0x39, 0x320, 0x206,
                            0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, 0x20202020, new TPicture(), 0x132, 0x3, 0x87, 0xf, 0,
                            1, kControlTagGran, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a6);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x20202020u);

    RegisterUiResourceEntry(kControlTagClus, kTagDocs, new TCluster(), 0x6, 0x2d, 0x1fe, 0x3c, 0, 1,
                            kControlTagGran, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kTagDoc7, new TRadioPictureButton(), 0x1ce, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc7);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc6, new TRadioPictureButton(), 0x1a2, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a7);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc6);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc5, new TRadioPictureButton(), 0x146, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc5);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc4, new TRadioPictureButton(), 0x11a, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a7);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc4);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc3, new TRadioPictureButton(), 0xbd, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc3);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc2, new TRadioPictureButton(), 0x91, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a7);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc2);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc1, new TRadioPictureButton(), 0x34, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc1);

    RegisterUiResourceEntry(kControlTagPict, kTagDoc0, new TRadioPictureButton(), 0x8, 0x8, 0x2a,
                            0x37, 1, 1, kTagDocs, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a7);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagDoc0);
    PopUiResourcePoolNode(kTagDocs);
    PopUiResourcePoolNode(kControlTagGran);

    // --- treaty panel (TTreatiesView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagTrty, new TTreatiesView(), 0x39, 0x320, 0x206,
                            0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagClus, kTagScro, new TCluster(), 0xe, 0xe, 0x1e4, 0x63, 0, 1,
                            kControlTagTrty, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kTagScr6, new TRadioPictureButton(), 0x155, 0x2, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x139e);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr6);

    RegisterUiResourceEntry(kControlTagPict, kTagScr5, new TRadioPictureButton(), 0xde, 0x2, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x139c);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr5);

    RegisterUiResourceEntry(kControlTagPict, kTagScr3, new TRadioPictureButton(), 0x1a, 0x5, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1398);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr3);

    RegisterUiResourceEntry(kControlTagPict, kTagScr4, new TRadioPictureButton(), 0x1a, 0x39, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x139a);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr4);

    RegisterUiResourceEntry(kControlTagPict, kTagScr2, new TRadioPictureButton(), 0xab, 0x39, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr2);

    RegisterUiResourceEntry(kControlTagPict, kTagScr1, new TRadioPictureButton(), 0x118, 0x39, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a2);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr1);

    RegisterUiResourceEntry(kControlTagPict, kTagScr0, new TRadioPictureButton(), 0x181, 0x39, 0x4b,
                            0x24, 1, 1, kTagScro, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13a4);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagScr0);
    PopUiResourcePoolNode(kTagScro);
    PopUiResourcePoolNode(kControlTagTrty);

    // --- trade panel (TTradePanelView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagTrad, new TTradePanelView(), 0x39, 0x320,
                            0x206, 0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagClus, kControlTagClus, new TCluster(), 0x6, 0x8, 0x1fa, 0x6e,
                            0, 1, kControlTagTrad, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kTagTraA, new TRadioPictureButton(), 0x5, 0x12, 0x2b,
                            0x32, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13ab);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraA);

    RegisterUiResourceEntry(kControlTagPict, kTagTraB, new TRadioPictureButton(), 0x38, 0x1d, 0x2b,
                            0x3c, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13ad);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraB);

    RegisterUiResourceEntry(kControlTagPict, kTagTraC, new TRadioPictureButton(), 0x6b, 0x12, 0x2b,
                            0x32, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13af);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraC);

    RegisterUiResourceEntry(kControlTagPict, kTagTraD, new TRadioPictureButton(), 0x9e, 0x1d, 0x2b,
                            0x3c, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13b1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraD);

    RegisterUiResourceEntry(kControlTagPict, kTagTraE, new TRadioPictureButton(), 0xd1, 0x12, 0x2b,
                            0x32, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13b3);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraE);

    RegisterUiResourceEntry(kControlTagPict, kTagTraF, new TRadioPictureButton(), 0x104, 0x1d, 0x2b,
                            0x3c, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13b5);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraF);

    RegisterUiResourceEntry(kControlTagPict, kTagTraG, new TRadioPictureButton(), 0x166, 0x21, 0x2b,
                            0x2c, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13b7);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagTraG);

    RegisterUiResourceEntry(kControlTagPict, kTagLink, new TRadioPictureButton(), 0x1c3, 0x21, 0x34,
                            0x2c, 1, 1, kControlTagClus, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xc, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13b9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kTagLink);
    PopUiResourcePoolNode(kControlTagClus);
    PopUiResourcePoolNode(kControlTagTrad);

    // --- offers panel (TOffersPanelView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagOffr, new TOffersPanelView(), 0x39, 0x320,
                            0x206, 0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagClus, kTagShee, new TCluster(), 0x8, 0x7, 0x1f6, 0x6c, 0, 1,
                            kControlTagOffr, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagTevw, kControlTagProp, new TDeluxeText(), 0x71, 0xc, 0x123,
                            0x5c, 0, 1, kTagShee, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagProp);

    RegisterUiResourceEntry(kControlTagPict, 0x72656a65u, new TUpDownPictureButton(), 0xc, 0x1a,
                            0x4b, 0x46, 1, 1, kTagShee, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x20d8);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x72656a65u);

    RegisterUiResourceEntry(kControlTagPict, 0x61636365u, new TUpDownPictureButton(), 0x1a7, 0x1a,
                            0x4b, 0x46, 1, 1, kTagShee, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x20d6);
    ClearUiResourceContext();
    PopUiResourcePoolNode(0x61636365u);
    PopUiResourcePoolNode(kTagShee);

    RegisterUiResourceEntry(kControlTagClus, kTagWait, new TCluster(), 0x8, 0x7, 0x1f6, 0x6c, 0, 1,
                            kControlTagOffr, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagTevw, kControlTagText, new TDeluxeText(), 0x71, 0xc, 0x123,
                            0x5c, 0, 1, kTagWait, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagText);
    PopUiResourcePoolNode(kTagWait);
    PopUiResourcePoolNode(kControlTagOffr);

    // --- 'too2' toolbar: query-floater launcher ---
    RegisterUiResourceEntry(kControlTagClus, kTagToo2, new TToolBarCluster(), 0x260, 0x27, 0x17,
                            0x27, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kControlTagQuer, new TPictureButton(), 0, 0, 0x17,
                            0x27, 1, 0, kTagToo2, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13bc);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagQuer);
    PopUiResourcePoolNode(kTagToo2);

    // --- selection brackets and hover-text zones ---
    RegisterUiResourceEntry(kControlTagPict, kControlTagLtab, new TPicture(), 0x11, 0x163, 0x28,
                            0x78, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x1389);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagLtab);

    RegisterUiResourceEntry(kControlTagPict, kControlTagRtab, new TPicture(), 0x242, 0x163, 0x28,
                            0x78, 0, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x138b);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagRtab);

    RegisterUiResourceEntry(kControlTagCntl, kControlTagInft, new TClickZone(), 0x10, 0x174, 0x27,
                            0x2a, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagInft);

    RegisterUiResourceEntry(kControlTagCntl, kControlTagCout, new TClickZone(), 0xf, 0x1a0, 0x27,
                            0x2a, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCout);

    RegisterUiResourceEntry(kControlTagCntl, kControlTagTrtt, new TClickZone(), 0x24d, 0x167, 0x1c,
                            0x25, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagTrtt);

    RegisterUiResourceEntry(kControlTagCntl, kControlTagGrat, new TClickZone(), 0x24d, 0x18c, 0x1c,
                            0x25, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagGrat);

    RegisterUiResourceEntry(kControlTagCntl, kControlTagTrat, new TClickZone(), 0x24d, 0x1b1, 0x1c,
                            0x25, 1, 0, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0x14, 0, 0, 0, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagTrat);

    // --- council panel (TCouncilPanelView) ---
    RegisterUiResourceEntry(kTagNameView, kControlTagCoun, new TCouncilPanelView(), 0x39, 0x320,
                            0x206, 0x7a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCoun);

    // --- 'too3' toolbar: end-turn launcher ---
    RegisterUiResourceEntry(kControlTagClus, kTagToo3, new TToolBarCluster(), 0x3, 0x20, 0x25, 0x3e,
                            0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kControlTagEndSpace, new TPictureButton(), 0x5, 0x6,
                            0x1e, 0x34, 1, 0, kTagToo3, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x13bb);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagEndSpace);
    PopUiResourcePoolNode(kTagToo3);

    // --- 'topB' toolbar: top-banner popup launchers ---
    RegisterUiResourceEntry(kControlTagClus, kControlTagTopB, new TToolBarCluster(), 0x10b, 0x5,
                            0x69, 0x1a, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagPict, kControlTagTran, new TUpDownPictureButton(), 0x3, 0x3,
                            0xe, 0x12, 1, 1, kControlTagTopB, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24ef);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagTran);

    RegisterUiResourceEntry(kControlTagPict, kControlTagCity, new TUpDownPictureButton(), 0x1f, 0x3,
                            0xe, 0x12, 1, 1, kControlTagTopB, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24ed);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCity);

    RegisterUiResourceEntry(kControlTagPict, kControlTagTrad, new TUpDownPictureButton(), 0x3b, 0x3,
                            0xe, 0x12, 1, 1, kControlTagTopB, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24eb);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagTrad);

    RegisterUiResourceEntry(kControlTagPict, kControlTagDipl, new TUpDownPictureButton(), 0x58, 0x3,
                            0xe, 0x12, 1, 1, kControlTagTopB, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xa, 0, 0, 0, 0);
    SetUiResourceContextPictureId(0x24e9);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagDipl);
    PopUiResourcePoolNode(kControlTagTopB);

    // --- map cursor readout ---
    RegisterUiResourceEntry(kControlTagTevw, kControlTagCurs, new TInfoBarText(), 0x18c, 0x5, 0xc9,
                            0x1e, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 0);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagCurs);

    // --- 'tool' toolbar: season/treasury readout ---
    RegisterUiResourceEntry(kControlTagClus, kControlTagTool, new TToolBarCluster(), 0x3, 0x6, 0xda,
                            0x1d, 0, 1, kControlTagMain, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(5, 0, 0, 0, 0);
    SetUiResourceContextStringCode(0x20202020);
    ClearUiResourceContext();

    RegisterUiResourceEntry(kControlTagStat, kControlTagSeas, new TDropShadowText(), 0x2c, 0x4,
                            0x5e, 0x11, 0, 1, kControlTagTool, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0xce4, 1, g_szUiPlaceholderSeason_006943BC, 3, 0, 9, 0, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagSeas);

    RegisterUiResourceEntry(kControlTagStat, kControlTagTrea, new TDropShadowText(), 0x8d, 0x4,
                            0x4b, 0x11, 0, 1, kControlTagTool, 0);
    SetUiResourceStateFlags(1, 1);
    SetUiResourceLayoutValues(0xd, 0, 0, 0, 0);
    BindUiResourceTextAndStyle(0xce4, 2, g_szUiPlaceholderTreasury_006943B0, 3, 0, 9, 0, 1);
    ClearUiResourceContext();
    PopUiResourcePoolNode(kControlTagTrea);
    PopUiResourcePoolNode(kControlTagTool);
    PopUiResourcePoolNode(kControlTagMain);
    PopUiResourcePoolNode(kControlTagBase);
    break;
  }
  default:
    return nullptr;
  }

  if (g_pUiResourceHead != 0) {
    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);
  }
  return g_pUiResourceHead;
}
