#include "DiplomacyScreen.h"

#include "ModalScreen.h"
#include "RuntimeUiDriver.h"

#include "game/diplomacy_domain_types.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/diplomacy_ui/TOffersPanelView.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/nation_globals.h"
#include "game/nation_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/ui_tags_widgets.h"
#include "game/resource_manifest_tags.h"

namespace {

// The map toolbar's diplomacy button while diplomacy is the current screen.
const short kDiplomacyToolbarSelectedPicture = 0x24ea;

// The minister topic buttons are consecutive tags from a base, which is how the original
// resolves them too: 'ovr0' + n is the nth map overlay, 'scr0' + n the nth treaty action.
const int kRelationshipOverlayIndex = 1;
const int kAllianceActionIndex = 1;
const int kDeclareWarActionIndex = 4;

// Every offer-sheet response control publishes the same command; the sheet distinguishes them
// by tag. A control that does not publish it would be a different widget wearing the tag.
const int kOfferResponseEventNumber = 0xa;

// The treaties topic is the second of the six minister topics.
const int kTreatiesTopicIndex = 1;

} // namespace

DiplomacyScreen::DiplomacyScreen()
    : MainViewScreen(RUNTIME_CLASS(TDiplomacyMapView), kTurnEventDiplomacyMap, "the diplomacy map"),
      diplomacyView(0) {
  diplomacyView = static_cast<TDiplomacyMapView*>(Root());
}

bool DiplomacyScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TDiplomacyMapView), kTurnEventDiplomacyMap);
}

TDiplomacyMapView* DiplomacyScreen::View() const {
  return diplomacyView;
}

bool DiplomacyScreen::HasMinisterControls() const {
  return Find(kControlTagInfo) != 0 && Find(kControlTagTrty) != 0 && Find(kControlTagMkey) != 0 &&
         Find(kControlTagEnd) != 0;
}

bool DiplomacyScreen::ToolbarButtonShowsSelectedArt() const {
  TView* toolbarDialog = g_pDisplayMgr != 0 ? g_pDisplayMgr->activeDialog : 0;
  TView* button = toolbarDialog != 0 ? toolbarDialog->ResolveControlByTag(kControlTagDipl) : 0;
  return button != 0 && button->IsKindOf(RUNTIME_CLASS(TPicture)) != 0 &&
         static_cast<TPicture*>(button)->glyphBase84 == kDiplomacyToolbarSelectedPicture;
}

RuntimeActionResult DiplomacyScreen::SelectNation(short nationSlot) {
  if (diplomacyView == 0) {
    return InvalidScreen("select a nation");
  }
  // The map resolves a click to a nation by hit region; a nation with no country descriptor is
  // not drawn and so cannot be clicked, which would make the call a silent no-op.
  if (nationSlot < 0 || nationSlot >= kNationSlotCount ||
      g_apTerrainTypeDescriptorTable[nationSlot] == 0) {
    CString detail;
    detail.Format("nation %d is not on the map", static_cast<int>(nationSlot));
    return ScreenFailure("select a nation", detail);
  }
  diplomacyView->ActivateNation(nationSlot);
  return RuntimeActionResult::Success();
}

RuntimeActionResult DiplomacyScreen::ShowRelationshipOverlay() {
  return Activate(kControlTagOvr0 + kRelationshipOverlayIndex, "show the relationship overlay");
}

RuntimeActionResult DiplomacyScreen::ShowTreaties() {
  if (diplomacyView == 0) {
    return InvalidScreen("select the treaties topic");
  }
  // A topic change is the view's own method rather than a control activation: the original
  // routes both its own DoEvent and the council view's through this one entry point.
  diplomacyView->ChangeSelectedActionTopic(kTreatiesTopicIndex);
  return RuntimeActionResult::Success();
}

RuntimeActionResult DiplomacyScreen::SelectAllianceAction() {
  return Activate(kControlTagScr0 + kAllianceActionIndex, "select the alliance treaty action");
}

RuntimeActionResult DiplomacyScreen::SelectDeclareWarAction() {
  return Activate(kControlTagScr0 + kDeclareWarActionIndex, "select the declare-war action");
}

RuntimeActionResult DiplomacyScreen::Close() {
  return Activate(kControlTagEnd, "leave the diplomacy map");
}

short DiplomacyScreen::SelectedNation() const {
  return diplomacyView != 0 ? diplomacyView->RuntimeActiveNation() : -1;
}

short DiplomacyScreen::RelationshipOverlaySourceNation() const {
  return diplomacyView != 0 ? diplomacyView->RuntimeRelationshipOverlaySourceNation() : -1;
}

bool DiplomacyScreen::TreatiesTopicIsSelected() const {
  return diplomacyView != 0 && diplomacyView->RuntimeActionTopicIndex() == kTreatiesTopicIndex;
}

bool DiplomacyScreen::TreatiesTopicIsActive() const {
  return TreatiesTopicIsSelected() && diplomacyView->actionCodeBC == kDipActionBuildConsulate;
}

int DiplomacyScreen::ActionCode() const {
  return diplomacyView != 0 ? diplomacyView->actionCodeBC : -1;
}

short DiplomacyScreen::PolicyIconForNation(short nationSlot) {
  return diplomacyView != 0 ? diplomacyView->RuntimeDrawPolicyIconForNation(nationSlot) : -1;
}

TOffersPanelView* DiplomacyScreen::OffersPanel() const {
  TView* panel = Find(kControlTagOffr);
  return panel != 0 && panel->IsKindOf(RUNTIME_CLASS(TOffersPanelView)) != 0
             ? static_cast<TOffersPanelView*>(panel)
             : 0;
}

bool DiplomacyScreen::ResponsePublishesOfferEvent(int responseTag) const {
  TOffersPanelView* offers = OffersPanel();
  TView* response = offers != 0 ? offers->ResolveControlByTag(responseTag) : 0;
  return response != 0 && response->IsKindOf(RUNTIME_CLASS(TControl)) != 0 &&
         static_cast<TControl*>(response)->GetEventNumber() == kOfferResponseEventNumber;
}

bool DiplomacyScreen::AcceptPublishesOfferEvent() const {
  return ResponsePublishesOfferEvent(kControlTagAcce);
}

bool DiplomacyScreen::RejectPublishesOfferEvent() const {
  return ResponsePublishesOfferEvent(kControlTagReje);
}

RuntimeActionResult DiplomacyScreen::ArmResponse(int responseTag, const char* what) {
  if (OffersPanel() == 0) {
    if (!IsValid()) {
      return InvalidScreen(what);
    }
    return ScreenFailure(what, CString("the offers panel is not present"));
  }
  // The sheet does not exist yet: the response is queued against the path it will occupy once
  // PoseOffer builds it, and runs from inside the modal loop that PoseOffer enters.
  return ModalScreen::PreArmDismiss(RuntimeControlSelector(kControlTagOffr, kControlTagShee,
                                                           responseTag, RUNTIME_CLASS(TControl),
                                                           kOfferResponseEventNumber));
}

RuntimeActionResult DiplomacyScreen::ArmAcceptResponse() {
  return ArmResponse(kControlTagAcce, "arm the offer-sheet accept response");
}

RuntimeActionResult DiplomacyScreen::ArmRejectResponse() {
  return ArmResponse(kControlTagReje, "arm the offer-sheet reject response");
}

RuntimeActionResult DiplomacyScreen::PoseNonAggressionOffer(short sourceNation,
                                                            short targetNation) {
  if (diplomacyView == 0) {
    return InvalidScreen("pose a diplomatic offer");
  }
  // Blocks until the armed response answers the sheet.
  diplomacyView->PoseOffer(sourceNation, targetNation,
                           static_cast<short>(kDiplomacyProposalNonAggressionPact));
  return RuntimeActionResult::Success();
}

bool DiplomacyScreen::LastResponseWas(int responseTag) const {
  TOffersPanelView* offers = OffersPanel();
  return offers != 0 && offers->lastNegotiationResponseTag64 == responseTag;
}

bool DiplomacyScreen::LastResponseWasAccept() const {
  return LastResponseWas(kControlTagAcce);
}

bool DiplomacyScreen::LastResponseWasReject() const {
  return LastResponseWas(kControlTagReje);
}
