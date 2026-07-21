#include "game/TArmyUnitView.h"

#include "game/TAssetMgr.h"
#include "game/TDialogBehavior.h"
#include "game/TDisplayMgr.h"
#include "game/TEditText.h"
#include "game/TMapUberPicture.h"
#include "game/TMilitaryUnit.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004a9450
// TArmyUnitView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a94c0
// TArmyUnitView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyUnitView, TView)

// FUNCTION: IMPERIALISM 0x004a94e0
TArmyUnitView::TArmyUnitView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x004a9510
// TArmyUnitView::`scalar deleting destructor'
TArmyUnitView::~TArmyUnitView() {}

// FUNCTION: IMPERIALISM 0x004a95b0
void TArmyUnitView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  CString unitTypeName;
  CString descriptor;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  unitTypeName = field60->name24;
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x10);
  DrawTextWithCachedQuickDrawStyleState(&unitTypeName);

  // Localized unit descriptor: string group 0x2746 substituting a literal 7 for the
  // special-cased unit-type 0xe, otherwise group 0x272c substituting the unit-type code.
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(2, 9, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  int unitTypeCode = field60->field_8;
  if (unitTypeCode == 0xe) {
    g_pSimMgr->GetString(0x2746, 7, &descriptor);
  } else {
    g_pSimMgr->GetString(0x272c, unitTypeCode, &descriptor);
  }
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x1f);
  DrawTextWithCachedQuickDrawStyleState(&descriptor);
  SetQuickDrawFillColor(0);

  short level = field60->field_34;
  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);

  {
    RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
    RECT dstRect = {0x43, 0x26, sVar1 * 4 + 0x42, 0x2d};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x41, 0x21);
  DrawCenteredGuideLineOnMapDc(0x41, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x21);

  short xpPercent = field60->field_38;
  short barWidth = (xpPercent / 100) * 0xb;
  if (xpPercent % 100 > 0x31) {
    barWidth += 5;
  }
  if (barWidth != 0) {
    RECT srcRect = {0, 0, barWidth, 10};
    RECT dstRect = {0x94, 0x18, barWidth + 0x94, 0x22};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x004a9990
void TArmyUnitView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagChec) {
    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
      // Ctrl held: force the unit into escort-order mode (0xe) unless already there.
      if (field60->field_8 != 0xe) {
        field60->SetOrderModeSlot34(0xe, -1);
      }
    } else if (field60->field_8 == 0) {
      field60->SetOrderModeSlot34(0, -1);
    } else {
      field60->SetOrderModeSlot34(3, -1);
    }

    RECT invalidateRect = {0x40, 0x18, 0x108, 0x24};
    InvalidateCityDialogRectRegion(&invalidateRect, 1);

    // The original then resolves a per-order-mode indicator control from the active
    // unit-category page (TMapUberPicture::categoryPages[activeUnitCategoryIndex96],
    // tag computed from a table keyed by field60->orderType) and nudges its count text.
    // The indicator's concrete class is unresolved (its field84 is read as a raw short,
    // unlike TStaticText's CString* field84 at the same offset), so that adjustment is
    // left unmodeled here.
  } else if (sourceHandler->controlTag == kControlTagUpgr) {
    if (field60->ApplyEraCapabilityCostAndSetSelection()) {
      TView* sourceView = static_cast<TView*>(sourceHandler);
      sourceView->SetEnabled(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_pMiniCivSharedText_0064cb18), sourceView);

      TStaticText* checkControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagChec));
      // UNRESOLVED_FIELD_ATTRIBUTION: the original also updates checkControl's
      // field88/field8C icon-index state here (a per-unit-type table lookup keyed by
      // TUnit::orderType) before RefreshControl. field8C is read here as a base pointer
      // for indexing, but TStaticText.cpp's InitializeTextEntryBaseAndOptionalStringResource
      // (src/game/TStaticText.cpp:100) writes it as a plain int (stringResourceIndex) --
      // conflicting readings of the same offset, not yet resolved -- so this table lookup
      // is left unmodeled rather than guessing which reading applies here.
      checkControl->RefreshControl();

      TStaticText* tbr1 = static_cast<TStaticText*>(
          g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagTbr1));
      tbr1->GetNextHandler();
      tbr1->SetTextAlignmentAndMaybeRefresh(static_cast<short>(g_pSimMgr->GetActiveNationId()), 0);
    } else {
      CString msg;
      g_pSimMgr->GetString(0x2745, 3, &msg);
      g_pUiRuntimeContext->ModalMessage(msg, g_ptArmyOrderModalMessage, 2, 0);
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    HandleCrossUArmyViewsNameCommand();
  }
  TView::DoEvent(commandId, sourceHandler, event);
}

// TArmyUnitView-only despite the generic Ghidra symbol name (0x4a9ca0) -- confirmed by the
// caller: TShipView::DoEvent's 'name' branch actually calls a different function
// (RunEngineerOrderNameEditDialogAndApply, 0x565a40), not this one, so there is no
// cross-class field60 ambiguity to resolve here. Runs the unit-rename dialog: seeds an edit
// box with field60's current name, runs it modally, and (unless cancelled) commits the
// typed text back into field60->name24.
// FUNCTION: IMPERIALISM 0x004a9ca0
void TArmyUnitView::HandleCrossUArmyViewsNameCommand() {
  TWindow* node =
      static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0xdb4));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyViews_00695858, 0x204);
  }

  TUiTextStyleDescriptor style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextFromStringResource(0x2746, 1, 1);
  titleControl->textStyle78 = style;

  TEditText* nameControl = static_cast<TEditText*>(node->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  nameControl->maxCharacterCount = 0x18;
  CString editedName;
  editedName = field60->name24;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle78 = style;

  node->SetModality(1);
  TDialogBehavior* behavior = node->GetDialogBehavior();
  if (behavior != nullptr) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  int modalResult = node->PoseModally();
  nameControl->GetCurrentText(&editedName);
  if (modalResult != 0x636e636c /* 'cncl' */) {
    field60->name24 = editedName;
  }
  RefreshControl();
}
