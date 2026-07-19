#include "game/TDealBookPicture.h"

#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTradePageBuyView.h"
#include "game/TTradePageSellView.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control);
void AssignSharedStringToControlState(CString sharedString, TView* control);

// SYNTHETIC: IMPERIALISM 0x005bab00
// TDealBookPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005baba0
// TDealBookPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealBookPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005babc0
TDealBookPicture::TDealBookPicture() : TPicture(), field90(8), fieldB2(0) {}

// SYNTHETIC: IMPERIALISM 0x005bac00
// TDealBookPicture::`scalar deleting destructor'
TDealBookPicture::~TDealBookPicture() {}

// FUNCTION: IMPERIALISM 0x005baf70
void TDealBookPicture::UpdateDealBookResourceSelectionAndToggleControls(int nResourceIndex,
                                                                        short nSelectedRow) {
  CString label;

  if (nSelectedRow != this->field90) {
    this->field90 = nSelectedRow;
    this->BuildSelectedNationOrderCapabilityRows();
  }

  int idx = nResourceIndex;
  this->field94 = static_cast<short>(idx);
  ++idx;

  TTradePageBuyView* buyCopy = this->fieldAC;
  if (static_cast<short>(idx) > buyCopy->field_0x60) {
    buyCopy->SetEnabled(0, 1);
  } else {
    buyCopy->OrphanCallChain_C8_I118_0056fdb0(static_cast<short>(idx));
    buyCopy->SetEnabled(1, 0);
  }

  TTradePageSellView* sellCopy = this->fieldA8;
  if (static_cast<short>(idx) > sellCopy->field_0x60) {
    sellCopy->SetEnabled(0, 1);
  } else {
    sellCopy->OrphanCallChain_C8_I118_0056fdb0(static_cast<short>(idx));
    sellCopy->SetEnabled(1, 0);
  }

  TView* leftCtrl = this->ResolveControlByTag(0x6c636f72);
  if (leftCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x16e);
  }
  TView* rightCtrl = this->ResolveControlByTag(0x72636f72);
  if (rightCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x170);
  }

  if (this->field94 != 0) {
    leftCtrl->SetEnabled(1, 1);
    leftCtrl->SetState(1, 1);
    g_pSimMgr->GetString(0x2730, 0xb, &label);
  } else {
    leftCtrl->SetEnabled(0, 1);
    leftCtrl->SetState(0, 1);
    label = g_szEmptyString;
  }
  AssignSharedStringToControlState(label, leftCtrl);

  short refRow = this->field92;
  if (this->field94 != refRow && refRow != 0) {
    rightCtrl->SetEnabled(1, 1);
    rightCtrl->SetState(1, 1);
    g_pSimMgr->GetString(0x2730, 0xa, &label);
  } else {
    rightCtrl->SetEnabled(0, 1);
    rightCtrl->SetState(0, 1);
    label = g_szEmptyString;
  }
  AssignSharedStringToControlState(label, rightCtrl);
}

// FUNCTION: IMPERIALISM 0x005bb2e0
undefined TDealBookPicture::BuildSelectedNationOrderCapabilityRows() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005bbc30
void TDealBookPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x005bc0d0
void TDealBookPicture::RefreshTradeSelectionHeaderAndNationOfferBidLines() {
  if (initializedFlagB1 == 0) {
    TView* markControl = ResolveControlByTag(0x6d61726b /* 'mark' */);
    markControl->AssertValid();
    markControl->SetState(1, 0);

    TStaticText* rtilControl =
        static_cast<TStaticText*>(ResolveControlByTag(0x7274696c /* 'rtil' */));
    rtilControl->AssertValid();

    CString seasonName;
    CString yearText;
    yearText.Format(g_szDecimalFormat, 0x717 + g_pSimMgr->quarterGateTick2c / 4);
    g_pSimMgr->FormatSeasonName(&seasonName);
    CString headerText = seasonName + s_szSpaceSeparator_00695794 + yearText;
    rtilControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&headerText, 0);

    RECT titleBounds;
    rtilControl->QueryBounds(&titleBounds);
    InvalidateCityDialogRectRegion(&titleBounds, 1);

    TView* tabsControl = ResolveControlByTag(0x74616273 /* 'tabs' */);
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 4, tabsControl);
  } else {
    sellView->RebuildNationOfferRowsForCategory(-1);
    buyView->RebuildNationBidRowsForCategory(-1);

    TView* tabsControl = ResolveControlByTag(0x74616273 /* 'tabs' */);
    if (tabsControl == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x2a2);
    }

    TStaticText* titLControl =
        static_cast<TStaticText*>(ResolveControlByTag(0x7469744c /* 'titL' */));
    titLControl->AssertValid();
    titLControl->LoadUiStringAndDispatchViaVslot1C8(0x2740, 0x19, 0);
    RECT titLBounds;
    titLControl->QueryBounds(&titLBounds);
    InvalidateCityDialogRectRegion(&titLBounds, 1);

    TStaticText* rtilControl =
        static_cast<TStaticText*>(ResolveControlByTag(0x7274696c /* 'rtil' */));
    rtilControl->AssertValid();
    rtilControl->LoadUiStringAndDispatchViaVslot1C8(0x2740, 0x1a, 0);
    RECT rtilBounds;
    rtilControl->QueryBounds(&rtilBounds);
    InvalidateCityDialogRectRegion(&rtilBounds, 1);

    TView* markControl = ResolveControlByTag(0x6d61726b /* 'mark' */);
    markControl->AssertValid();
    markControl->SetState(0, 0);

    TView* tabsControl2 = ResolveControlByTag(0x74616273 /* 'tabs' */);
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 4, tabsControl2);
  }

  // NOTE: the receiver for the first CaptureLayoutF0 call below is not yet confirmed
  // (field9c reuse is a placeholder pending compare/triage evidence).
  int captureBuffer1[2] = {1000, 1000};
  field9c->CaptureLayoutF0(captureBuffer1, 1);
  int captureBuffer2[2] = {1000, 1000};
  buyView->CaptureLayoutF0(captureBuffer2, 1);
  int captureBuffer3[2] = {0x41, 0x59};
  sellView->CaptureLayoutF0(captureBuffer3, 1);
  int captureBuffer4[2] = {0x13a, 0x59};
  buyView->CaptureLayoutF0(captureBuffer4, 1);

  fieldA8 = sellView;
  fieldAC = buyView;
  if (fieldAC->field_0x60 < fieldA8->field_0x60) {
    field92 = fieldAC->field_0x60 - 1;
  } else {
    field92 = fieldA8->field_0x60 - 1;
  }

  SetPictureResourceIdAndRefresh(field98, 1);
  initializedFlagB1 = initializedFlagB1 == 0;
}
