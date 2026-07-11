#include "game/TCombatReportView.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/TControl.h"
#include "game/TEventHandler.h"
#include "game/TStaticText.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x0058c830
// TCombatReportView::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058c8b0
// TCombatReportView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCombatReportView, TPicture)

// FUNCTION: IMPERIALISM 0x0058c8d0
TCombatReportView::TCombatReportView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0058c900
// TCombatReportView::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058c950
bool TCombatReportView::IsSelected(void* reportRecord) {
  (void)reportRecord;
  return false;
}

// FUNCTION: IMPERIALISM 0x0058d2b0
void TCombatReportView::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
}

// FUNCTION: IMPERIALISM 0x0058d950
void TCombatReportView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    unsigned int controlTag = static_cast<unsigned int>(sourceHandler->controlTag);

    if (controlTag == 0x70677570) { // 'pgup'
      if (reportValue < 2) {
        reportValue = 0;
        const unsigned int kPageTags[4] = {0x70677570, 0x7067646e, 0x70616765,
                                           0x70696374}; // pgup,pgdn,page,pict
        for (int i = 0; i < 4; i++) {
          TView* widget = ResolveControlByTag(kPageTags[i]);
          if (widget != NULL) {
            widget->SetEnabled(1, 1);
          }
        }
        TView* pgUp = ResolveControlByTag(0x70677570);
        if (pgUp == NULL) {
          MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x145d);
        }
        pgUp->SetEnabled(0, 1);
        TView* pgDown = ResolveControlByTag(0x7067646e);
        if (pgDown == NULL) {
          MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x1460);
        }
        pgDown->SetEnabled(1, 1);
      } else {
        reportValue--;
      }
      TView* pgDown = ResolveControlByTag(0x7067646e);
      if (pgDown == NULL) {
        MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
        TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x1460);
      }
      pgDown->SetEnabled(1, 1);
      RECT rect = {4, 0x9f, 0xe1, 0x149};
      InvalidateCityDialogRectRegion(&rect, 1);
    } else if (controlTag == 0x7067646e) { // 'pgdn'
      if (reportValue == 0) {
        reportValue = 1;
        const unsigned int kPageTags[4] = {0x70677570, 0x7067646e, 0x70616765,
                                           0x70696374}; // pgup,pgdn,page,pict
        for (int i = 0; i < 4; i++) {
          TView* widget = ResolveControlByTag(kPageTags[i]);
          if (widget != NULL) {
            widget->SetEnabled(1, 1);
          }
        }
        TView* pgUp = ResolveControlByTag(0x70677570);
        if (pgUp == NULL) {
          MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x1470);
        }
        pgUp->SetEnabled(1, 1);
        TView* pgDown = ResolveControlByTag(0x7067646e);
        if (pgDown == NULL) {
          MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x1477);
        }
        pgDown->SetEnabled(0, 1);
      } else if (reportValue < totalPages) {
        reportValue++;
      }
      if (reportValue == totalPages) {
        TView* pgDown = ResolveControlByTag(0x7067646e);
        if (pgDown == NULL) {
          MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
          TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\USmallViews.cpp", 0x1477);
        }
        pgDown->SetEnabled(0, 1);
      }
      RECT rect = {4, 0x9f, 0xe1, 0x149};
      InvalidateCityDialogRectRegion(&rect, 1);
    }

    TView* page = ResolveControlByTag(0x70616765); // 'page'
    if (page != NULL) {
      CString pageNumber;
      pageNumber.Format(g_szDecimalFormat, reportValue + 1);
      CString pageText = "Page " + pageNumber;
      pageText = pageText + " of ";
      pageNumber.Format(g_szDecimalFormat, totalPages + 1);
      pageText += pageNumber;
      static_cast<TStaticText*>(page)->AssignTextSharedRefIfChangedAndMaybeInvalidate(&pageText, 1);
    }
  }

  TControl::HandleEvent(commandId, sourceHandler, event);
}

TCombatReportView::~TCombatReportView() {}
