#include "game/TCombatReportView.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/TControl.h"
#include "game/TCountry.h"
#include "game/TEventHandler.h"
#include "game/TMacViewMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"
#include "game/quickdraw_rendering.h"
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

// Draws the combat-report participant page: a header line naming the active
// participant nation, then up to 4 unit rows (name + status suffix, a divider strip, a
// unit icon, an XP/experience guide-line pair, and up to two conditional icon
// overlays). Two participants (A/B) share one contiguous page range: pages
// [1..field9c) list participant A's units (m_reportContext->unitsA), pages
// [field9c..totalPages] list participant B's (unitsB); rowIndex = (reportValue-1)*4
// relative to whichever participant's range reportValue falls in.
// FUNCTION: IMPERIALISM 0x0058d2b0
void TCombatReportView::ApplyRectSlot110(RECT* rectBuffer) {
  // Function-scope scratch: reused first for the page-header nation name, then
  // overwritten each loop iteration with the current row's "Name (Status)" label.
  CString scratch;

  TPicture::ApplyRectSlot110(rectBuffer);

  if (reportValue != 0) {
    SetQuickDrawFillColor(0);
    SetQuickDrawTextFont(3);
    SetQuickDrawTextSize(0xc);
    SetQuickDrawTextFace(1);

    short upperBound;
    short rowIndex;
    if (reportValue < field9c) {
      g_apTerrainTypeDescriptorTable[m_reportContext->nationIdA]->FormatOverlayTerrainLabelText(
          &scratch);
      upperBound = field98;
      rowIndex = reportValue * 4 - 4;
    } else {
      g_apTerrainTypeDescriptorTable[m_reportContext->nationIdB]->FormatOverlayTerrainLabelText(
          &scratch);
      upperBound = field9a;
      rowIndex = (reportValue - field9c) * 4;
    }

    SetQuickDrawTextOriginWithContextOffset(6, 0xb0);
    DrawTextWithCachedQuickDrawStyleState(&scratch);
    SetQuickDrawTextSize(9);
    SetQuickDrawTextFace(0);

    int y = 0xc0;
    int rowInPage = 0;
    for (;;) {
      if (rowIndex >= upperBound) {
        break;
      }
      SetQuickDrawTextOriginWithContextOffset(6, static_cast<short>(y));

      CombatReportUnitRecord* record = (reportValue < field9c) ? m_reportContext->unitsA + rowIndex
                                                               : m_reportContext->unitsB + rowIndex;

      {
        // The record's own name buffer copy-constructs the label; a separate GetString
        // lookup below appends " (status)" onto it.
        CString recordName(record->name);
        scratch = recordName;
      }
      CString retrieved;
      g_pSimMgr->GetString(0x2717, record->statusStringIndex14, &retrieved);
      scratch += CString(" (") + retrieved + ")";
      DrawTextWithCachedQuickDrawStyleState(&scratch);

      // Thin divider strip beneath the row.
      UpdatePaletteIndexWithDefaultFallback(0x13);
      RECT dividerSrcRect = {0, 0, 0xd9, 6};
      RECT dividerDstRect = {6, y + 2, 0xdf, y + 7};
      BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas684->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &dividerSrcRect, &dividerDstRect, 0, 0);

      // Two guide-line ticks positioned from the record's fieldAt18/fieldAt1c ratios
      // (magic-number /7 division reproduces the original's IMUL-based division).
      SetQuickDrawTextOriginWithContextOffset(7, static_cast<short>(y + 3));
      SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(1, 4);
      g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x34);
      int guideX = (record->fieldAt18 * 3) / 7 + 7;
      DrawCenteredGuideLineOnMapDc(static_cast<short>(guideX), static_cast<short>(y + 3));
      g_pUiRuntimeContext->ApplyLegendSplitSlot34(0x33);
      DrawCenteredGuideLineOnMapDc(static_cast<short>(guideX - (record->fieldAt1c * 3) / 7),
                                   static_cast<short>(y + 3));
      g_pUiRuntimeContext->ApplyLegendSplitSlot34(0);

      // Unit icon strip.
      UpdatePaletteIndexWithDefaultFallback(0x10);
      RECT iconSrcRect = {0, 6, 0xac, 0x10};
      RECT iconDstRect = {6, y + 8, 0xb2, y + 0x12};
      BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas684->GetBlitSurface(),
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                       &iconSrcRect, &iconDstRect, 0x24, 0);

      if (record->widthParamAt17 != 0) {
        short overlayWidth = static_cast<short>(record->widthParamAt17 * 2 - 0x18);
        int overlayRight = overlayWidth + 0x1f;
        RECT overlaySrcRect = {0, 0x12, overlayWidth, 0x17};
        RECT overlayDstRect = {0x1f, y + 0xb, overlayRight, y + 0x13};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas684->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &overlaySrcRect, &overlayDstRect, 0x24, 0);
      }

      if (record->flagAt15 != 0) {
        RECT markerSrcRect = {0, 0x12, 5, 0x17};
        RECT markerDstRect = {0x7c, y + 0xb, 0x81, y + 0x13};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas684->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &markerSrcRect, &markerDstRect, 0x24, 0);
      }

      UpdatePaletteIndexWithDefaultFallback(0x13);

      y += 0x20;
      rowIndex++;
      rowInPage++;
      if (rowInPage >= 4) {
        break;
      }
    }
  }
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
      static_cast<TStaticText*>(page)->SetTextAndMaybeRefresh(&pageText, 1);
    }
  }

  TControl::HandleEvent(commandId, sourceHandler, event);
}

TCombatReportView::~TCombatReportView() {}
