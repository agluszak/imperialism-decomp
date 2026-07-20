#include "game/TUniversityView.h"

#include "game/TMapMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004caba0
// TUniversityView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cac40
// TUniversityView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUniversityView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cac60
TUniversityView::TUniversityView() {}

// SYNTHETIC: IMPERIALISM 0x004cac90
// TUniversityView::`scalar deleting destructor'
TUniversityView::~TUniversityView() {}

// FUNCTION: IMPERIALISM 0x004cace0
undefined TUniversityView::OrphanRetStub_004c6fd0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cb320
void TUniversityView::SelectUniversityRecruitmentEntry(short nRecruitmentEntryIndex) {}

// FUNCTION: IMPERIALISM 0x004cb8a0
void TUniversityView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x004cbb20
undefined TUniversityView::OrphanRetStub_004c6fb0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004cbf30
void TUniversityView::Free() {}

// Two dialog sections, each SectRect-gated against the passed-in paint rect: (1) a
// fixed 0x40x0x40 preview-panel blit whose source frame is selected by
// GetMapImprovementSpriteBaseOffset(fielda4); (2) the selected recruitment category's
// requirement grid, one row per resource
// (g_UniversityRequirementResourceTypeTable[row + fielda4*4], -1 = empty), each row
// blitting the resource icon and drawing up to nHighestRequirementLevel columns of its
// per-nation capability level. Exact on-screen rect positions for the panel/per-row
// icon blits are approximate (the original reuses a stack scratch rect across several
// calls in a way that could not be fully untangled) but every call and its arguments
// are faithfully reproduced.
// FUNCTION: IMPERIALISM 0x004cbf70
void TUniversityView::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);

  int nHighestRequirementLevel = 0;
  short baseOffset = g_pGlobalMapState->GetMapImprovementSpriteBaseOffset(fielda4, 0, 1);
  UpdatePaletteIndexWithDefaultFallback(0x10);

  RECT panelRect = {0, 0, 0x40, 0x40};
  RECT scratchClip;
  if (SectRect(&panelRect, rectBuffer, &scratchClip)) {
    RECT srcRect = {baseOffset, 0, baseOffset + 0x40, 0x40};
    BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas66c->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &panelRect, 0x24, 0);
  }

  RECT gridRegion = {0, 0xff, 0xc8, 0x186};
  if (SectRect(&gridRegion, rectBuffer, &scratchClip)) {
    ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6b);
    int row = 0;
    for (int rowBottomY = 0x12e; rowBottomY < 0x192; rowBottomY += 0x19, ++row) {
      CString text;
      short nCommoditySpriteId =
          static_cast<short>(g_UniversityRequirementResourceTypeTable[row + fielda4 * 4]);
      if (nCommoditySpriteId != -1) {
        RECT reqSrcRect = {nCommoditySpriteId * 0x14, 0, (nCommoditySpriteId + 1) * 0x14, 0x18};
        RECT reqDstRect = {2, rowBottomY - 0x19, 2 + 0x14, rowBottomY - 1};
        BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->unitIconAtlas->GetBlitSurface(),
                                         g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                         &reqSrcRect, &reqDstRect, 0x24, 0);

        short activeNationId = g_pSimMgr->GetActiveNationId();
        short capabilityLevel =
            g_pCityOrderCapabilityState
                ->capabilityValueByNationAndResource[activeNationId][nCommoditySpriteId];
        if (nHighestRequirementLevel < capabilityLevel) {
          nHighestRequirementLevel = capabilityLevel;
        }
        for (int level = 1; level <= nHighestRequirementLevel; ++level) {
          text.Format(
              g_szDecimalFormat,
              static_cast<int>(g_abUniversityRequirementLevelById[nCommoditySpriteId][level]));
          SetQuickDrawTextOriginWithContextOffset(static_cast<short>(level * 0x28 + 0x27),
                                                  static_cast<short>(row * 0x19 + 0x121));
          DrawTextWithCachedQuickDrawStyleState(&text);
        }
      }
    }
  }

  UpdatePaletteIndexWithDefaultFallback(0x13);
}
