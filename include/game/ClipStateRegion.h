#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class TBitmapResourceLoader;

struct ClipStateRegionInner {
  RECT boundingBox; // +0x00 region bounding rect (written by GetRgnBox)
  int attachRegistered; // +0x10
  CBrush brush;         // +0x14 (region handle in CGdiObject::m_hObject at +0x18)
};

ASSERT_SIZE(ClipStateRegionInner, 0x1c);

struct ClipStateRegionWrapper {
  ClipStateRegionInner* inner;
};

ClipStateRegionWrapper* CreateClipStateRegionWrapperObject(void);
undefined4 DestroyClipStateRegionWrapperObject(ClipStateRegionWrapper* wrapperObject);
int IntersectRectWrapper(RECT* src1, RECT* src2, RECT* dst);

void CombineTwoRegionsIntoDestinationAndUpdateBox(ClipStateRegionWrapper* src1,
                                                  ClipStateRegionWrapper* src2,
                                                  ClipStateRegionWrapper* dst);
void CombineOptionalSourceRegionIntoDestinationAndUpdateBox(ClipStateRegionWrapper* src,
                                                            ClipStateRegionWrapper* dst);
void ResetClipRegionAndReadBoundingRect(ClipStateRegionWrapper* region);
void RebuildMapTileNeighborHighlightPolygonsForAllTiles_Impl(void);
void DrawFrameRectOrUpdateClipRegion(RECT* rect);
void WrapperFor_LookupHandleMapEntryWithCreate_At00497f90(ClipStateRegionWrapper* dst);
int RebuildSpriteNonTransparentPolygonRegion(ClipStateRegionWrapper* region, void* spriteSurface);
undefined4 NoOpRuntimeCallback_00497c00(TBitmapResourceLoader** handle);
