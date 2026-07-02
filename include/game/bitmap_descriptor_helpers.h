#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;

void GetActiveQuickDrawSurfaceContextAndFlags(TQuickDrawSurfaceContext** outContext, int* outFlags);
void SetActiveQuickDrawSurfaceContext(TQuickDrawSurfaceContext* context, int flags);
void* GetSurfaceObjectAtContextOffset24(TQuickDrawSurfaceContext* context);
void* GetSurfaceHeaderFromSurfaceObject(void* surfaceObject);
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(TQuickDrawSurfaceContext** outContext,
                                                         short bitDepth, RECT* bounds,
                                                         int hintField18, int arg4, int arg5);
void __stdcall FreeQuickDrawSurfaceContextSlot(TQuickDrawSurfaceContext** slot);
unsigned char ReturnConstantTrueQuickDrawFlag(void* surfaceObject);
void NoOpQuickDrawLifecycleHookB(void* surfaceObject);
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds);
TQuickDrawSurfaceContext*
LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId);
