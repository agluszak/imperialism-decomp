#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;

void GetActiveQuickDrawSurfaceContextAndFlags(undefined4* outContext, int* outFlags);
void SetActiveQuickDrawSurfaceContext(undefined4 context, undefined4 flags);
void* GetSurfaceObjectAtContextOffset24(int context);
void* GetSurfaceHeaderFromSurfaceObject(void* surfaceObject);
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(int* outContext, short bitDepth,
                                                         RECT* bounds, int hintField18, int arg4,
                                                         int arg5);
unsigned char ReturnConstantTrueQuickDrawFlag(void* surfaceObject);
void NoOpQuickDrawLifecycleHookB(void* surfaceObject);
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds);
int LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId);
