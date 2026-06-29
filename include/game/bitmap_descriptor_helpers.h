#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;
extern TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
extern CDC* g_pQuickDrawMemoryDc;
extern HGDIOBJ g_hQuickDrawSavedBitmap;
extern int g_nActiveQuickDrawSurfaceFlags;

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
