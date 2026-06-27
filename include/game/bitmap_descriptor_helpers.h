#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
struct TQuickDrawSurfaceContext;

extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContextHead;
extern TQuickDrawSurfaceContext g_defaultQuickDrawSurfaceSentinel;
extern CDC* g_pQuickDrawMemoryDc;
extern HGDIOBJ g_hQuickDrawSavedBitmap;
extern int g_nActiveQuickDrawSurfaceFlags;

void GetActiveQuickDrawSurfaceContextAndFlags(undefined4* outContext, undefined4* outFlags);
void SetActiveQuickDrawSurfaceContext(TQuickDrawSurfaceContext* context, undefined4 flags);
int GetSurfaceObjectAtContextOffset24(int context);
void* GetSurfaceHeaderFromSurfaceObject(void* surfaceObject);
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(int* outContext, short bitDepth,
                                                         RECT* bounds, int hintField18, int arg4,
                                                         int arg5);
unsigned char ReturnConstantTrueQuickDrawFlag(void* surfaceObject);
void NoOpQuickDrawLifecycleHookB(void* surfaceObject);
void WrapperFor_thunk_ResolveBmpResourceHandleWithDefault3B6_At00495c40(int** handle,
                                                                        RECT* bounds);
int LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId);
