#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;

void GetActiveQuickDrawSurfaceContextAndFlags(TQuickDrawSurfaceContext** outContext, int* outFlags);
void SetActiveQuickDrawSurfaceContext(TQuickDrawSurfaceContext* context, int flags);
void* GetSurfaceNodeSlot(TQuickDrawSurfaceContext* context);
void* GetSurfaceNodePixelBits(void* surfaceObject);
short InitializeBitmapDescriptorRecordAndLoadSurfaceNode(TQuickDrawSurfaceContext** outContext,
                                                         short bitDepth, const RECT* bounds,
                                                         int hintField18, int arg4, int arg5);
unsigned char ReturnConstantTrueQuickDrawFlag(void* surfaceObject);
void NoOpQuickDrawLifecycleHookB(void* surfaceObject);
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds);
// Mac Resource Manager LoadResource emulation: a no-op returning noErr(0) — the
// Windows "handles" are always resident. Callers invoke it before dereferencing a
// resource-loader handle, exactly where the Mac source called LoadResource(Handle).
// (QD prefix: Win32 LoadResource collides.)
undefined4 QDLoadResource(TBitmapResourceLoader** handle);
TQuickDrawSurfaceContext*
LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId);
